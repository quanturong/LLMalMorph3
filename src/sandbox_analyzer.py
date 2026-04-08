"""
Sandbox Analyzer for LLMalMorph
================================
Integrates with CAPE/Cuckoo sandbox for dynamic behavioral analysis 
of mutated executables.

Supported backends:
    - CAPE Sandbox (recommended, Cuckoo v3 fork)
    - Cuckoo Sandbox v2 (legacy)
    - VirusTotal (cloud detonation/analysis)

Features:
  - Submit compiled PE executables for analysis
  - Poll for task completion
  - Retrieve behavioral reports (API calls, registry, network, file I/O)
  - Compare original vs mutated behavioral signatures
  - Generate evasion metrics (detection rate change)

Usage:
    from sandbox_analyzer import SandboxAnalyzer
    
    analyzer = SandboxAnalyzer(
        backend='cape',
        api_url='http://192.168.1.100:8090',
        api_token='your_token_here'  # optional for CAPE
    )
    
    result = analyzer.submit_and_wait('path/to/malware.exe', timeout=300)
    print(result.detections, result.behavior_summary)
"""

import os
import sys
import json
import time
import logging
import hashlib
import requests
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────

@dataclass
class SandboxReport:
    """Parsed sandbox analysis report"""
    task_id: Any = 0
    status: str = 'pending'          # pending | running | completed | failed | timeout
    score: float = 0.0               # threat score (0-10)
    
    # Detection
    detections: List[str] = field(default_factory=list)
    signatures: List[Dict[str, Any]] = field(default_factory=list)
    
    # Behavioral data
    api_calls: List[Dict[str, Any]] = field(default_factory=list)
    api_call_count: int = 0
    registry_operations: List[Dict[str, Any]] = field(default_factory=list)
    file_operations: List[Dict[str, Any]] = field(default_factory=list)
    network_operations: List[Dict[str, Any]] = field(default_factory=list)
    process_operations: List[Dict[str, Any]] = field(default_factory=list)
    mutex_operations: List[str] = field(default_factory=list)
    behavior_summary: Dict[str, Any] = field(default_factory=dict)
    dll_loaded: List[str] = field(default_factory=list)

    # MITRE ATT&CK TTPs
    ttps: List[Dict[str, Any]] = field(default_factory=list)
    
    # File info
    sample_sha256: str = ''
    sample_name: str = ''
    sample_size: int = 0
    
    # Timing
    analysis_duration: float = 0.0   # seconds
    submit_time: str = ''
    complete_time: str = ''
    
    # Raw report for debugging
    raw_report: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ''

    def to_dict(self) -> dict:
        """Serialize to dict (exclude raw_report for readability)"""
        d = {
            'task_id': self.task_id,
            'status': self.status,
            'score': self.score,
            'detections': self.detections,
            'signatures': self.signatures,
            'api_call_count': self.api_call_count,
            'registry_ops_count': len(self.registry_operations),
            'file_ops_count': len(self.file_operations),
            'network_ops_count': len(self.network_operations),
            'process_ops_count': len(self.process_operations),
            'mutex_count': len(self.mutex_operations),
            'behavior_summary': self.behavior_summary,
            'dll_loaded': self.dll_loaded,
            'dll_loaded_count': len(self.dll_loaded),
            'ttps': self.ttps,
            'ttp_count': len(self.ttps),
            'sample_sha256': self.sample_sha256,
            'sample_name': self.sample_name,
            'sample_size': self.sample_size,
            'analysis_duration': self.analysis_duration,
            'submit_time': self.submit_time,
            'complete_time': self.complete_time,
            'error_message': self.error_message,
        }
        return d


@dataclass
class ComparisonResult:
    """Behavioral comparison between original and mutated samples"""
    original_report: Optional[SandboxReport] = None
    mutated_report: Optional[SandboxReport] = None
    
    # Detection comparison
    original_detections: int = 0
    mutated_detections: int = 0
    detection_delta: int = 0          # negative = fewer detections (good for evasion)
    
    # Behavioral similarity
    api_similarity: float = 0.0       # 0-1, how similar the API call patterns are
    behavioral_preserved: bool = False # True if core behavior is maintained
    
    # Signature changes
    new_signatures: List[str] = field(default_factory=list)       # only in mutated
    removed_signatures: List[str] = field(default_factory=list)   # only in original
    common_signatures: List[str] = field(default_factory=list)    # in both
    
    score_delta: float = 0.0          # mutated - original threat score

    def to_dict(self) -> dict:
        return {
            'original_detections': self.original_detections,
            'mutated_detections': self.mutated_detections,
            'detection_delta': self.detection_delta,
            'api_similarity': round(self.api_similarity, 4),
            'behavioral_preserved': self.behavioral_preserved,
            'new_signatures': self.new_signatures,
            'removed_signatures': self.removed_signatures,
            'common_signatures': self.common_signatures,
            'score_delta': round(self.score_delta, 2),
            'original_score': self.original_report.score if self.original_report else 0,
            'mutated_score': self.mutated_report.score if self.mutated_report else 0,
        }


# ─────────────────────────────────────────────────────────────────
# Backend API clients
# ─────────────────────────────────────────────────────────────────

class CapeApiClient:
    """
    CAPE Sandbox REST API client.
    
    API docs: https://capev2.readthedocs.io/en/latest/usage/api.html
    
    Endpoints used:
        POST /apiv2/tasks/create/file/     - submit sample
        GET  /apiv2/tasks/view/{id}/        - check task status
        GET  /apiv2/tasks/report/{id}/      - get full report
        GET  /apiv2/tasks/delete/{id}/      - delete task (cleanup)
    """
    
    def __init__(self, api_url: str, api_token: str = '', timeout: int = 30):
        self.api_url = api_url.rstrip('/')
        self.api_token = api_token
        self.timeout = timeout
        self.session = requests.Session()
        if api_token:
            self.session.headers['Authorization'] = f'Token {api_token}'
    
    def _url(self, path: str) -> str:
        return f'{self.api_url}{path}'
    
    def test_connection(self) -> bool:
        """Test if CAPE server is reachable"""
        try:
            r = self.session.get(
                self._url('/apiv2/tasks/list/'),
                timeout=self.timeout,
                params={'limit': 1}
            )
            return r.status_code == 200
        except requests.exceptions.ConnectionError:
            return False
        except Exception as e:
            logger.warning(f"Connection test failed: {e}")
            return False
    
    def submit_file(self, filepath: str, 
                    machine: str = '', 
                    platform: str = 'windows',
                    timeout_analysis: int = 120,
                    options: Dict[str, str] = None) -> Optional[int]:
        """
        Submit a file for analysis.
        Returns task_id on success, None on failure.
        """
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return None
        
        try:
            with open(filepath, 'rb') as f:
                files = {'file': (os.path.basename(filepath), f)}
                data = {
                    'timeout': timeout_analysis,
                    'platform': platform,
                }
                if machine:
                    data['machine'] = machine
                if options:
                    # CAPE supports some submission fields as top-level keys (e.g. route).
                    # Keep backward-compatible "options" string for everything else.
                    top_level_option_keys = {
                        'route', 'package', 'custom', 'clock', 'memory',
                        'enforce_timeout', 'priority', 'tags'
                    }
                    options_for_string = {}
                    for k, v in options.items():
                        if k in top_level_option_keys:
                            data[k] = v
                        else:
                            options_for_string[k] = v

                    if options_for_string:
                        data['options'] = ','.join(f'{k}={v}' for k, v in options_for_string.items())
                
                r = self.session.post(
                    self._url('/apiv2/tasks/create/file/'),
                    files=files,
                    data=data,
                    timeout=self.timeout
                )
                
            if r.status_code == 200:
                result = r.json()
                # CAPE returns {"data": {"task_ids": [123]}} or {"task_id": 123}
                if 'data' in result and 'task_ids' in result['data']:
                    task_ids = result['data']['task_ids']
                    if task_ids:
                        return task_ids[0]
                elif 'task_id' in result:
                    return result['task_id']
                elif 'data' in result and 'task_id' in result['data']:
                    return result['data']['task_id']
                
                logger.error(f"Unexpected submit response: {result}")
                return None
            else:
                logger.error(f"Submit failed ({r.status_code}): {r.text[:500]}")
                return None
                
        except Exception as e:
            logger.error(f"Submit error: {e}")
            return None

    def submit_bytes(self, file_bytes: bytes, filename: str = "sample.exe",
                     machine: str = '', platform: str = 'windows',
                     timeout_analysis: int = 120,
                     options: Dict[str, str] = None) -> Optional[int]:
        """
        Submit in-memory bytes for analysis (no plaintext touches disk).
        Returns task_id on success, None on failure.
        """
        import io
        try:
            files = {'file': (filename, io.BytesIO(file_bytes))}
            data = {
                'timeout': timeout_analysis,
                'platform': platform,
            }
            if machine:
                data['machine'] = machine
            if options:
                top_level_option_keys = {
                    'route', 'package', 'custom', 'clock', 'memory',
                    'enforce_timeout', 'priority', 'tags'
                }
                options_for_string = {}
                for k, v in options.items():
                    if k in top_level_option_keys:
                        data[k] = v
                    else:
                        options_for_string[k] = v
                if options_for_string:
                    data['options'] = ','.join(f'{k}={v}' for k, v in options_for_string.items())

            r = self.session.post(
                self._url('/apiv2/tasks/create/file/'),
                files=files,
                data=data,
                timeout=self.timeout
            )

            if r.status_code == 200:
                result = r.json()
                if 'data' in result and 'task_ids' in result['data']:
                    task_ids = result['data']['task_ids']
                    if task_ids:
                        return task_ids[0]
                elif 'task_id' in result:
                    return result['task_id']
                elif 'data' in result and 'task_id' in result['data']:
                    return result['data']['task_id']
                logger.error(f"Unexpected submit response: {result}")
                return None
            else:
                logger.error(f"Submit failed ({r.status_code}): {r.text[:500]}")
                return None
        except Exception as e:
            logger.error(f"Submit bytes error: {e}")
            return None

    def get_task_status(self, task_id: int) -> str:
        """
        Get task status. 
        Returns: 'pending', 'running', 'completed', 'reported', 'failed_analysis'
        """
        try:
            r = self.session.get(
                self._url(f'/apiv2/tasks/view/{task_id}/'),
                timeout=self.timeout
            )
            if r.status_code == 200:
                data = r.json()
                task = data.get('data', data.get('task', data))
                return task.get('status', 'unknown')
            return 'unknown'
        except Exception as e:
            logger.warning(f"Status check error for task {task_id}: {e}")
            return 'unknown'
    
    def get_report(self, task_id: int) -> Optional[Dict]:
        """Get full analysis report"""
        try:
            # CAPEv2 current API uses /apiv2/tasks/get/report/{id}/(json)
            # Keep backward compatibility with older /apiv2/tasks/report/{id}/ endpoint.
            candidate_paths = [
                f'/apiv2/tasks/get/report/{task_id}/json/',
                f'/apiv2/tasks/get/report/{task_id}/',
                f'/apiv2/tasks/report/{task_id}/',
            ]

            last_status = None
            for path in candidate_paths:
                r = self.session.get(self._url(path), timeout=60)  # reports can be large
                last_status = r.status_code
                if r.status_code == 200:
                    return r.json()

            logger.error(f"Report fetch failed ({last_status})")
            return None
        except Exception as e:
            logger.error(f"Report fetch error: {e}")
            return None
    
    def delete_task(self, task_id: int) -> bool:
        """Delete a task and its data"""
        try:
            r = self.session.get(
                self._url(f'/apiv2/tasks/delete/{task_id}/'),
                timeout=self.timeout
            )
            return r.status_code == 200
        except Exception:
            return False


class CuckooV2ApiClient:
    """
    Cuckoo Sandbox v2 (legacy) REST API client.
    
    Endpoints:
        POST /tasks/create/file   - submit sample
        GET  /tasks/view/{id}     - check status
        GET  /tasks/report/{id}   - get report
    """
    
    def __init__(self, api_url: str, api_token: str = '', timeout: int = 30):
        self.api_url = api_url.rstrip('/')
        self.api_token = api_token
        self.timeout = timeout
        self.session = requests.Session()
        if api_token:
            self.session.headers['Authorization'] = f'Bearer {api_token}'
    
    def _url(self, path: str) -> str:
        return f'{self.api_url}{path}'
    
    def test_connection(self) -> bool:
        try:
            r = self.session.get(
                self._url('/cuckoo/status'),
                timeout=self.timeout
            )
            return r.status_code == 200
        except:
            return False
    
    def submit_file(self, filepath: str, 
                    machine: str = '',
                    platform: str = 'windows',
                    timeout_analysis: int = 120,
                    options: Dict[str, str] = None) -> Optional[int]:
        if not os.path.exists(filepath):
            return None
        try:
            with open(filepath, 'rb') as f:
                files = {'file': (os.path.basename(filepath), f)}
                data = {'timeout': timeout_analysis, 'platform': platform}
                if machine:
                    data['machine'] = machine
                if options:
                    top_level_option_keys = {
                        'route', 'package', 'custom', 'clock', 'memory',
                        'enforce_timeout', 'priority', 'tags'
                    }
                    options_for_string = {}
                    for k, v in options.items():
                        if k in top_level_option_keys:
                            data[k] = v
                        else:
                            options_for_string[k] = v

                    if options_for_string:
                        data['options'] = ','.join(f'{k}={v}' for k, v in options_for_string.items())
                r = self.session.post(
                    self._url('/tasks/create/file'),
                    files=files,
                    data=data,
                    timeout=self.timeout
                )
            if r.status_code == 200:
                return r.json().get('task_id')
            return None
        except Exception as e:
            logger.error(f"Cuckoo submit error: {e}")
            return None
    
    def get_task_status(self, task_id: int) -> str:
        try:
            r = self.session.get(
                self._url(f'/tasks/view/{task_id}'),
                timeout=self.timeout
            )
            if r.status_code == 200:
                task = r.json().get('task', {})
                return task.get('status', 'unknown')
            return 'unknown'
        except:
            return 'unknown'
    
    def get_report(self, task_id: int) -> Optional[Dict]:
        try:
            r = self.session.get(
                self._url(f'/tasks/report/{task_id}'),
                timeout=60
            )
            return r.json() if r.status_code == 200 else None
        except:
            return None
    
    def delete_task(self, task_id: int) -> bool:
        try:
            r = self.session.get(
                self._url(f'/tasks/delete/{task_id}'),
                timeout=self.timeout
            )
            return r.status_code == 200
        except:
            return False


class VirusTotalApiClient:
    """
    VirusTotal API v3 client.

    Endpoints:
        POST /api/v3/files              - submit file
        GET  /api/v3/analyses/{id}      - check analysis status
        GET  /api/v3/files/{sha256}     - get file report
    """

    def __init__(self, api_url: str = 'https://www.virustotal.com', api_token: str = '', timeout: int = 30):
        self.api_url = api_url.rstrip('/')
        self.api_token = api_token
        self.timeout = timeout
        self.session = requests.Session()
        if api_token:
            self.session.headers['x-apikey'] = api_token

    def _url(self, path: str) -> str:
        return f'{self.api_url}{path}'

    def test_connection(self) -> bool:
        """Test whether API key and VT endpoint are reachable."""
        if not self.api_token:
            return False
        # Use known EICAR hash; 404/200 means endpoint+auth are reachable, 401 means bad key.
        known_hash = '275a021bbfb6480f8a5abf1f7c1524f6d8f3f13f11f6f8f3bc5f3f9137bac9df'
        try:
            r = self.session.get(
                self._url(f'/api/v3/files/{known_hash}'),
                timeout=self.timeout
            )
            return r.status_code in (200, 404)
        except Exception as e:
            logger.warning(f"VT connection test failed: {e}")
            return False

    def submit_file(self, filepath: str,
                    machine: str = '',
                    platform: str = 'windows',
                    timeout_analysis: int = 120,
                    options: Dict[str, str] = None) -> Optional[str]:
        del machine, platform, timeout_analysis, options  # not used by VT API
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return None
        if not self.api_token:
            logger.error("VirusTotal API key missing")
            return None
        try:
            with open(filepath, 'rb') as f:
                files = {'file': (os.path.basename(filepath), f)}
                r = self.session.post(
                    self._url('/api/v3/files'),
                    files=files,
                    timeout=max(self.timeout, 120)
                )
            if r.status_code in (200, 201):
                data = r.json().get('data', {})
                return data.get('id')
            logger.error(f"VT submit failed ({r.status_code}): {r.text[:500]}")
            return None
        except Exception as e:
            logger.error(f"VT submit error: {e}")
            return None

    def get_task_status(self, task_id: str) -> str:
        try:
            r = self.session.get(
                self._url(f'/api/v3/analyses/{task_id}'),
                timeout=self.timeout
            )
            if r.status_code != 200:
                return 'unknown'
            status = r.json().get('data', {}).get('attributes', {}).get('status', 'unknown')
            if status == 'completed':
                return 'completed'
            if status in ('queued', 'in-progress'):
                return 'running'
            return status
        except Exception:
            return 'unknown'

    def get_report(self, task_id: str) -> Optional[Dict]:
        """Return combined analysis + file report payload."""
        try:
            analysis_resp = self.session.get(
                self._url(f'/api/v3/analyses/{task_id}'),
                timeout=self.timeout
            )
            if analysis_resp.status_code != 200:
                logger.error(f"VT analysis fetch failed ({analysis_resp.status_code})")
                return None
            analysis_json = analysis_resp.json()

            attrs = analysis_json.get('data', {}).get('attributes', {})
            sha256 = (
                attrs.get('sha256')
                or analysis_json.get('meta', {}).get('file_info', {}).get('sha256')
            )

            file_json = None
            if sha256:
                file_resp = self.session.get(
                    self._url(f'/api/v3/files/{sha256}'),
                    timeout=self.timeout
                )
                if file_resp.status_code == 200:
                    file_json = file_resp.json()

            return {
                'analysis': analysis_json,
                'file': file_json,
            }
        except Exception as e:
            logger.error(f"VT report fetch error: {e}")
            return None

    def delete_task(self, task_id: str) -> bool:
        del task_id
        # VT does not expose task deletion for submitted analyses.
        return True


# ─────────────────────────────────────────────────────────────────
# Main analyzer
# ─────────────────────────────────────────────────────────────────

class SandboxAnalyzer:
    """
    High-level sandbox analysis orchestrator.
    
    Submits PE executables to CAPE/Cuckoo, waits for analysis,
    and parses behavioral reports.
    """
    
    SUPPORTED_BACKENDS = ('cape', 'cuckoo', 'virustotal')
    TERMINAL_STATES = {'completed', 'reported', 'failed_analysis', 'failed_processing'}
    
    def __init__(self, 
                 backend: str = 'cape',
                 api_url: str = 'http://localhost:8090',
                 api_token: str = '',
                 machine: str = '',
                 platform: str = 'windows',
                 analysis_timeout: int = 120,
                 poll_interval: int = 15,
                 max_wait: int = 600,
                 cleanup: bool = False,
                 submission_options: Optional[Dict[str, Any]] = None):
        """
        Args:
            backend:           'cape' or 'cuckoo' or 'virustotal'
            api_url:           Base URL of the sandbox REST API
            api_token:         API authentication token (optional for local installs)
            machine:           Specific VM to use (empty = auto select)
            platform:          Target platform (default: windows)
            analysis_timeout:  Analysis timeout inside sandbox VM (seconds)
            poll_interval:     How often to check task status (seconds)
            max_wait:          Maximum total wait time (seconds)
            cleanup:           Delete tasks after retrieving report
        """
        if backend not in self.SUPPORTED_BACKENDS:
            raise ValueError(f"Unsupported backend '{backend}'. Use: {self.SUPPORTED_BACKENDS}")
        
        self.backend = backend
        self.machine = machine
        self.platform = platform
        self.analysis_timeout = analysis_timeout
        self.poll_interval = poll_interval
        self.max_wait = max_wait
        self.cleanup = cleanup
        self.submission_options = {
            str(k): str(v)
            for k, v in (submission_options or {}).items()
            if k is not None and v is not None and str(k).strip() and str(v).strip()
        }
        
        # Initialize API client
        if backend == 'cape':
            self.client = CapeApiClient(api_url, api_token)
        elif backend == 'cuckoo':
            self.client = CuckooV2ApiClient(api_url, api_token)
        else:
            self.client = VirusTotalApiClient(api_url, api_token)
        
        logger.info(f"SandboxAnalyzer initialized: backend={backend}, url={api_url}")
        if self.submission_options:
            logger.info(f"Sandbox submission options: {self.submission_options}")
    
    def test_connection(self) -> bool:
        """Test connectivity to the sandbox server"""
        connected = self.client.test_connection()
        if connected:
            logger.info(f"✅ Connected to {self.backend} sandbox")
        else:
            logger.error(f"❌ Cannot connect to {self.backend} sandbox")
        return connected

    def _has_meaningful_behavior(self, raw: Dict[str, Any]) -> bool:
        """Check whether a CAPE report already contains usable behavioral data."""
        if not isinstance(raw, dict):
            return False

        behavior = raw.get('behavior', {})
        if not isinstance(behavior, dict):
            return False

        processes = behavior.get('processes', [])
        if isinstance(processes, list):
            for proc in processes:
                if not isinstance(proc, dict):
                    continue
                calls = proc.get('calls', [])
                if isinstance(calls, dict):
                    calls = calls.get('calls', []) or []
                if isinstance(calls, list) and len(calls) > 0:
                    return True

        summary = behavior.get('summary', {})
        if isinstance(summary, dict):
            for k in ('files', 'read_files', 'write_files', 'delete_files',
                      'keys', 'read_keys', 'write_keys', 'delete_keys',
                      'mutexes', 'regkey_written', 'regkey_read', 'regkey_deleted',
                      'file_created', 'file_written', 'file_deleted', 'file_read',
                      'dll_loaded', 'dlls_loaded', 'loaded_dll', 'loaded_dlls'):
                v = summary.get(k, [])
                if isinstance(v, list) and len(v) > 0:
                    return True

        return False
    
    def submit_and_wait(self, filepath: str, timeout: int = None) -> SandboxReport:
        """
        Submit a sample, wait for analysis to complete, return parsed report.
        
        This is the main high-level method.
        """
        report = SandboxReport()
        report.sample_name = os.path.basename(filepath)
        report.sample_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
        report.submit_time = datetime.now().isoformat()
        
        # Compute SHA256
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                report.sample_sha256 = hashlib.sha256(f.read()).hexdigest()
        
        # Submit
        logger.info(f"📤 Submitting {report.sample_name} to {self.backend}...")
        task_id = self.client.submit_file(
            filepath,
            machine=self.machine,
            platform=self.platform,
            timeout_analysis=self.analysis_timeout,
            options=self.submission_options
        )
        
        if task_id is None:
            report.status = 'failed'
            report.error_message = 'Failed to submit file to sandbox'
            logger.error(report.error_message)
            return report
        
        report.task_id = task_id
        logger.info(f"   Task ID: {task_id}")
        
        # Poll for completion
        wait_timeout = timeout or self.max_wait
        start_time = time.time()
        
        while True:
            elapsed = time.time() - start_time
            if elapsed > wait_timeout:
                report.status = 'timeout'
                report.error_message = f'Analysis timed out after {wait_timeout}s'
                logger.warning(report.error_message)
                break
            
            status = self.client.get_task_status(task_id)
            logger.info(f"   [{int(elapsed)}s] Task {task_id}: {status}")
            
            if status in self.TERMINAL_STATES:
                if 'failed' in status:
                    report.status = 'failed'
                    report.error_message = f'Sandbox analysis failed: {status}'
                    logger.error(report.error_message)
                    break
                elif status == 'completed' and self.backend == 'virustotal':
                    # VT analyses use 'completed' as final state and do not expose
                    # CAPE-style behavior/report generation states.
                    report.status = 'completed'
                    logger.info(f"   ✅ Analysis completed in {int(elapsed)}s")
                    break
                elif status == 'reported':
                    # Report is fully generated and ready to fetch
                    report.status = 'completed'
                    logger.info(f"   ✅ Analysis completed and reported in {int(elapsed)}s")
                    break
                elif status == 'completed':
                    # VM analysis done - try fetching report (may or may not be ready yet)
                    logger.info(f"   ⏳ VM analysis done, trying to fetch report early...")
                    raw = self.client.get_report(task_id)
                    if raw and self._has_meaningful_behavior(raw):
                        report.status = 'completed'
                        report.raw_report = raw
                        self._parse_report(report, raw)
                        report.complete_time = datetime.now().isoformat()
                        report.analysis_duration = time.time() - start_time
                        logger.info(f"   ✅ Report fetched at 'completed' stage in {int(elapsed)}s")
                        if self.cleanup and task_id:
                            self.client.delete_task(task_id)
                        return report
                    elif raw:
                        logger.info("   ⏳ Early report exists but behavior is incomplete; waiting for 'reported'...")
                    # Report not ready yet, keep polling until 'reported' or timeout
            
            time.sleep(self.poll_interval)
        
        # Retrieve report
        if report.status == 'completed':
            raw = self.client.get_report(task_id)
            if raw:
                report.raw_report = raw
                self._parse_report(report, raw)
                report.complete_time = datetime.now().isoformat()
                report.analysis_duration = time.time() - start_time
            else:
                report.error_message = 'Failed to retrieve analysis report'
                report.status = 'failed'
        
        # Cleanup
        if self.cleanup and task_id:
            self.client.delete_task(task_id)
        
        return report
    
    def _parse_report(self, report: SandboxReport, raw: Dict):
        """Parse raw CAPE/Cuckoo report into SandboxReport fields"""
        try:
            if self.backend == 'cape':
                self._parse_cape_report(report, raw)
            elif self.backend == 'cuckoo':
                self._parse_cuckoo_report(report, raw)
            else:
                self._parse_virustotal_report(report, raw)
        except Exception as e:
            logger.warning(f"Report parsing error: {e}")
            report.error_message = f'Report parse error: {e}'
    
    def _parse_cape_report(self, report: SandboxReport, raw: Dict):
        """Parse CAPE-specific report format"""
        def _normalize_string_list(values):
            normalized = []
            for item in values or []:
                if isinstance(item, str):
                    val = item.strip()
                    if val:
                        normalized.append(val)
                elif isinstance(item, dict):
                    # Keep common module descriptors if present
                    val = (
                        item.get('filepath')
                        or item.get('path')
                        or item.get('name')
                        or item.get('module')
                        or item.get('dll')
                        or ''
                    )
                    if isinstance(val, str):
                        val = val.strip()
                        if val:
                            normalized.append(val)
            # De-duplicate while preserving order
            seen = set()
            unique = []
            for val in normalized:
                if val not in seen:
                    unique.append(val)
                    seen.add(val)
            return unique

        # Info section — malscore is the real score field; info.score is often null
        report.score = float(raw.get('malscore', 0) or 0)
        report.status = str(raw.get('malstatus', 'unknown') or 'unknown').lower()

        # Sample metadata from target.file
        target_file = raw.get('target', {}).get('file', {}) or {}
        report.sample_sha256 = target_file.get('sha256', '') or ''
        report.sample_name   = target_file.get('name', '') or ''
        report.sample_size   = int(target_file.get('size', 0) or 0)

        # Signatures (behavioral indicators)
        for sig in raw.get('signatures', []):
            report.signatures.append({
                'name': sig.get('name', ''),
                'description': sig.get('description', ''),
                'severity': sig.get('severity', 0),
                'categories': sig.get('categories', []),
                'families': sig.get('families', []),
                'weight': sig.get('weight', 0),
                'confidence': sig.get('confidence', 0),
            })

        # Detections — from signature families + YARA + malstatus
        detection_set: list = []
        malstatus = str(raw.get('malstatus', '') or '')
        if malstatus and malstatus.lower() not in ('', 'undetected', 'unknown', 'none'):
            detection_set.append(malstatus)
        for sig in raw.get('signatures', []):
            for fam in (sig.get('families') or []):
                if fam and fam not in detection_set:
                    detection_set.append(fam)
        for yara_hit in target_file.get('yara', []):
            name = yara_hit.get('name', '') if isinstance(yara_hit, dict) else str(yara_hit)
            if name:
                detection_set.append(f'YARA:{name}')
        for yara_hit in target_file.get('cape_yara', []):
            name = yara_hit.get('name', '') if isinstance(yara_hit, dict) else str(yara_hit)
            if name:
                detection_set.append(f'CAPE_YARA:{name}')
        # Legacy fields still checked for backward compat
        legacy = raw.get('detections', raw.get('malfamily_tag', ''))
        if isinstance(legacy, str) and legacy and legacy not in detection_set:
            detection_set.append(legacy)
        elif isinstance(legacy, list):
            for v in legacy:
                if v and v not in detection_set:
                    detection_set.append(v)
        report.detections = detection_set
        
        # Behavior section
        behavior = raw.get('behavior', {})
        
        # API calls
        for proc in behavior.get('processes', []):
            calls = proc.get('calls', [])
            if isinstance(calls, dict):
                calls = calls.get('calls', []) or []
            if not isinstance(calls, list):
                calls = []

            for call in calls:
                report.api_calls.append({
                    'api': call.get('api', ''),
                    'category': call.get('category', ''),
                    'status': call.get('status', ''),
                    'return': call.get('return', ''),
                })
            report.api_call_count += len(calls)
        
        # Summary (aggregated behavioral data)
        summary = behavior.get('summary', {})
        if not isinstance(summary, dict):
            summary = {}
        report.behavior_summary = dict(summary)
        
        # Registry
        for key in summary.get('regkey_written', []) + summary.get('write_keys', []):
            report.registry_operations.append({'type': 'write', 'key': key})
        for key in summary.get('regkey_read', []) + summary.get('read_keys', []):
            report.registry_operations.append({'type': 'read', 'key': key})
        for key in summary.get('regkey_deleted', []) + summary.get('delete_keys', []):
            report.registry_operations.append({'type': 'delete', 'key': key})
        
        # Files
        for f in summary.get('file_created', []) + summary.get('files', []):
            report.file_operations.append({'type': 'create', 'path': f})
        for f in summary.get('file_written', []) + summary.get('write_files', []):
            report.file_operations.append({'type': 'write', 'path': f})
        for f in summary.get('file_deleted', []) + summary.get('delete_files', []):
            report.file_operations.append({'type': 'delete', 'path': f})
        for f in summary.get('file_read', []) + summary.get('read_files', []):
            report.file_operations.append({'type': 'read', 'path': f})
        
        # Network
        network = raw.get('network', {}) if isinstance(raw.get('network', {}), dict) else {}
        for host in network.get('hosts', []):
            report.network_operations.append({
                'type': 'dns' if 'hostname' in host else 'ip',
                'target': host.get('hostname', host.get('ip', '')),
                'port': host.get('port', 0),
            })
        for dns in network.get('dns', []):
            report.network_operations.append({
                'type': 'dns',
                'target': dns.get('request', ''),
                'answers': dns.get('answers', []),
            })
        for domain in network.get('domains', []):
            report.network_operations.append({
                'type': 'dns',
                'target': domain.get('domain', ''),
                'ip': domain.get('ip', ''),
            })
        for http in network.get('http', []):
            report.network_operations.append({
                'type': 'http',
                'method': http.get('method', ''),
                'uri': http.get('uri', ''),
                'host': http.get('host', ''),
            })
        
        # Processes
        for proc in behavior.get('processes', []):
            report.process_operations.append({
                'pid': proc.get('pid', proc.get('process_id', 0)),
                'process_name': proc.get('process_name', ''),
                'command_line': proc.get('command_line', ''),
                'parent_id': proc.get('parent_id', 0),
            })
        
        # Mutexes
        report.mutex_operations = summary.get('mutex', []) + summary.get('mutexes', [])

        # Resolved APIs (dynamic imports)
        resolved = summary.get('resolved_apis', [])
        if resolved and isinstance(resolved, list):
            # Store in behavior_summary for downstream consumers
            report.behavior_summary.setdefault('resolved_apis', resolved)

        # Executed commands
        exec_cmds = summary.get('executed_commands', [])
        if exec_cmds and isinstance(exec_cmds, list):
            report.behavior_summary.setdefault('executed_commands', exec_cmds)

        # Created / started services
        for svc_key in ('created_services', 'started_services'):
            svc_list = summary.get(svc_key, [])
            if svc_list:
                report.behavior_summary.setdefault(svc_key, svc_list)

        # Loaded DLLs — primary source: behavior.enhanced library-load events
        dll_candidates = []
        for evt in behavior.get('enhanced', []):
            if not isinstance(evt, dict):
                continue
            if evt.get('object') == 'library':
                file_val = evt.get('data', {}).get('file', '') if isinstance(evt.get('data'), dict) else ''
                if file_val and isinstance(file_val, str):
                    dll_candidates.append(file_val)
        # Fallback: summary and per-process fields (older CAPE/Cuckoo)
        for key in ('dll_loaded', 'dlls_loaded', 'loaded_dll', 'loaded_dlls', 'modules'):
            for val in (summary.get(key, []) or []):
                dll_candidates.append(val)
        for proc in behavior.get('processes', []):
            if not isinstance(proc, dict):
                continue
            for key in ('dll_loaded', 'dlls_loaded', 'loaded_modules', 'modules'):
                for val in (proc.get(key, []) or []):
                    dll_candidates.append(val)
        report.dll_loaded = _normalize_string_list(dll_candidates)

        # TTPs (MITRE ATT&CK)
        # Real CAPE format: raw['ttps'] is a list of
        #   {"signature": "name", "ttps": ["T1485", ...], "mbcs": ["OB0008", ...]}
        for ttp_entry in raw.get('ttps', []):
            if not isinstance(ttp_entry, dict):
                continue
            sig_name = ttp_entry.get('signature', '')
            for ttp_id in (ttp_entry.get('ttps', []) or []):
                if ttp_id:
                    report.ttps.append({
                        'ttp_id': str(ttp_id),
                        'name': '',
                        'description': '',
                        'tactic': '',
                        'signature': sig_name,
                        'mbcs': ttp_entry.get('mbcs', []),
                    })
        # Fallback: extract from signatures that have inline ATT&CK references
        if not report.ttps:
            for sig in raw.get('signatures', []):
                refs = sig.get('ttp', []) or sig.get('ttps', []) or sig.get('attack', [])
                if isinstance(refs, str):
                    refs = [refs]
                for ref in refs:
                    if isinstance(ref, dict):
                        ttp_id = ref.get('ttp_id', ref.get('ttp', ref.get('id', '')))
                        if ttp_id:
                            report.ttps.append({
                                'ttp_id': str(ttp_id),
                                'name': ref.get('name', ''),
                                'description': ref.get('description', ''),
                                'tactic': ref.get('tactic', ''),
                                'signature': sig.get('name', ''),
                                'mbcs': [],
                            })
                    elif isinstance(ref, str) and ref:
                        report.ttps.append({
                            'ttp_id': ref,
                            'name': '',
                            'description': '',
                            'tactic': '',
                            'signature': sig.get('name', ''),
                            'mbcs': [],
                        })

    def _parse_cuckoo_report(self, report: SandboxReport, raw: Dict):
        """Parse Cuckoo v2 report format (very similar to CAPE)"""
        info = raw.get('info', {})
        report.score = info.get('score', 0)
        
        for sig in raw.get('signatures', []):
            report.signatures.append({
                'name': sig.get('name', ''),
                'description': sig.get('description', ''),
                'severity': sig.get('severity', 0),
            })
        
        behavior = raw.get('behavior', {})
        summary = behavior.get('summary', {})
        if not isinstance(summary, dict):
            summary = {}
        report.behavior_summary = dict(summary)
        
        # API calls
        for proc in behavior.get('processes', []):
            for call in proc.get('calls', []):
                report.api_calls.append({
                    'api': call.get('api', ''),
                    'category': call.get('category', ''),
                })
            report.api_call_count += len(proc.get('calls', []))
        
        # Registry
        for key in summary.get('regkey_written', []):
            report.registry_operations.append({'type': 'write', 'key': key})
        for key in summary.get('regkey_read', []):
            report.registry_operations.append({'type': 'read', 'key': key})
        
        # Files
        for f in summary.get('file_created', []):
            report.file_operations.append({'type': 'create', 'path': f})
        for f in summary.get('file_written', []):
            report.file_operations.append({'type': 'write', 'path': f})
        
        # Network
        for host in raw.get('network', {}).get('hosts', []):
            report.network_operations.append({
                'type': 'ip',
                'target': host.get('ip', ''),
            })
        
        # Mutexes
        report.mutex_operations = summary.get('mutex', [])

        # Loaded DLLs/modules
        dll_candidates = []
        for key in ('dll_loaded', 'dlls_loaded', 'loaded_dll', 'loaded_dlls', 'modules'):
            values = summary.get(key, [])
            if isinstance(values, list):
                dll_candidates.extend(values)
        for proc in behavior.get('processes', []):
            if not isinstance(proc, dict):
                continue
            for key in ('dll_loaded', 'dlls_loaded', 'loaded_modules', 'modules'):
                values = proc.get(key, [])
                if isinstance(values, list):
                    dll_candidates.extend(values)

        seen = set()
        report.dll_loaded = []
        for item in dll_candidates:
            if isinstance(item, str):
                value = item.strip()
            elif isinstance(item, dict):
                value = (
                    item.get('filepath')
                    or item.get('path')
                    or item.get('name')
                    or item.get('module')
                    or item.get('dll')
                    or ''
                )
                value = value.strip() if isinstance(value, str) else ''
            else:
                value = ''
            if value and value not in seen:
                report.dll_loaded.append(value)
                seen.add(value)

    def _parse_virustotal_report(self, report: SandboxReport, raw: Dict):
        """Parse VirusTotal API v3 analysis + file report format."""
        analysis = raw.get('analysis', {}) if isinstance(raw, dict) else {}
        file_rep = raw.get('file', {}) if isinstance(raw, dict) else {}

        analysis_attrs = analysis.get('data', {}).get('attributes', {})
        file_attrs = file_rep.get('data', {}).get('attributes', {}) if file_rep else {}

        stats = analysis_attrs.get('stats', {}) or file_attrs.get('last_analysis_stats', {})
        malicious = int(stats.get('malicious', 0) or 0)
        suspicious = int(stats.get('suspicious', 0) or 0)
        harmless = int(stats.get('harmless', 0) or 0)
        undetected = int(stats.get('undetected', 0) or 0)
        total_votes = max(malicious + suspicious + harmless + undetected, 1)

        # Map VT verdicts to a CAPE-like score (0-10)
        weighted = malicious + (0.5 * suspicious)
        report.score = round(min(10.0, (weighted / total_votes) * 10.0), 2)

        # Detections from engine results
        report.detections = []
        results = file_attrs.get('last_analysis_results', {})
        if isinstance(results, dict):
            for engine, result_obj in results.items():
                category = str(result_obj.get('category', '')).lower()
                if category in ('malicious', 'suspicious'):
                    verdict = result_obj.get('result') or category
                    report.detections.append(f"{engine}:{verdict}")

        # High-level signatures/tags where available
        for tag in file_attrs.get('tags', []) or []:
            report.signatures.append({
                'name': str(tag),
                'description': 'VirusTotal tag',
                'severity': 1,
                'categories': ['vt_tag'],
            })

        # File info
        report.sample_sha256 = (
            file_rep.get('data', {}).get('id', '')
            or analysis_attrs.get('sha256', '')
            or report.sample_sha256
        )
        report.sample_size = int(file_attrs.get('size', report.sample_size or 0) or 0)

        # VT does not expose detailed process/API traces in standard public responses;
        # leave behavioral operation lists empty.
    
    def compare_reports(self, 
                        original: SandboxReport, 
                        mutated: SandboxReport) -> ComparisonResult:
        """
        Compare behavioral reports between original and mutated samples.
        
        This helps measure:
        1. Evasion success (detection reduction)
        2. Behavioral preservation (functional equivalence)
        """
        comp = ComparisonResult()
        comp.original_report = original
        comp.mutated_report = mutated
        
        # Detection comparison
        comp.original_detections = len(original.detections)
        comp.mutated_detections = len(mutated.detections)
        comp.detection_delta = comp.mutated_detections - comp.original_detections
        
        # Score comparison
        comp.score_delta = mutated.score - original.score
        
        # Signature comparison
        orig_sig_names = {s['name'] for s in original.signatures}
        mut_sig_names = {s['name'] for s in mutated.signatures}
        
        comp.common_signatures = sorted(orig_sig_names & mut_sig_names)
        comp.new_signatures = sorted(mut_sig_names - orig_sig_names)
        comp.removed_signatures = sorted(orig_sig_names - mut_sig_names)
        
        # API call similarity (Jaccard index on unique API names)
        orig_apis = {c['api'] for c in original.api_calls}
        mut_apis = {c['api'] for c in mutated.api_calls}
        
        if orig_apis or mut_apis:
            intersection = len(orig_apis & mut_apis)
            union = len(orig_apis | mut_apis)
            comp.api_similarity = intersection / union if union > 0 else 0
        else:
            comp.api_similarity = 1.0  # both empty = identical
        
        # Behavioral preservation check
        # Core behavior is preserved if API similarity > 0.7 and
        # critical operations (registry, network) overlap significantly
        orig_reg_keys = {op.get('key', '') for op in original.registry_operations if op.get('type') == 'write'}
        mut_reg_keys = {op.get('key', '') for op in mutated.registry_operations if op.get('type') == 'write'}
        
        orig_net = {op.get('target', '') for op in original.network_operations}
        mut_net = {op.get('target', '') for op in mutated.network_operations}
        
        reg_overlap = len(orig_reg_keys & mut_reg_keys) / max(len(orig_reg_keys), 1) if orig_reg_keys else 1.0
        net_overlap = len(orig_net & mut_net) / max(len(orig_net), 1) if orig_net else 1.0
        
        comp.behavioral_preserved = (
            comp.api_similarity >= 0.7 and
            reg_overlap >= 0.5 and
            net_overlap >= 0.5
        )
        
        return comp
    
    def analyze_exe(self, exe_path: str, timeout: int = None) -> SandboxReport:
        """
        Convenience method: submit exe and return completed report.
        Alias for submit_and_wait().
        """
        return self.submit_and_wait(exe_path, timeout)
    
    def batch_analyze(self, exe_paths: List[str], 
                      timeout_per_sample: int = None) -> List[SandboxReport]:
        """
        Analyze multiple executables sequentially.
        
        For parallel submission, use submit_file directly and poll manually.
        """
        results = []
        for i, path in enumerate(exe_paths, 1):
            logger.info(f"\n{'='*50}")
            logger.info(f"Analyzing sample {i}/{len(exe_paths)}: {os.path.basename(path)}")
            logger.info(f"{'='*50}")
            report = self.submit_and_wait(path, timeout_per_sample)
            results.append(report)
        return results
    
    def batch_analyze_parallel(self, exe_paths: List[str],
                                timeout: int = None) -> List[SandboxReport]:
        """
        Submit all samples first, then poll for all to complete.
        Much faster for multiple samples.
        """
        wait_timeout = timeout or self.max_wait
        
        # Phase 1: Submit all
        tasks = []  # (task_id, filepath, report)
        for path in exe_paths:
            report = SandboxReport()
            report.sample_name = os.path.basename(path)
            report.sample_size = os.path.getsize(path) if os.path.exists(path) else 0
            report.submit_time = datetime.now().isoformat()
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    report.sample_sha256 = hashlib.sha256(f.read()).hexdigest()
            
            task_id = self.client.submit_file(
                path, machine=self.machine, platform=self.platform,
                timeout_analysis=self.analysis_timeout,
                options=self.submission_options
            )
            if task_id:
                report.task_id = task_id
                tasks.append((task_id, path, report))
                logger.info(f"📤 Submitted {report.sample_name} → task {task_id}")
            else:
                report.status = 'failed'
                report.error_message = 'Submit failed'
                tasks.append((None, path, report))
        
        # Phase 2: Poll all
        start_time = time.time()
        pending = {t[0] for t in tasks if t[0] is not None}
        
        while pending and (time.time() - start_time) < wait_timeout:
            time.sleep(self.poll_interval)
            for task_id in list(pending):
                status = self.client.get_task_status(task_id)
                if status in self.TERMINAL_STATES:
                    pending.discard(task_id)
                    logger.info(f"   Task {task_id}: {status}")
            elapsed = int(time.time() - start_time)
            logger.info(f"   [{elapsed}s] {len(pending)} tasks still running...")
        
        # Phase 3: Collect reports
        results = []
        for task_id, path, report in tasks:
            if task_id and report.status != 'failed':
                status = self.client.get_task_status(task_id)
                if status in self.TERMINAL_STATES and 'failed' not in status:
                    raw = self.client.get_report(task_id)
                    if raw:
                        report.status = 'completed'
                        report.raw_report = raw
                        self._parse_report(report, raw)
                        report.complete_time = datetime.now().isoformat()
                        report.analysis_duration = time.time() - start_time
                    else:
                        report.status = 'failed'
                        report.error_message = 'Failed to retrieve report'
                else:
                    report.status = 'timeout' if task_id in pending else 'failed'
            results.append(report)
            
            if self.cleanup and task_id:
                self.client.delete_task(task_id)
        
        return results


# ─────────────────────────────────────────────────────────────────
# Standalone usage
# ─────────────────────────────────────────────────────────────────

def main():
    """CLI for standalone sandbox analysis"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Submit executables to CAPE/Cuckoo/VirusTotal sandbox')
    parser.add_argument('files', nargs='+', help='PE executable(s) to analyze')
    parser.add_argument('--backend', choices=['cape', 'cuckoo', 'virustotal'], default='cape')
    parser.add_argument('--url', default='http://localhost:8090', help='Sandbox API URL')
    parser.add_argument('--token', default='', help='API token')
    parser.add_argument('--timeout', type=int, default=300, help='Max wait time (seconds)')
    parser.add_argument('--output', default=None, help='Output JSON file')
    parser.add_argument('--compare', nargs=2, metavar=('ORIGINAL', 'MUTATED'), 
                        help='Compare two executables')
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    analyzer = SandboxAnalyzer(
        backend=args.backend,
        api_url=args.url,
        api_token=args.token,
        max_wait=args.timeout
    )
    
    if not analyzer.test_connection():
        print(f"\n❌ Cannot connect to {args.backend} at {args.url}")
        print("   Make sure the sandbox is running and accessible.")
        sys.exit(1)
    
    if args.compare:
        # Compare mode
        print(f"\n📊 Comparing: {args.compare[0]} vs {args.compare[1]}")
        orig_report = analyzer.submit_and_wait(args.compare[0])
        mut_report = analyzer.submit_and_wait(args.compare[1])
        comparison = analyzer.compare_reports(orig_report, mut_report)
        
        print(f"\n{'='*60}")
        print(f"COMPARISON RESULTS")
        print(f"{'='*60}")
        print(f"Original score:    {orig_report.score}")
        print(f"Mutated score:     {mut_report.score} (delta: {comparison.score_delta:+.1f})")
        print(f"Original detections: {comparison.original_detections}")
        print(f"Mutated detections:  {comparison.mutated_detections} (delta: {comparison.detection_delta:+d})")
        print(f"API similarity:    {comparison.api_similarity:.1%}")
        print(f"Behavior preserved:{comparison.behavioral_preserved}")
        
        if comparison.removed_signatures:
            print(f"\n✅ Signatures removed by mutation:")
            for s in comparison.removed_signatures:
                print(f"   - {s}")
        if comparison.new_signatures:
            print(f"\n⚠️  New signatures in mutated:")
            for s in comparison.new_signatures:
                print(f"   + {s}")
        
        output_data = comparison.to_dict()
    else:
        # Standard analysis mode
        reports = analyzer.batch_analyze(args.files, args.timeout)
        
        for report in reports:
            print(f"\n{'='*60}")
            print(f"Sample: {report.sample_name}")
            print(f"{'='*60}")
            print(f"Status:     {report.status}")
            print(f"Score:      {report.score}/10")
            print(f"Detections: {', '.join(report.detections) if report.detections else 'None'}")
            print(f"API calls:  {report.api_call_count}")
            print(f"Registry:   {len(report.registry_operations)} operations")
            print(f"Files:      {len(report.file_operations)} operations")
            print(f"Network:    {len(report.network_operations)} connections")
            print(f"Processes:  {len(report.process_operations)}")
            print(f"Mutexes:    {len(report.mutex_operations)}")
            
            if report.signatures:
                print(f"\nSignatures:")
                for sig in report.signatures[:10]:
                    print(f"   [{sig.get('severity',0)}] {sig['name']}: {sig.get('description','')[:80]}")
        
        output_data = [r.to_dict() for r in reports]
    
    # Save output
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\n📁 Results saved to: {args.output}")


if __name__ == '__main__':
    main()
