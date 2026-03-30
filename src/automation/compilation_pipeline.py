"""
Automated Compilation Pipeline for LLMalMorph.
Handles compilation, testing, and error detection.
"""
import subprocess
import os
import logging
import tempfile
import shutil
from typing import Tuple, List, Dict, Optional
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class CompilationStatus(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    NOT_ATTEMPTED = "not_attempted"


@dataclass
class CompilationResult:
    """Result of compilation attempt"""
    status: CompilationStatus
    output: str = ""
    errors: List[str] = None
    warnings: List[str] = None
    executable_path: Optional[str] = None
    compilation_time: float = 0.0
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []


@dataclass
class TestResult:
    """Result of test execution"""
    passed: bool = False
    output: str = ""
    failures: List[str] = None
    execution_time: float = 0.0
    
    def __post_init__(self):
        if self.failures is None:
            self.failures = []


class CompilationPipeline:
    """
    Automated compilation and testing pipeline.
    Supports multiple compilers and build systems.
    """
    
    # Compiler configurations
    COMPILERS = {
        'c': {
            'gcc': ['gcc', '-Wall', '-Wextra', '-std=c11', '-O2'],
            'clang': ['clang', '-Wall', '-Wextra', '-std=c11', '-O2'],
        },
        'cpp': {
            'g++': ['g++', '-Wall', '-Wextra', '-std=c++17', '-O2'],
            'clang++': ['clang++', '-Wall', '-Wextra', '-std=c++17', '-O2'],
        },
        'python': {
            'python': ['python', '-m', 'py_compile'],
        },
    }
    
    def __init__(
        self,
        language: str = 'c',
        compiler: Optional[str] = None,
        timeout: int = 30,
        working_dir: Optional[str] = None,
    ):
        """
        Initialize compilation pipeline.
        
        Args:
            language: Programming language ('c', 'cpp', 'python')
            compiler: Compiler name (auto-detect if None)
            timeout: Compilation timeout in seconds
            working_dir: Working directory for compilation
        """
        self.language = language.lower()
        self.timeout = timeout
        self.working_dir = working_dir or tempfile.mkdtemp()
        # Ensure working directory exists
        os.makedirs(self.working_dir, exist_ok=True)
        self.compiler = compiler or self._detect_compiler()
        
        logger.info(
            f"Initialized compilation pipeline: "
            f"language={language}, compiler={self.compiler}"
        )
    
    def _detect_compiler(self) -> str:
        """Auto-detect available compiler"""
        if self.language not in self.COMPILERS:
            raise ValueError(f"Unsupported language: {self.language}")
        
        compilers = self.COMPILERS[self.language]
        
        for compiler_name in compilers.keys():
            if shutil.which(compiler_name):
                logger.debug(f"Detected compiler: {compiler_name}")
                return compiler_name
        
        raise RuntimeError(
            f"No compiler found for {self.language}. "
            f"Available: {list(compilers.keys())}"
        )
    
    def compile(
        self,
        source_file: str,
        output_file: Optional[str] = None,
        additional_flags: List[str] = None,
        include_dirs: List[str] = None,
        library_dirs: List[str] = None,
        libraries: List[str] = None,
        permissive: bool = False,
    ) -> CompilationResult:
        """
        Compile source file.
        
        Args:
            source_file: Path to source file
            output_file: Optional output executable path
            additional_flags: Additional compiler flags
            include_dirs: Include directories
            library_dirs: Library directories
            libraries: Libraries to link
        
        Returns:
            CompilationResult
        """
        import time
        
        if not os.path.exists(source_file):
            return CompilationResult(
                status=CompilationStatus.FAILED,
                errors=[f"Source file not found: {source_file}"],
            )
        
        if output_file is None:
            base_name = Path(source_file).stem
            if self.language in ['c', 'cpp']:
                output_file = os.path.join(self.working_dir, base_name)
            else:
                output_file = source_file  # Python doesn't need separate output
        
        # Build compiler command
        if self.language in ['c', 'cpp']:
            cmd = self.COMPILERS[self.language][self.compiler].copy()
        else:
            cmd = self.COMPILERS[self.language][self.compiler].copy()
        
        # Add include directories
        if include_dirs:
            for inc_dir in include_dirs:
                cmd.extend(['-I', inc_dir])
        
        # Add library directories
        if library_dirs:
            for lib_dir in library_dirs:
                cmd.extend(['-L', lib_dir])
        
        # Add libraries
        if libraries:
            for lib in libraries:
                cmd.extend(['-l', lib])
        
        # Add permissive flags if requested
        if permissive:
            from .fix_strategies import FixStrategies
            permissive_flags = FixStrategies.get_permissive_compiler_flags(self.language)
            cmd.extend(permissive_flags)
            logger.debug(f"Added permissive flags: {permissive_flags}")
        
        # Add additional flags
        if additional_flags:
            cmd.extend(additional_flags)
        
        # Add output and source file
        if self.language in ['c', 'cpp']:
            cmd.extend(['-o', output_file, source_file])
        else:
            cmd.append(source_file)
        
        logger.info(f"Compiling {source_file} with {self.compiler}...")
        logger.debug(f"Command: {' '.join(cmd)}")
        
        # Ensure working directory exists
        os.makedirs(self.working_dir, exist_ok=True)
        
        # Ensure source file exists
        if not os.path.exists(source_file):
            logger.error(f"Source file not found: {source_file}")
            return CompilationResult(
                status=CompilationStatus.FAILED,
                errors=[f"Source file not found: {source_file}"],
            )
        
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.working_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            
            compilation_time = time.time() - start_time
            
            if result.returncode == 0:
                logger.info(f"✓ Compilation successful: {output_file}")
                return CompilationResult(
                    status=CompilationStatus.SUCCESS,
                    output=result.stdout,
                    errors=[],
                    warnings=self._extract_warnings(result.stderr),
                    executable_path=output_file if self.language in ['c', 'cpp'] else None,
                    compilation_time=compilation_time,
                )
            else:
                logger.error(f"✗ Compilation failed")
                errors = self._extract_errors(result.stderr)
                return CompilationResult(
                    status=CompilationStatus.FAILED,
                    output=result.stdout,
                    errors=errors,
                    warnings=self._extract_warnings(result.stderr),
                    compilation_time=compilation_time,
                )
        
        except subprocess.TimeoutExpired:
            logger.error(f"✗ Compilation timeout after {self.timeout}s")
            return CompilationResult(
                status=CompilationStatus.TIMEOUT,
                errors=[f"Compilation timeout after {self.timeout} seconds"],
                compilation_time=self.timeout,
            )
        
        except Exception as e:
            logger.error(f"✗ Compilation error: {e}")
            return CompilationResult(
                status=CompilationStatus.FAILED,
                errors=[str(e)],
            )
    
    def test(
        self,
        executable: str,
        test_cases: Optional[List[Dict]] = None,
        timeout: int = 5,
    ) -> TestResult:
        """
        Run tests on executable.
        
        Args:
            executable: Path to executable or source file
            test_cases: List of test cases (optional)
            timeout: Test execution timeout
        
        Returns:
            TestResult
        """
        import time
        
        if self.language in ['c', 'cpp']:
            if not os.path.exists(executable):
                return TestResult(
                    passed=False,
                    failures=["Executable not found"],
                )
            cmd = [executable]
        else:
            # Python: run as script
            cmd = ['python', executable]
        
        logger.info(f"Running tests on {executable}...")
        
        start_time = time.time()
        
        if test_cases is None:
            # Basic smoke test
            try:
                result = subprocess.run(
                    cmd,
                    cwd=self.working_dir,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                
                execution_time = time.time() - start_time
                
                return TestResult(
                    passed=result.returncode == 0,
                    output=result.stdout,
                    failures=[] if result.returncode == 0 else [f"Exit code: {result.returncode}"],
                    execution_time=execution_time,
                )
            
            except subprocess.TimeoutExpired:
                return TestResult(
                    passed=False,
                    failures=["Test execution timeout"],
                    execution_time=timeout,
                )
            
            except Exception as e:
                return TestResult(
                    passed=False,
                    failures=[str(e)],
                )
        
        # Run test cases
        failures = []
        for test_case in test_cases:
            try:
                test_cmd = cmd + test_case.get("args", [])
                result = subprocess.run(
                    test_cmd,
                    input=test_case.get("input", ""),
                    capture_output=True,
                    text=True,
                    timeout=test_case.get("timeout", timeout),
                    cwd=self.working_dir,
                )
                
                expected_output = test_case.get("expected_output")
                if expected_output and result.stdout.strip() != expected_output.strip():
                    failures.append(
                        f"Test '{test_case.get('name', 'unknown')}': "
                        f"Expected '{expected_output}', got '{result.stdout.strip()}'"
                    )
            
            except Exception as e:
                failures.append(f"Test '{test_case.get('name', 'unknown')}': {e}")
        
        execution_time = time.time() - start_time
        
        return TestResult(
            passed=len(failures) == 0,
            output="",
            failures=failures,
            execution_time=execution_time,
        )
    
    def _extract_errors(self, stderr: str) -> List[str]:
        """Extract error messages from compiler output"""
        errors = []
        for line in stderr.split('\n'):
            line = line.strip()
            if not line:
                continue
            if 'error:' in line.lower() or 'fatal error:' in line.lower():
                errors.append(line)
        return errors
    
    def _extract_warnings(self, stderr: str) -> List[str]:
        """Extract warning messages from compiler output"""
        warnings = []
        for line in stderr.split('\n'):
            line = line.strip()
            if not line:
                continue
            if 'warning:' in line.lower():
                warnings.append(line)
        return warnings
    
    def cleanup(self):
        """Cleanup working directory"""
        if os.path.exists(self.working_dir) and self.working_dir.startswith(tempfile.gettempdir()):
            try:
                shutil.rmtree(self.working_dir)
                logger.debug(f"Cleaned up working directory: {self.working_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup working directory: {e}")

