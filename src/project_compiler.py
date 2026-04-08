"""
Project Compiler - Compile Complete Malware Projects
====================================================
Compiles multi-file projects with all dependencies and headers.

Features:
- Multi-file compilation
- Automatic header inclusion
- Dependency resolution
- Windows PE generation
- MSVC (cl.exe) support (primary)
- MinGW/GCC support (fallback)
"""

import glob
import os
import subprocess
import shutil
import tempfile
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import logging
import json

logger = logging.getLogger(__name__)

# Import auto-fixer (LLM-powered) - each import separated to avoid one failure disabling all
import sys
import os
automation_path = os.path.join(os.path.dirname(__file__), 'automation')
if automation_path not in sys.path:
    sys.path.insert(0, automation_path)

# AutoFixer (core LLM fixer)
AUTOFIXER_AVAILABLE = False
try:
    from auto_fixer import AutoFixer
    AUTOFIXER_AVAILABLE = True
except ImportError as e:
    AutoFixer = None
    logger.warning(f"AutoFixer not available: {e}")

# Mahoraga adaptive fixer (optional)
MAHORAGA_AVAILABLE = False
try:
    from mahoraga_fixer import MahoragaAdaptiveFixer
    MAHORAGA_AVAILABLE = True
except ImportError as e:
    MahoragaAdaptiveFixer = None
    logger.debug(f"Mahoraga fixer not available: {e}")

# Enhanced tools (optional)
ENHANCED_TOOLS_AVAILABLE = False
try:
    from enhanced_error_categorizer import EnhancedErrorCategorizer, ErrorCategory
    from compilation_validator import CompilationValidator
    from project_context_collector import ProjectContextCollector
    from header_generator import HeaderGenerator
    ENHANCED_TOOLS_AVAILABLE = True
except ImportError as e:
    EnhancedErrorCategorizer = None
    CompilationValidator = None
    ProjectContextCollector = None
    HeaderGenerator = None
    logger.debug(f"Enhanced tools not available: {e}")

# Multi-file support (optional)
MULTI_FILE_SUPPORT_AVAILABLE = False
try:
    from multi_file_support import MultiFileCompilationSupport, get_multi_file_support
    MULTI_FILE_SUPPORT_AVAILABLE = True
except ImportError as e:
    MultiFileCompilationSupport = None
    logger.debug(f"Multi-file support not available: {e}")

# Also keep simple pattern-based fixer as fallback
try:
    from project_auto_fixer import ProjectAutoFixer
except ImportError:
    ProjectAutoFixer = None

# ClangAnalyzer for AST-aware compilation support (optional)
CLANG_ANALYZER_AVAILABLE = False
try:
    from clang_analyzer import ClangAnalyzer, AnalysisResult as ClangAnalysisResult
    CLANG_ANALYZER_AVAILABLE = True
except ImportError:
    ClangAnalyzer = None
    ClangAnalysisResult = None


class CompilationResult:
    """Result of compilation"""
    
    def __init__(self):
        self.success = False
        self.executable_path = None
        self.object_files = []
        self.output = ""
        self.errors = ""
        self.warnings = []
        self.compile_time = 0.0
        self.executable_size = 0
        
    def to_dict(self):
        return {
            'success': self.success,
            'executable_path': self.executable_path,
            'object_files': self.object_files,
            'output': self.output,
            'errors': self.errors,
            'warnings': self.warnings,
            'compile_time': self.compile_time,
            'executable_size': self.executable_size,
        }


class ProjectCompiler:
    """Compile complete C/C++ projects"""
    
    # Known MSVC installation paths
    _MSVC_SEARCH_PATHS = [
        r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat",
        r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat",
        r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
    ]
    
    def __init__(self, compiler: str = 'auto', msvc_arch: str = 'x64'):
        """
        Initialize compiler
        
        Args:
            compiler: 'msvc', 'gcc', 'g++', 'auto' (auto-detect, prefers MSVC)
        """
        self.compiler_type = None  # 'msvc' or 'gcc'
        self.msvc_env = None       # Captured MSVC environment variables
        self.vcvarsall_path = None # Path to vcvarsall.bat
        self.msvc_arch = msvc_arch if msvc_arch in ('x86', 'x64') else 'x64'
        self.compiler = self._find_compiler(compiler)
        self.compile_flags = []
        self.link_flags = []
        self.include_dirs = []
        self.lib_dirs = []
        self.libraries = []
        
        # vcpkg integration — auto-detect vcpkg installed libraries
        self.vcpkg_root = self._find_vcpkg()
        self.vcpkg_include = None
        self.vcpkg_lib = None
        if self.vcpkg_root:
            triplet = 'x64-windows-static'
            self.vcpkg_include = os.path.join(self.vcpkg_root, 'installed', triplet, 'include')
            self.vcpkg_lib = os.path.join(self.vcpkg_root, 'installed', triplet, 'lib')
            if os.path.isdir(self.vcpkg_include):
                logger.info(f"   vcpkg found: {self.vcpkg_root} (triplet: {triplet})")
            else:
                self.vcpkg_include = None
                self.vcpkg_lib = None
        
        # Default flags for malware compilation
        if self.compiler_type == 'msvc':
            self._setup_msvc_flags()
        else:
            self._setup_default_flags()
    
    def _find_vcpkg(self) -> Optional[str]:
        """Find vcpkg installation"""
        candidates = [
            r'E:\vcpkg',
            r'C:\vcpkg',
            os.path.join(os.environ.get('VCPKG_ROOT', ''), '') if os.environ.get('VCPKG_ROOT') else None,
            os.path.join(os.environ.get('USERPROFILE', ''), 'vcpkg'),
        ]
        for p in candidates:
            if p and os.path.isdir(p) and os.path.exists(os.path.join(p, 'vcpkg.exe')):
                return p
        return None

    def _find_msvc(self) -> Optional[str]:
        """Find MSVC vcvarsall.bat"""
        for path in self._MSVC_SEARCH_PATHS:
            if os.path.exists(path):
                return path
        
        # Try vswhere.exe (VS installer)
        vswhere = r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
        if os.path.exists(vswhere):
            try:
                proc = subprocess.run(
                    [vswhere, '-latest', '-products', '*', '-requires',
                     'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
                     '-property', 'installationPath'],
                    capture_output=True, text=True, timeout=10
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    install_path = proc.stdout.strip()
                    vcvars = os.path.join(install_path, 'VC', 'Auxiliary', 'Build', 'vcvarsall.bat')
                    if os.path.exists(vcvars):
                        return vcvars
            except Exception:
                pass
        
        return None
    
    def _get_msvc_env(self, vcvarsall: str, arch: str = 'x64') -> Optional[Dict[str, str]]:
        """Run vcvarsall.bat and capture the resulting environment variables"""
        try:
            # Start from a CLEAN base environment to prevent arch mismatch.
            # If the current process already has x64 MSVC paths loaded (e.g. from
            # VS Code or a Developer Command Prompt), vcvarsall may detect the
            # existing setup and refuse to switch to x86, causing the compiler to
            # target x64 while the libraries remain x86 → LNK4272 errors.
            clean_env = {
                'SystemRoot': os.environ.get('SystemRoot', r'C:\Windows'),
                'SystemDrive': os.environ.get('SystemDrive', 'C:'),
                'TEMP': os.environ.get('TEMP', os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'Temp')),
                'TMP': os.environ.get('TMP', os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'Temp')),
                'COMSPEC': os.environ.get('COMSPEC', r'C:\Windows\system32\cmd.exe'),
                'PATH': os.environ.get('SystemRoot', r'C:\Windows') + r'\system32;' + os.environ.get('SystemRoot', r'C:\Windows'),
                'USERPROFILE': os.environ.get('USERPROFILE', ''),
            }
            # Run vcvarsall.bat and then 'set' to dump all env vars
            cmd = f'"{vcvarsall}" {arch} >nul 2>&1 && set'
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                timeout=30,
                # Use bytes mode to avoid encoding issues on Windows
                text=False,
                env=clean_env
            )
            
            if proc.returncode != 0:
                logger.warning(f"   ⚠️  vcvarsall.bat returned {proc.returncode}")
                return None
            
            # Decode stdout with error handling (vcvarsall may output non-UTF8 chars)
            try:
                stdout_text = proc.stdout.decode('utf-8', errors='replace')
            except Exception:
                stdout_text = proc.stdout.decode('cp1252', errors='replace')
            
            env = {}
            for line in stdout_text.split('\n'):
                line = line.strip()
                if '=' in line:
                    key, _, value = line.partition('=')
                    env[key] = value
            
            # Verify we got a meaningful environment
            if 'Path' not in env and 'PATH' not in env:
                logger.warning("   ⚠️  No PATH in MSVC environment")
                return None
            
            return env
            
        except subprocess.TimeoutExpired:
            logger.warning("   ⚠️  vcvarsall.bat timed out")
            return None
        except Exception as e:
            logger.warning(f"   ⚠️  Failed to setup MSVC environment: {e}")
            return None
        
    def _find_compiler(self, compiler: str) -> Dict[str, str]:
        """Find available compiler (prefers MSVC on Windows)"""
        compilers = {
            'c': None,
            'cpp': None,
        }
        
        # First check if cl.exe is already available in current environment
        # (e.g., when running from VS Developer Command Prompt)
        # Also verify that INCLUDE is set (needed for Windows SDK headers)
        if compiler in ('auto', 'msvc'):
            try:
                cl_check = subprocess.run(
                    ['cl.exe'],
                    capture_output=True,
                    timeout=5,
                    env=os.environ.copy()
                )
                # cl.exe with no args shows banner and returns 0
                # Also check INCLUDE env var is set (for Windows SDK headers like WinSock2.h)
                if 'Microsoft' in cl_check.stderr.decode('utf-8', errors='ignore'):
                    include_val = os.environ.get('INCLUDE', '')
                    if include_val:
                        # Validate that INCLUDE paths actually exist on disk
                        # (guards against stale env pointing to wrong SDK version)
                        inc_dirs = [d.strip() for d in include_val.split(';') if d.strip()]
                        missing = [d for d in inc_dirs if not os.path.isdir(d)]
                        if missing:
                            logger.info(f"⚠️  cl.exe found but INCLUDE has {len(missing)} non-existent path(s), running vcvarsall...")
                            logger.info(f"   Stale: {missing[0]}")
                        else:
                            logger.info(f"✓ cl.exe already available in environment")
                            self.compiler_type = 'msvc'
                            self.msvc_env = os.environ.copy()  # Use current environment
                            # Resolve full path to avoid CreateProcess PATH issues
                            cl_full = shutil.which('cl.exe') or 'cl.exe'
                            compilers['c'] = cl_full
                            compilers['cpp'] = cl_full
                            return compilers
                    else:
                        logger.info(f"⚠️  cl.exe found but INCLUDE not set, running vcvarsall...")
            except Exception:
                pass  # cl.exe not in PATH, try vcvarsall
        
        # Try MSVC first (unless explicitly requesting gcc)
        if compiler in ('auto', 'msvc'):
            vcvarsall = self._find_msvc()
            if vcvarsall:
                logger.info(f"🔍 Found MSVC: {vcvarsall}")
                msvc_env = self._get_msvc_env(vcvarsall, arch=self.msvc_arch)
                if msvc_env:
                    self.compiler_type = 'msvc'
                    self.msvc_env = msvc_env
                    self.vcvarsall_path = vcvarsall
                    
                    # CRITICAL: Resolve cl.exe to its FULL PATH using msvc_env's PATH.
                    # On Windows, subprocess.run(['cl.exe',...], env=msvc_env) with
                    # shell=False calls CreateProcess, which searches the PARENT
                    # process's PATH (not msvc_env PATH) for the executable.  If the
                    # parent (e.g. VS Code terminal) already has an x64 cl.exe in its
                    # PATH, the wrong compiler is invoked even though msvc_env was
                    # configured for x86.  Using the full path avoids this entirely.
                    msvc_path = msvc_env.get('Path', msvc_env.get('PATH', ''))
                    cl_full = shutil.which('cl.exe', path=msvc_path)
                    if cl_full:
                        compilers['c'] = cl_full
                        compilers['cpp'] = cl_full
                        logger.info(f"✓ MSVC compiler ready: {cl_full}")
                    else:
                        compilers['c'] = 'cl.exe'
                        compilers['cpp'] = 'cl.exe'
                        logger.info(f"✓ MSVC compiler ready (cl.exe)")
                    
                    # Log MSVC version
                    try:
                        ver_proc = subprocess.run(
                            [compilers['c']],
                            capture_output=True,
                            env=msvc_env, timeout=5
                        )
                        # cl.exe prints version to stderr
                        ver_line = ver_proc.stderr.decode('utf-8', errors='replace').split('\n')[0] if ver_proc.stderr else 'unknown'
                        logger.info(f"✓ MSVC version: {ver_line.strip()}")
                    except Exception:
                        pass
                    
                    return compilers
                else:
                    logger.warning("⚠️  Found vcvarsall.bat but failed to setup environment")
        
        # Fallback to GCC/MinGW
        if compiler in ('auto', 'gcc', 'g++'):
            self.compiler_type = 'gcc'
            
            gcc_variants = ['gcc', 'x86_64-w64-mingw32-gcc', 'i686-w64-mingw32-gcc']
            gpp_variants = ['g++', 'x86_64-w64-mingw32-g++', 'i686-w64-mingw32-g++']
            
            for gcc in gcc_variants:
                if shutil.which(gcc):
                    compilers['c'] = gcc
                    logger.info(f"✓ Found C compiler: {gcc}")
                    break
            
            for gpp in gpp_variants:
                if shutil.which(gpp):
                    compilers['cpp'] = gpp
                    logger.info(f"✓ Found C++ compiler: {gpp}")
                    break
            
            if not compilers['c'] and not compilers['cpp']:
                logger.warning("⚠️  No compiler found (neither MSVC nor GCC)!")
        
        return compilers
    
    def _setup_msvc_flags(self):
        """Setup default MSVC compilation flags for malware"""
        self.compile_flags = [
            '/nologo',        # Suppress startup banner
            '/O2',            # Optimize for speed
            '/MT',            # Static link C runtime (no VCRUNTIME dependency)
            '/EHsc',          # C++ exception handling
            # NOTE: UNICODE/MBCS is NOT defined by default.
            # Auto-detection in build_compile_command() will add /DUNICODE /D_UNICODE
            # ONLY when the source code genuinely uses wide-char APIs/types,
            # AND does not predominantly use ANSI char buffers with WinAPI.
            '/DWIN32',        # Windows 32/64-bit
            '/D_WINDOWS',     # Windows target
            '/DNDEBUG',       # Release mode
            '/DWINDOWS_IGNORE_PACKING_MISMATCH',  # Tolerate #pragma pack before windows.h
            # NOTE: Do NOT use WIN32_LEAN_AND_MEAN — it prevents windows.h from
            # including wincrypt.h, winsock2.h, shellapi.h, etc.
            # Malware samples commonly use CryptUnprotectData/DATA_BLOB/WinSock
            # which require these sub-headers.
            # Instead, we handle winsock conflicts by ensuring winsock2.h is
            # included before windows.h (already handled by source code order).
            '/D_CRT_SECURE_NO_WARNINGS',     # Suppress CRT security warnings
            '/D_CRT_NONSTDC_NO_DEPRECATE',   # Suppress POSIX deprecation
            '/D_WINSOCK_DEPRECATED_NO_WARNINGS',  # Suppress WinSock deprecation
            '/D_WIN32_WINNT=0x0601',         # Target Windows 7+
        ]
        
        # Link flags (go after /link)
        self.link_flags = [
            '/NOLOGO',
            '/RELEASE',          # Set release checksum
            '/OPT:REF',          # Remove unreferenced functions
            '/OPT:ICF',          # COMDAT folding
            '/INCREMENTAL:NO',   # Full link
        ]
        
        # Common Windows libraries (with .lib suffix for MSVC)
        self.libraries = [
            'kernel32.lib',
            'user32.lib',
            'advapi32.lib',
            'ws2_32.lib',
            'shell32.lib',
            'shlwapi.lib',
            'ole32.lib',
            'oleaut32.lib',
            'wininet.lib',
            'crypt32.lib',
            'gdi32.lib',
            'winspool.lib',
            'comdlg32.lib',
            'uuid.lib',
            'iphlpapi.lib',
            'psapi.lib',
            'ntdll.lib',
            'mpr.lib',
            'secur32.lib',
            'userenv.lib',
            'setupapi.lib',
            'version.lib',
            'netapi32.lib',
            'wtsapi32.lib',
            'urlmon.lib',
            'rpcrt4.lib',
            'dbghelp.lib',
            'cabinet.lib',
            'comctl32.lib',
            'legacy_stdio_definitions.lib',
        ]
    
    def _setup_default_flags(self):
        """Setup default GCC/MinGW compilation flags for malware"""
        self.compile_flags = [
            '-m64',
            '-O2',
            '-ffunction-sections',
            '-fdata-sections',
        ]
        
        self.link_flags = [
            '-static',
            '-Wl,--gc-sections',
            '-Wl,--strip-all',
        ]
        
        self.libraries = [
            'kernel32', 'user32', 'advapi32', 'ws2_32', 'shell32',
            'shlwapi', 'ole32', 'oleaut32', 'wininet', 'crypt32',
            'gdi32', 'winspool', 'comdlg32', 'uuid', 'iphlpapi',
            'psapi', 'ntdll', 'mpr', 'secur32', 'userenv',
            'setupapi', 'version', 'netapi32', 'wtsapi32',
        ]
    
    def add_include_dir(self, directory: str):
        """Add include directory"""
        if os.path.exists(directory):
            self.include_dirs.append(directory)
    
    def add_library(self, lib: str):
        """Add library to link"""
        if lib not in self.libraries:
            self.libraries.append(lib)

    @staticmethod
    def cleanup_build_intermediates(output_dir: str, keep_exe: bool = True) -> int:
        """
        Securely wipe build intermediates (.obj, .pdb, .ilk, .exp, .lib, .o)
        from output_dir.  Returns number of files removed.

        The .exe is kept by default (it goes to artifact store which handles
        encryption).  Intermediates are overwritten with zeros before deletion
        to prevent forensic recovery of partial PE content.
        """
        intermediate_exts = {".obj", ".o", ".pdb", ".ilk", ".exp", ".lib", ".idb", ".pch"}
        removed = 0
        for ext in intermediate_exts:
            for fpath in glob.glob(os.path.join(output_dir, f"*{ext}")):
                try:
                    # Overwrite with zeros before unlinking
                    sz = os.path.getsize(fpath)
                    with open(fpath, "wb") as f:
                        f.write(b"\x00" * min(sz, 4096))  # zero first 4K (fast)
                        f.flush()
                        os.fsync(f.fileno())
                    os.unlink(fpath)
                    removed += 1
                except OSError:
                    pass
        if removed:
            logger.info(f"   🧹 Wiped {removed} build intermediates from {output_dir}")
        return removed
    
    def _build_msvc_compile_cmd(self, project, language, compiler_cmd, executable_path, optimization, output_dir):
        """Build MSVC cl.exe compilation command"""
        # MSVC cl.exe: cl /nologo /O2 /MT /EHsc /Fe:out.exe file1.c file2.cpp /I dir /link lib.lib
        compile_cmd = [compiler_cmd]
        
        # Compiler flags
        compile_cmd.extend(self.compile_flags)
        
        # Check if project has mixed C and C++ files
        c_files = [f for f in project.source_files if f.lower().endswith('.c')]
        cpp_files = [f for f in project.source_files if f.lower().endswith(('.cpp', '.cxx', '.cc'))]
        has_mixed = len(c_files) > 0 and len(cpp_files) > 0
        
        # Language standard and compilation mode
        if language == 'cpp':
            compile_cmd.append('/std:c++17')
            if not has_mixed:
                compile_cmd.append('/TP')  # Force C++ compilation for all files
            # If mixed, let MSVC auto-detect based on extension
            logger.info(f"   Using C++ standard: /std:c++17{' (mixed C/C++ project)' if has_mixed else ''}")
        else:
            compile_cmd.append('/std:c11')
            compile_cmd.append('/TC')  # Force C compilation
            logger.info(f"   Using C standard: /std:c11")
        
        # Optimization
        opt_map = {'O0': '/Od', 'O1': '/O1', 'O2': '/O2', 'O3': '/Ox', 'Os': '/Os'}
        compile_cmd.append(opt_map.get(optimization, '/O2'))
        
        # Suppress all warnings for malware code
        compile_cmd.append('/w')
        
        # Output executable
        compile_cmd.append(f'/Fe:{executable_path}')
        
        # Object file output directory (to avoid cluttering source dirs)
        compile_cmd.append(f'/Fo:{output_dir}\\')
        
        # Include directories
        for inc_dir in self.include_dirs:
            compile_cmd.append(f'/I{inc_dir}')
        
        # Detect multiple main() definitions - each file with main() is a separate program
        # Only keep the largest file with main() and include all non-main files
        import re as _re_local
        main_files = []
        non_main_files = []
        for src_file in project.source_files:
            try:
                with open(src_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                # Match main() definition (not declaration or comment)
                if _re_local.search(r'^\s*(?:int\s+)?main\s*\(', content, _re_local.MULTILINE):
                    main_files.append(src_file)
                else:
                    non_main_files.append(src_file)
            except Exception:
                non_main_files.append(src_file)
        
        if len(main_files) > 1:
            # Multiple main() — pick the largest file as the "primary" entry point
            main_files.sort(key=lambda f: os.path.getsize(f), reverse=True)
            primary_main = main_files[0]
            logger.info(f"   ⚠️  Multiple main() found in {len(main_files)} files — using {os.path.basename(primary_main)}")
            for excluded in main_files[1:]:
                logger.info(f"      Excluding: {os.path.basename(excluded)} (duplicate main)")
            effective_sources = [primary_main] + non_main_files
        else:
            effective_sources = project.source_files
        
        # Check if project links old OpenSSL libs that reference __iob_func (removed in VS2015+)
        # If so, inject a compatibility shim source file
        has_old_openssl_libs = False
        for other_file in getattr(project, 'other_files', []):
            basename = os.path.basename(other_file).lower()
            if basename in ('libeay32.lib', 'ssleay32.lib', 'libssl.lib', 'libcrypto.lib'):
                has_old_openssl_libs = True
                break
        
        if has_old_openssl_libs:
            # Generate __iob_func shim to fix LNK2019 with old OpenSSL libs
            shim_path = os.path.join(output_dir, '_iob_func_shim.c')
            shim_content = '''/* Auto-generated shim for __iob_func compatibility with MSVC 2015+ */
#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif
FILE * __cdecl __iob_func(void) {
    static FILE _iob[3];
    _iob[0] = *stdin;
    _iob[1] = *stdout;
    _iob[2] = *stderr;
    return _iob;
}
#ifdef __cplusplus
}
#endif
'''
            try:
                with open(shim_path, 'w', encoding='utf-8') as f:
                    f.write(shim_content)
                effective_sources.append(shim_path)
                logger.info(f"   Injected __iob_func shim for old OpenSSL lib compatibility")
            except Exception as e:
                logger.warning(f"   Failed to create __iob_func shim: {e}")
        
        # Source files
        compile_cmd.extend(effective_sources)
        
        # Linker section (everything after /link goes to linker)
        compile_cmd.append('/link')
        
        # Link flags
        compile_cmd.extend(self.link_flags)
        
        # Auto-detect subsystem based on entry point
        subsystem = 'CONSOLE'
        try:
            for src_file in project.source_files:
                with open(src_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Check for WinMain or DllMain => GUI/DLL subsystem
                    if 'WinMain' in content or 'wWinMain' in content:
                        subsystem = 'WINDOWS'
                        logger.info(f"   Auto-detected GUI subsystem (WinMain found)")
                        break
                    if 'DllMain' in content:
                        subsystem = 'WINDOWS'  # DLLs need WINDOWS subsystem
                        logger.info(f"   Auto-detected DLL subsystem (DllMain found)")
                        break
        except Exception as e:
            logger.debug(f"   Could not auto-detect subsystem: {e}")
        
        compile_cmd.append(f'/SUBSYSTEM:{subsystem}')
        
        # Auto-detect UNICODE mode and additional required libraries
        additional_libs = set()
        needs_unicode = False
        try:
            all_content = ""
            for src_file in project.source_files + project.header_files:
                try:
                    with open(src_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        all_content += content
                except Exception:
                    continue
            
            # --- UNICODE vs ANSI detection ---
            # Count both wide-char (UNICODE) and narrow-char (ANSI) indicators.
            # Only define UNICODE when wide usage clearly dominates.
            import re as _re
            unicode_score = 0
            ansi_score = 0
            
            # --- Wide (UNICODE) indicators ---
            if 'LPCWSTR' in all_content or 'LPWSTR' in all_content:
                unicode_score += 2
            if 'WCHAR' in all_content and 'WCHAR*' in all_content:
                unicode_score += 2
            if 'wchar_t' in all_content:
                unicode_score += 1
            # Wide string literals like L"..."
            if _re.search(r'\bL"[^"]*"', all_content):
                unicode_score += 2
            # W-suffix API calls like CreateFileW, MessageBoxW
            w_calls = len(_re.findall(r'\b[A-Z]\w+W\s*\(', all_content))
            if w_calls > 0:
                unicode_score += min(w_calls, 3)
            # wnsprintfW / wsprintfW
            if 'wnsprintfW' in all_content or 'wsprintfW' in all_content:
                unicode_score += 2
            # If TCHAR is used alongside WCHAR, may need UNICODE
            if 'TCHAR' in all_content and unicode_score >= 2:
                unicode_score += 2
            
            # --- Narrow (ANSI) indicators ---
            # char buffers passed to WinAPI are strong ANSI signals
            ansi_buf_patterns = len(_re.findall(r'\bchar\s+\w+\s*\[\s*\d+\s*\]', all_content))
            if ansi_buf_patterns > 0:
                ansi_score += min(ansi_buf_patterns, 5)
            if 'LPCSTR' in all_content or 'LPSTR' in all_content:
                ansi_score += 2
            # A-suffix API calls like CreateFileA, MessageBoxA
            a_calls = len(_re.findall(r'\b[A-Z]\w+A\s*\(', all_content))
            if a_calls > 0:
                ansi_score += min(a_calls, 3)
            # ANSI string functions with char*
            if 'strlwr' in all_content or 'strupr' in all_content:
                ansi_score += 1
            if _re.search(r'\bstrcat\s*\(', all_content) or _re.search(r'\bstrcpy\s*\(', all_content):
                ansi_score += 1
            # getenv returns char*
            if 'getenv(' in all_content:
                ansi_score += 1
            
            logger.info(f"   UNICODE score: {unicode_score}, ANSI score: {ansi_score}")
            
            # Enable UNICODE when wide usage exceeds narrow usage
            if unicode_score >= 3 and unicode_score > ansi_score:
                needs_unicode = True
                logger.info(f"   Auto-detected UNICODE mode (wide={unicode_score} >> ansi={ansi_score})")
            else:
                logger.info(f"   Using ANSI/MBCS mode (wide={unicode_score} <= ansi={ansi_score})")
            
            # --- Library detection ---
            # Registry / Crypto context => advapi32.lib
            if any(fn in all_content for fn in ['RegOpenKey', 'RegCloseKey', 'RegQueryValue', 'RegSetValue',
                    'RegCreateKey', 'RegDeleteKey', 'CryptAcquireContext', 'CryptGenRandom',
                    'CryptReleaseContext', 'OpenProcessToken', 'AdjustTokenPrivileges']):
                additional_libs.add('advapi32.lib')
            # Shell functions => shell32.lib
            if any(fn in all_content for fn in ['ShellExecute', 'SHGetFolderPath', 'SHFileOperation',
                    'SHGetSpecialFolder', 'CommandLineToArgvW']):
                additional_libs.add('shell32.lib')
            # Network functions => ws2_32.lib
            if any(fn in all_content for fn in ['socket', 'WSAStartup', 'gethostbyname', 'getaddrinfo',
                    'WSASocket', 'WSAConnect']):
                additional_libs.add('ws2_32.lib')
            # WinInet => wininet.lib
            if any(fn in all_content for fn in ['InternetOpen', 'InternetConnect', 'HttpOpenRequest',
                    'InternetReadFile', 'HttpSendRequest', 'InternetCloseHandle']):
                additional_libs.add('wininet.lib')
            # OLE/COM => ole32.lib oleaut32.lib
            if any(fn in all_content for fn in ['CoInitialize', 'CoCreateInstance', 'CoCreateGuid',
                    'StringFromGUID', 'OleInitialize', 'OleUninitialize',
                    'SafeArrayCreate', 'VariantInit', 'SysAllocString', 'SysFreeString']):
                additional_libs.add('ole32.lib')
                additional_libs.add('oleaut32.lib')
            # DPAPI / Crypto => crypt32.lib
            if any(fn in all_content for fn in ['CryptUnprotectData', 'CryptProtectData',
                    'CryptStringToBinary', 'CryptBinaryToString', 'CertOpenStore']):
                additional_libs.add('crypt32.lib')
            # Shlwapi => shlwapi.lib
            if any(fn in all_content for fn in ['wnsprintfA', 'wnsprintfW', 'PathFileExists',
                    'PathCombine', 'PathAppend', 'PathFindFileName', 'PathRemoveFileSpec',
                    'StrStr', 'PathIsDirectory']):
                additional_libs.add('shlwapi.lib')
            # DNS => dnsapi.lib
            if any(fn in all_content for fn in ['DnsQuery', 'DnsFree', 'DnsRecordListFree']):
                additional_libs.add('dnsapi.lib')
            # IP Helper => iphlpapi.lib
            if any(fn in all_content for fn in ['GetAdaptersInfo', 'GetAdaptersAddresses',
                    'GetIpAddrTable', 'GetBestInterface', 'GetNetworkParams']):
                additional_libs.add('iphlpapi.lib')
            # GDI => gdi32.lib
            if any(fn in all_content for fn in ['CreateCompatibleDC', 'CreateCompatibleBitmap',
                    'BitBlt', 'SelectObject', 'DeleteDC', 'GetDIBits', 'CreateDIBSection',
                    'GetObject', 'DeleteObject']):
                additional_libs.add('gdi32.lib')
            # User32 => user32.lib
            if any(fn in all_content for fn in ['GetDesktopWindow', 'GetWindowDC', 'SendMessage',
                    'FindWindow', 'MessageBox', 'GetDC', 'ReleaseDC', 'SetWindowPos',
                    'GetSystemMetrics', 'EnumWindows', 'PostMessage', 'DestroyWindow']):
                additional_libs.add('user32.lib')
            # VFW (Video for Windows) => vfw32.lib
            if any(fn in all_content for fn in ['capCreateCaptureWindow', 'capGetDriverDescription',
                    'MCIWndCreate']) or 'WM_CAP_' in all_content or '#include' in all_content and 'vfw.h' in all_content:
                additional_libs.add('vfw32.lib')
            # WinCred => credui.lib (usually no extra lib needed, but add advapi32)
            if any(fn in all_content for fn in ['CredEnumerate', 'CredFree', 'CredRead']):
                additional_libs.add('advapi32.lib')
            # Winmm => winmm.lib
            if any(fn in all_content for fn in ['PlaySound', 'mciSendString', 'timeGetTime']):
                additional_libs.add('winmm.lib')
            # Psapi => psapi.lib
            if any(fn in all_content for fn in ['EnumProcesses', 'GetModuleFileNameEx',
                    'EnumProcessModules', 'GetProcessMemoryInfo']):
                additional_libs.add('psapi.lib')
            # Ntdll => ntdll.lib
            if any(fn in all_content for fn in ['NtQuerySystemInformation', 'NtQueryInformationProcess',
                    'RtlInitUnicodeString', 'NtCreateFile']):
                additional_libs.add('ntdll.lib')
            # Winspool => winspool.lib
            if any(fn in all_content for fn in ['OpenPrinter', 'EnumPrinters', 'GetPrinter']):
                additional_libs.add('winspool.lib')
            # Urlmon => urlmon.lib
            if any(fn in all_content for fn in ['URLDownloadToFile', 'URLDownloadToCacheFile']):
                additional_libs.add('urlmon.lib')
            # #pragma comment(lib, ...) - parse these too
            for m in _re.finditer(r'#pragma\s+comment\s*\(\s*lib\s*,\s*"([^"]+)"\s*\)', all_content):
                lib_name = m.group(1)
                # Ensure .lib extension
                if not lib_name.lower().endswith('.lib'):
                    lib_name = lib_name + '.lib'
                additional_libs.add(lib_name)
                
        except Exception as e:
            logger.debug(f"   Could not auto-detect libraries: {e}")
        
        # Detect custom /ENTRY: pragmas — respect the project's custom entry point
        # instead of overriding it with CRT entry, which breaks projects that
        # intentionally bypass CRT (e.g., malware with custom _entryPoint).
        try:
            entry_match = _re.search(
                r'^[^/\n]*#pragma\s+comment\s*\(\s*linker\s*,\s*"\s*(/ENTRY:|/entry:)([^"\s]+)',
                all_content,
                _re.MULTILINE
            )
            if entry_match:
                custom_entry = entry_match.group(2)
                # Use the project's own custom entry point
                try:
                    link_idx = compile_cmd.index('/link')
                    compile_cmd.insert(link_idx + 1, f'/ENTRY:{custom_entry}')
                    logger.info(f"   Using project's custom entry point: /ENTRY:{custom_entry}")
                except ValueError:
                    pass
        except Exception:
            pass
        
        # Insert UNICODE defines before source files if detected
        if needs_unicode:
            # Find position after compiler flags but before source files
            # Insert right after the /w flag
            try:
                w_idx = compile_cmd.index('/w')
                compile_cmd.insert(w_idx + 1, '/D_UNICODE')
                compile_cmd.insert(w_idx + 1, '/DUNICODE')
                logger.info(f"   Added /DUNICODE /D_UNICODE defines")
            except ValueError:
                compile_cmd.insert(1, '/D_UNICODE')
                compile_cmd.insert(1, '/DUNICODE')
        
        if additional_libs:
            logger.info(f"   Auto-detected libraries: {', '.join(additional_libs)}")
        
        # Libraries - always use full library set
        # Projects with /NODEFAULTLIB pragma handle CRT exclusion themselves;
        # our explicit libraries (ntdll.lib etc.) still get searched by the linker
        compile_cmd.extend(self.libraries)
        compile_cmd.extend(additional_libs)
        
        # === vcpkg external library integration ===
        # Detect which external libraries this project needs and add vcpkg paths
        vcpkg_libs_needed = set()
        if self.vcpkg_include and self.vcpkg_lib:
            try:
                # OpenSSL
                if any(h in all_content for h in ['openssl/evp.h', 'openssl/aes.h', 'openssl/sha.h',
                        'openssl/ecdh.h', 'openssl/ssl.h', 'openssl/rsa.h', 'openssl/pem.h',
                        'openssl/ec.h', 'openssl/bn.h']):
                    vcpkg_libs_needed.update(['libcrypto.lib', 'libssl.lib'])
                    # Remove old OpenSSL lib pragmas that won't resolve (libeay32, ssleay32)
                    compile_cmd = [x for x in compile_cmd if x.lower() not in
                                   ('libeay32.lib', 'ssleay32.lib')]
                # Crypto++
                if 'cryptopp/' in all_content:
                    vcpkg_libs_needed.add('cryptopp.lib')
                # libcurl
                if 'curl/curl.h' in all_content:
                    vcpkg_libs_needed.update(['libcurl.lib', 'zlib.lib'])
                    compile_cmd.append('/DCURL_STATICLIB')
                # libjpeg
                if 'jpeglib.h' in all_content:
                    vcpkg_libs_needed.add('jpeg.lib')
                # nlohmann/json (header-only, just needs include path)
                # fmt
                if 'fmt/core.h' in all_content or 'fmt/format.h' in all_content:
                    vcpkg_libs_needed.add('fmt.lib')
                # cpr
                if 'cpr/cpr.h' in all_content:
                    vcpkg_libs_needed.update(['cpr.lib', 'libcurl.lib', 'zlib.lib', 'libssl.lib', 'libcrypto.lib'])
                    compile_cmd.append('/DCURL_STATICLIB')
                
                if vcpkg_libs_needed:
                    # Add vcpkg include path (before source files)
                    compile_cmd.insert(1, f'/I{self.vcpkg_include}')
                    # Add vcpkg lib path and libraries
                    compile_cmd.append(f'/LIBPATH:{self.vcpkg_lib}')
                    compile_cmd.extend(vcpkg_libs_needed)
                    logger.info(f"   vcpkg libraries: {', '.join(vcpkg_libs_needed)}")
            except Exception as e:
                logger.debug(f"   vcpkg detection error: {e}")
        
        # Add /LIBPATH for directories containing .lib files in the project
        lib_dirs_added = set()
        for other_file in getattr(project, 'other_files', []):
            if other_file.lower().endswith('.lib'):
                lib_dir = os.path.dirname(other_file)
                if lib_dir and lib_dir not in lib_dirs_added:
                    lib_dirs_added.add(lib_dir)
                    compile_cmd.append(f'/LIBPATH:{lib_dir}')
                    logger.info(f"   Added /LIBPATH:{lib_dir}")
        # Always add project root as library search path
        if project.root_dir not in lib_dirs_added:
            compile_cmd.append(f'/LIBPATH:{project.root_dir}')
        
        # Log command
        logger.info(f"\n📝 MSVC Compilation command:")
        logger.info(f"   cl.exe {' '.join(compile_cmd[1:5])} ... /link ...")
        logger.info(f"   Total arguments: {len(compile_cmd)}")
        
        # Save command to file
        cmd_file = os.path.join(output_dir, 'compile_command.txt')
        with open(cmd_file, 'w', encoding='utf-8') as f:
            f.write(' '.join(compile_cmd))
        logger.info(f"   Saved to: {cmd_file}")
        
        return compile_cmd, getattr(self, '_project_msvc_env', self.msvc_env)
    
    def _build_gcc_compile_cmd(self, project, language, compiler_cmd, executable_path, optimization, output_dir):
        """Build GCC/MinGW compilation command"""
        compile_cmd = [compiler_cmd]
        
        # Check for mixed C/C++ source files
        has_c_files = any(f.endswith('.c') for f in project.source_files)
        has_cpp_files = any(f.endswith(('.cpp', '.cc', '.cxx')) for f in project.source_files)
        is_mixed = language == 'cpp' and has_c_files and has_cpp_files
        
        c_object_files = []
        effective_source_files = list(project.source_files)
        
        if is_mixed and self.compiler.get('c'):
            c_source_files = [f for f in project.source_files if f.endswith('.c')]
            cpp_source_files = [f for f in project.source_files if not f.endswith('.c')]
            logger.info(f"\n🔀 Mixed C/C++ project: {len(cpp_source_files)} C++ files, {len(c_source_files)} C files")
            logger.info(f"   Pre-compiling C files with {self.compiler['c']}...")
            
            c_compile_success = True
            for c_file in c_source_files:
                obj_file = os.path.join(output_dir, os.path.basename(c_file).replace('.c', '.o'))
                c_cmd = [self.compiler['c'], '-c', c_file, '-o', obj_file, '-std=gnu11']
                c_cmd.extend(self.compile_flags)
                for inc_dir in self.include_dirs:
                    c_cmd.extend(['-I', inc_dir])
                c_cmd.extend(['-w', '-fpermissive'])
                
                try:
                    c_proc = subprocess.run(c_cmd, capture_output=True, text=True, timeout=120)
                    if c_proc.returncode == 0 and os.path.exists(obj_file):
                        c_object_files.append(obj_file)
                        logger.info(f"   ✓ {os.path.basename(c_file)} → {os.path.basename(obj_file)}")
                    else:
                        logger.warning(f"   ⚠ Failed to pre-compile {os.path.basename(c_file)}: {c_proc.stderr[:200]}")
                        c_compile_success = False
                except Exception as e:
                    logger.warning(f"   ⚠ Error pre-compiling {os.path.basename(c_file)}: {e}")
                    c_compile_success = False
            
            if c_compile_success and c_object_files:
                effective_source_files = cpp_source_files + c_object_files
                logger.info(f"   ✓ All C files pre-compiled successfully")
            else:
                logger.warning(f"   Falling back to compiling all files with {compiler_cmd}")
                c_object_files = []
                effective_source_files = list(project.source_files)
        
        # Detect multiple main() definitions for GCC path too
        import re as _re_local_gcc
        gcc_main_files = []
        gcc_non_main_files = []
        for src_file in effective_source_files:
            if src_file.endswith('.o') or src_file.endswith('.obj'):
                gcc_non_main_files.append(src_file)
                continue
            try:
                with open(src_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                if _re_local_gcc.search(r'^\s*(?:int\s+)?main\s*\(', content, _re_local_gcc.MULTILINE):
                    gcc_main_files.append(src_file)
                else:
                    gcc_non_main_files.append(src_file)
            except Exception:
                gcc_non_main_files.append(src_file)
        
        if len(gcc_main_files) > 1:
            gcc_main_files.sort(key=lambda f: os.path.getsize(f), reverse=True)
            primary = gcc_main_files[0]
            logger.info(f"   ⚠️  Multiple main() found in {len(gcc_main_files)} files — using {os.path.basename(primary)}")
            for excluded in gcc_main_files[1:]:
                logger.info(f"      Excluding: {os.path.basename(excluded)} (duplicate main)")
            effective_source_files = [primary] + gcc_non_main_files
        
        # Add source files
        compile_cmd.extend(effective_source_files)
        
        # Output
        compile_cmd.extend(['-o', executable_path])
        
        # Include directories
        for inc_dir in self.include_dirs:
            compile_cmd.extend(['-I', inc_dir])
        
        # Compile flags
        compile_cmd.extend(self.compile_flags)
        
        # Language standard
        if language == 'cpp':
            compile_cmd.append('-std=gnu++17')
            logger.info(f"   Using C++ standard: -std=gnu++17")
        else:
            compile_cmd.append('-std=gnu11')
            logger.info(f"   Using C standard: -std=gnu11")
        
        # Update optimization
        compile_cmd = [c for c in compile_cmd if not c.startswith('-O')]
        compile_cmd.append(f'-{optimization}')
        
        # Link flags
        compile_cmd.extend(self.link_flags)
        
        # Libraries
        for lib in self.libraries:
            compile_cmd.extend(['-l', lib])
        
        # Suppress warnings
        compile_cmd.extend(['-w', '-fpermissive', '-Wno-everything'])
        
        # Log command
        logger.info(f"\n📝 GCC Compilation command:")
        logger.info(f"   {' '.join(compile_cmd[:3])} ...")
        logger.info(f"   Total arguments: {len(compile_cmd)}")
        
        # Save command to file
        cmd_file = os.path.join(output_dir, 'compile_command.txt')
        with open(cmd_file, 'w', encoding='utf-8') as f:
            f.write(' '.join(compile_cmd))
        logger.info(f"   Saved to: {cmd_file}")
        
        return compile_cmd
    
    def compile_project(
        self, 
        project,
        output_dir: str,
        output_name: str = None,
        optimization: str = 'O2',
        auto_fix: bool = True,
        max_fix_attempts: int = 3,
        llm_model: str = "qwen2.5:32b",
        use_llm_fixer: bool = True,
        llm_fixer_max_code_length: int = 50000,
        permissive_mode: bool = True,
        parse_result = None,  # Optional parse result for enhanced context
        pre_validate: bool = True,  # Run validation before compilation
        auto_generate_headers: bool = True,  # Auto-generate missing headers
        use_enhanced_categorization: bool = True,  # Use enhanced error categorization
        use_project_context: bool = True,  # Collect project-wide context for LLM
        use_hybrid_llm: bool = False,  # Enable hybrid mode (Ollama + Mistral)
        hybrid_local_model: str = "qwen2.5-coder:7b-instruct-q4_K_M",  # Local model
        hybrid_cloud_file_size_limit: int = 15000,  # Files below this use cloud, above use local
        hybrid_mode: str = "hybrid",  # Mode: "hybrid", "local_only", "cloud_only"
        use_mahoraga: bool = False,  # Enable Mahoraga adaptive fixer
        mahoraga_memory_file: str = None,  # Path to Mahoraga memory file
        external_fixer = None,  # Pre-created fixer instance (Mahoraga or AutoFixer)
        clang_analysis = None,  # Pre-computed ClangAnalyzer result
    ) -> CompilationResult:
        """
        Compile complete project to executable
        
        Args:
            project: MalwareProject object
            output_dir: Output directory
            output_name: Output executable name (default: project name)
            optimization: Optimization level (O0, O1, O2, O3, Os)
            auto_fix: Enable automatic error fixing
            max_fix_attempts: Maximum fix attempts
            llm_model: LLM model for auto-fixing (default: codestral-2508)
            use_llm_fixer: Use LLM-powered fixer (default: True)
            llm_fixer_max_code_length: Maximum source code length for LLM fixer (default: 50000)
            permissive_mode: Try permissive compilation flags (default: True)
            
        Returns:
            CompilationResult object
        """
        result = CompilationResult()
        
        if not project.source_files:
            logger.error("❌ No source files to compile")
            result.errors = "No source files"
            return result
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Determine output name
        if not output_name:
            output_name = f"{project.name}_mutated.exe"
        if not output_name.endswith('.exe'):
            output_name += '.exe'
        
        executable_path = os.path.join(output_dir, output_name)
        
        # Determine language
        language = project.get_language()

        # Route Python and JavaScript projects to dedicated compilers
        if language == 'python':
            return self._compile_python_project(project, output_dir, output_name)
        elif language == 'javascript':
            return self._compile_javascript_project(project, output_dir, output_name)

        compiler_cmd = self.compiler['cpp'] if language == 'cpp' else self.compiler['c']
        
        if not compiler_cmd:
            logger.error(f"❌ No compiler found for {language}")
            result.errors = f"No {language} compiler found"
            return result
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🔨 COMPILING PROJECT: {project.name}")
        logger.info(f"{'='*60}")
        logger.info(f"Language: {language.upper()}")
        logger.info(f"Compiler: {compiler_cmd} ({self.compiler_type.upper()})")
        logger.info(f"Source files: {len(project.source_files)}")
        logger.info(f"Header files: {len(project.header_files)}")
        logger.info(f"Output: {executable_path}")
        
        # === ADAPT FLAGS FOR DETECTED PROJECT BUILD CONFIG ===
        msvc_ver = getattr(project, 'target_msvc_version', '')
        target_arch = getattr(project, 'target_arch', 'x64')
        nodefaultlib = getattr(project, 'nodefaultlib', False)
        custom_ntdll = getattr(project, 'has_custom_ntdll_h', False)
        needs_gs_off = getattr(project, 'needs_gs_disabled', False)
        extra_defines = getattr(project, 'extra_defines', [])

        if msvc_ver:
            logger.info(f"   Detected project target: {msvc_ver.upper()}, arch={target_arch}")
        if nodefaultlib:
            logger.info(f"   Project excludes default CRT (/NODEFAULTLIB)")
        if custom_ntdll:
            logger.info(f"   Project has custom ntdll.h (may conflict with SDK)")

        # NOTE: We always use x64 compilation even for projects originally targeting x86.
        # Modern MSVC 2022 x64 builds are compatible with most old x86 code patterns,
        # and switching arch at runtime requires re-resolving cl.exe path which is fragile.
        self._project_msvc_env = self.msvc_env

        # Rebuild compile_flags per-project to avoid accumulation
        if self.compiler_type == 'msvc':
            self._setup_msvc_flags()
        else:
            self._setup_default_flags()

        # Apply project-specific flag adjustments
        if self.compiler_type == 'msvc':
            # --- GS (buffer security check) ---
            if needs_gs_off:
                self.compile_flags.append('/GS-')
                logger.info(f"   Added /GS- (project excludes CRT)")

            # --- Extra defines for old MSVC projects ---
            for define in extra_defines:
                self.compile_flags.append(f'/D{define}')

            # --- Old MSVC 6.0 projects: add compatibility flags ---
            if msvc_ver in ('msvc6', 'msvc7', 'msvc8'):
                # These old projects often use deprecated APIs and K&R-ish code
                if '/Zc:twoPhase-' not in self.compile_flags:
                    self.compile_flags.append('/Zc:twoPhase-')
                # Allow implicit int (common in MSVC 6 C code)
                if '/Zc:implicitNoexcept-' not in self.compile_flags:
                    pass  # /w already suppresses warnings

        # Reset include dirs for each project to prevent cross-contamination
        self.include_dirs = []
        
        # Add project's root directory and subdirectories as include paths
        self.add_include_dir(project.root_dir)
        
        # Find all subdirectories with headers
        for header_file in project.header_files:
            header_dir = os.path.dirname(header_file)
            if header_dir not in self.include_dirs:
                self.add_include_dir(header_dir)
        
        # Also add all subdirectories with source files as include paths
        # This handles cross-directory includes like #include "common/utils.h"
        for source_file in project.source_files:
            source_dir = os.path.dirname(source_file)
            if source_dir not in self.include_dirs:
                self.add_include_dir(source_dir)
        
        # Add all immediate subdirectories of root as include paths
        # This handles projects like KINS with includes like #include "common/mem.h"
        if os.path.isdir(project.root_dir):
            for entry in os.listdir(project.root_dir):
                subdir = os.path.join(project.root_dir, entry)
                if os.path.isdir(subdir) and subdir not in self.include_dirs:
                    self.add_include_dir(subdir)
        
        # === ENHANCED VALIDATION AND CONTEXT COLLECTION ===
        project_context = None
        validation_issues = []
        
        if ENHANCED_TOOLS_AVAILABLE and pre_validate:
            logger.info(f"\n📋 Running pre-compilation validation...")
            
            # Validate project
            is_valid, validation_issues = CompilationValidator.validate_project(project, verbose=True)
            
            if validation_issues:
                logger.warning(f"\n⚠️  Found {len(validation_issues)} validation issue(s)")
                
                # Try to auto-fix validation issues
                if auto_fix:
                    fixes_applied = CompilationValidator.auto_fix_issues(project, validation_issues)
                    if fixes_applied > 0:
                        logger.info(f"   ✓ Auto-fixed {fixes_applied} issue(s)")
                        # Re-validate after fixes
                        is_valid, validation_issues = CompilationValidator.validate_project(project, verbose=False)
        
        # Collect project context for LLM fixer (ALWAYS if use_project_context is enabled)
        if ENHANCED_TOOLS_AVAILABLE and use_project_context:
            logger.info(f"\n📚 Collecting project context...")
            project_context = ProjectContextCollector.collect_project_context(project, parse_result)
        
        # Build multi-file symbol index for cross-file dependency resolution
        multi_file_support = None
        if MULTI_FILE_SUPPORT_AVAILABLE and auto_fix:
            logger.info(f"\n🔗 Building multi-file symbol index...")
            multi_file_support = get_multi_file_support()
            multi_file_support.build_index(project)
        
        # Run Clang AST analysis for compilation-fix context
        clang_analyzer_instance = None
        if CLANG_ANALYZER_AVAILABLE and auto_fix:
            if clang_analysis is None:
                try:
                    logger.info(f"\n🔬 Running Clang AST analysis for fix context...")
                    clang_analyzer_instance = ClangAnalyzer()
                    clang_analysis = clang_analyzer_instance.analyze_files(
                        list(project.source_files),
                        list(getattr(project, 'header_files', []))
                    )
                    logger.info(f"   Symbols: {len(clang_analysis.symbols)}, "
                               f"Functions: {len(clang_analysis.functions) if hasattr(clang_analysis, 'functions') else len(clang_analysis.get_function_symbols())}, "
                               f"Dependencies: {len(clang_analysis.dependencies)}")
                except Exception as e:
                    logger.warning(f"   Clang analysis failed: {e}")
                    clang_analysis = None
            else:
                logger.info(f"\n🔬 Using pre-computed Clang analysis ({len(clang_analysis.symbols)} symbols)")
        
        # Generate project header if requested
        if ENHANCED_TOOLS_AVAILABLE and auto_generate_headers and project.source_files:
            try:
                logger.info(f"\n📝 Generating project header...")
                header_path = HeaderGenerator.generate_project_header(
                    project,
                    output_path=output_dir,
                    header_name=f"{project.name}_declarations.h"
                )
                # Add header to project
                if header_path not in project.header_files:
                    project.add_header_file(header_path)
            except Exception as e:
                logger.warning(f"Failed to generate project header: {e}")
        
        # Build compilation command — branch on compiler type
        if self.compiler_type == 'msvc':
            compile_cmd, subprocess_env = self._build_msvc_compile_cmd(
                project, language, compiler_cmd, executable_path, optimization, output_dir
            )
        else:
            compile_cmd = self._build_gcc_compile_cmd(
                project, language, compiler_cmd, executable_path, optimization, output_dir
            )
            subprocess_env = None  # Use default env for GCC
        
        # Execute compilation with auto-fix retry
        auto_fixer = None
        llm_fixer = None
        fix_history = []
        
        if auto_fix:
            # Use external fixer if provided (shared across projects)
            if external_fixer:
                llm_fixer = external_fixer
                logger.info(f"\u2638 Using shared external fixer")
            # Try Mahoraga adaptive fixer first (if enabled)
            elif use_mahoraga and MAHORAGA_AVAILABLE and MahoragaAdaptiveFixer:
                try:
                    # Resolve API key based on model name
                    # Ollama-format names (with ':') go to RunPod, not DeepSeek API
                    if llm_model.startswith('deepseek-') and ':' not in llm_model:
                        api_key = os.environ.get('DEEPSEEK_API_KEY')
                    elif llm_model.startswith('codestral-') or llm_model.startswith('mistral-'):
                        api_key = os.environ.get('MISTRAL_API_KEY')
                    else:
                        api_key = os.environ.get('RUNPOD_API_KEY', 'ollama')
                    llm_fixer = MahoragaAdaptiveFixer(
                        llm_model=llm_model,
                        api_key=api_key,
                        use_hybrid=use_hybrid_llm,
                        local_model=hybrid_local_model,
                        cloud_file_size_limit=hybrid_cloud_file_size_limit,
                        mode=hybrid_mode,
                        memory_file=mahoraga_memory_file,
                        enable_learning=True,
                    )
                    logger.info(f"\u2638 Mahoraga Adaptive Fixer initialized")
                except Exception as e:
                    logger.warning(f"Failed to initialize Mahoraga Fixer: {e}")
                    logger.info("Falling back to standard AutoFixer...")

            # Try to use LLM-powered fixer first
            if not llm_fixer and use_llm_fixer and AUTOFIXER_AVAILABLE:
                try:
                    # Resolve API key based on model name
                    # Ollama-format names (with ':') go to RunPod, not DeepSeek API
                    if llm_model.startswith('deepseek-') and ':' not in llm_model:
                        api_key = os.environ.get('DEEPSEEK_API_KEY')
                    elif llm_model.startswith('codestral-') or llm_model.startswith('mistral-'):
                        api_key = os.environ.get('MISTRAL_API_KEY')
                    else:
                        api_key = os.environ.get('RUNPOD_API_KEY', 'ollama')
                    llm_fixer = AutoFixer(
                        llm_model=llm_model, 
                        api_key=api_key,
                        use_hybrid=use_hybrid_llm,
                        local_model=hybrid_local_model,
                        cloud_file_size_limit=hybrid_cloud_file_size_limit,
                        mode=hybrid_mode,
                        fix_history_path=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'fix_history_global.json'),
                        compiler_type=self.compiler_type,
                    )
                    if use_hybrid_llm:
                        logger.info(f"✓ HYBRID LLM-powered AutoFixer initialized")
                        logger.info(f"  Local: {hybrid_local_model}")
                        logger.info(f"  Cloud: {llm_model}")
                    else:
                        logger.info(f"✓ LLM-powered AutoFixer initialized ({llm_model})")
                except Exception as e:
                    logger.warning(f"Failed to initialize LLM AutoFixer: {e}")
                    logger.info("Falling back to pattern-based fixer...")
            
            # Fallback to simple pattern-based fixer
            if not llm_fixer and ProjectAutoFixer:
                auto_fixer = ProjectAutoFixer(max_attempts=max_fix_attempts)
                logger.info("Using pattern-based ProjectAutoFixer")
        
        compilation_attempt = 0
        max_compilation_attempts = max_fix_attempts + 1 if auto_fix else 1
        
        # Track error signatures for fix-loop detection
        error_signature_history = []
        
        try:
            import time
            import hashlib
            start_time = time.time()
            
            self._force_pattern_only_fix = False  # reset at start of compile_project
            self._pattern_only_attempted = False  # reset pattern-only-attempted flag
            _extra_attempt_granted = False  # track if we've already given an extra attempt
            while compilation_attempt < max_compilation_attempts or (
                getattr(self, '_force_pattern_only_fix', False) and not _extra_attempt_granted
            ):
                compilation_attempt += 1
                
                if compilation_attempt == 1:
                    logger.info(f"\n⏳ Compiling... (this may take a while)")
                else:
                    logger.info(f"\n🔄 Retry attempt {compilation_attempt - 1}/{max_fix_attempts}")
                    # ── Smart cloud cooldown reset between compilation attempts ──
                    # Only reset if enough time has passed since last rate limit
                    if llm_fixer and hasattr(llm_fixer, 'llm_provider'):
                        _prov = llm_fixer.llm_provider
                        if hasattr(_prov, '_cloud_cooldown_until'):
                            import time as _t
                            _time_since_cooldown = _t.time() - getattr(_prov, '_cloud_cooldown_until', 0)
                            if _time_since_cooldown > 120:  # only reset after 2+ min
                                _prov._cloud_consecutive_fails = 0
                                _prov._cloud_cooldown_until = 0.0
                                logger.info(f"   ☁️ Cloud cooldown reset (120s+ elapsed)")
                            else:
                                logger.info(f"   ☁️ Cloud still cooling down ({abs(int(_time_since_cooldown))}s since cooldown)")
                
                process = subprocess.run(
                    compile_cmd,
                    capture_output=True,
                    timeout=300,  # 5 minutes timeout
                    env=subprocess_env  # MSVC env or None for GCC
                )
                
                result.compile_time = time.time() - start_time
                
                # Decode output with encoding error handling
                try:
                    stdout_text = process.stdout.decode('utf-8', errors='replace') if process.stdout else ''
                except (AttributeError, UnicodeDecodeError):
                    stdout_text = str(process.stdout) if process.stdout else ''
                try:
                    stderr_text = process.stderr.decode('utf-8', errors='replace') if process.stderr else ''
                except (AttributeError, UnicodeDecodeError):
                    stderr_text = str(process.stderr) if process.stderr else ''
                
                result.output = stdout_text
                # MSVC outputs errors to stdout, GCC to stderr
                if self.compiler_type == 'msvc':
                    result.errors = stdout_text + '\n' + stderr_text
                else:
                    result.errors = stderr_text
                
                # Check if successful
                if process.returncode == 0 and os.path.exists(executable_path):
                    result.success = True
                    result.executable_path = executable_path
                    result.executable_size = os.path.getsize(executable_path)
                    
                    logger.info(f"\n✅ COMPILATION SUCCESSFUL!")
                    if compilation_attempt > 1:
                        logger.info(f"   ✨ Fixed after {compilation_attempt - 1} attempt(s)")
                    logger.info(f"   Executable: {executable_path}")
                    logger.info(f"   Size: {result.executable_size:,} bytes ({result.executable_size / 1024 / 1024:.2f} MB)")
                    logger.info(f"   Time: {result.compile_time:.2f}s")
                    
                    # Verify PE file
                    self._verify_pe_file(executable_path)
                    break
                    
                else:
                    logger.error(f"\n❌ COMPILATION FAILED (Attempt {compilation_attempt})")
                    logger.error(f"   Return code: {process.returncode}")
                    
                    if result.errors:
                        # Use enhanced error categorization if available
                        if ENHANCED_TOOLS_AVAILABLE and use_enhanced_categorization:
                            error_analysis = EnhancedErrorCategorizer.analyze_errors(result.errors.split('\n'))
                            
                            logger.error(f"\n📊 Error Analysis:")
                            logger.error(f"   Total errors: {error_analysis['total_errors']}")
                            logger.error(f"   Total warnings: {error_analysis['total_warnings']}")
                            
                            if error_analysis['category_counts']:
                                logger.error(f"   Categories:")
                                for cat, count in error_analysis['category_counts'].items():
                                    logger.error(f"     - {cat}: {count}")
                            
                            # Separate by compilation phase
                            phases = EnhancedErrorCategorizer.separate_by_phase(result.errors.split('\n'))
                            if phases['has_compile_errors']:
                                logger.error(f"   Compile-phase errors: {len(phases['compile_phase'])}")
                            if phases['has_link_errors']:
                                logger.error(f"   Link-phase errors: {len(phases['link_phase'])}")
                        
                        logger.error(f"\n📋 Compilation errors:")
                        # Show first 20 lines of errors
                        error_lines = result.errors.split('\n')[:20]
                        for line in error_lines:
                            if line.strip():
                                logger.error(f"   {line}")
                        if len(result.errors.split('\n')) > 20:
                            logger.error(f"   ... and {len(result.errors.split('\n')) - 20} more lines")
                    
                    # === FIX-LOOP DETECTION ===
                    # Track error signatures across attempts. If same errors appear 3+ times, stop.
                    # Handle both GCC ('error:') and MSVC ('error C') error formats
                    error_sig_lines = sorted([l.strip() for l in result.errors.split('\n') 
                                             if 'error:' in l or 'error C' in l or 'fatal error' in l])
                    current_sig = hashlib.md5('\n'.join(error_sig_lines[:20]).encode()).hexdigest()[:16]
                    error_signature_history.append(current_sig)
                    
                    # Check for loops (same signature appears 2+ times = 3+ total attempts)
                    # Exception: if we just entered pattern-only mode after rollback,
                    # the same signature is expected because rollback restored original code.
                    # Allow one pattern-only attempt before declaring a fix loop.
                    sig_count = error_signature_history.count(current_sig)
                    _in_pattern_only = getattr(self, '_force_pattern_only_fix', False)
                    _pattern_only_attempted = getattr(self, '_pattern_only_attempted', False)
                    if sig_count >= 2 and compilation_attempt > 2:
                        if _in_pattern_only and not _pattern_only_attempted:
                            logger.info(f"\n🔄 Same errors after rollback — allowing one pattern-only attempt")
                            self._pattern_only_attempted = True
                            _extra_attempt_granted = True  # allow loop to continue beyond max
                        else:
                            logger.warning(f"\n🔄 Fix loop detected! Same errors appeared {sig_count} times.")
                            logger.warning(f"   Error signature: {current_sig}")
                            logger.warning(f"   Stopping fix attempts to avoid wasting API calls.")
                            break
                    
                    # Try permissive compilation first if enabled
                    if permissive_mode and compilation_attempt == 1:
                        logger.info(f"\n🔄 Trying permissive compilation...")
                        permissive_cmd = compile_cmd.copy()
                        
                        if self.compiler_type == 'msvc':
                            # MSVC: try /permissive- (disable conformance), /Zc:twoPhase-
                            if '/permissive-' not in permissive_cmd:
                                # Insert before /link
                                link_idx = permissive_cmd.index('/link') if '/link' in permissive_cmd else len(permissive_cmd)
                                permissive_cmd.insert(link_idx, '/Zc:twoPhase-')
                        else:
                            # GCC: add -fpermissive
                            if '-fpermissive' not in permissive_cmd:
                                permissive_cmd.append('-fpermissive')
                        
                        permissive_process = subprocess.run(
                            permissive_cmd,
                            capture_output=True,
                            timeout=300,
                            env=subprocess_env
                        )
                        
                        if permissive_process.returncode == 0 and os.path.exists(executable_path):
                            result.success = True
                            result.executable_path = executable_path
                            result.executable_size = os.path.getsize(executable_path)
                            result.compile_time = time.time() - start_time
                            logger.info(f"\n✅ PERMISSIVE COMPILATION SUCCESSFUL!")
                            logger.info(f"   Executable: {executable_path}")
                            self._verify_pe_file(executable_path)
                            break
                    
                    # Try auto-fix if enabled and not last attempt
                    # Allow one extra attempt if pattern-only mode was just activated
                    _in_pattern_mode = getattr(self, '_force_pattern_only_fix', False)
                    _can_fix = compilation_attempt < max_compilation_attempts or _in_pattern_mode
                    if auto_fix and _can_fix:
                        logger.info(f"\n🔧 Attempting automatic fixes...")
                        
                        # Count errors for rollback detection
                        all_error_lines = result.errors.split('\n')
                        # Count ALL MSVC error types: compile (error Cxxxx), linker (error LNKxxxx), and fatal
                        import re as _re_err_count
                        current_error_count = sum(
                            1 for e in all_error_lines
                            if _re_err_count.search(r'error\s+(?:C|LNK)\d+', e)
                            or 'fatal error' in e.lower()
                        )
                        
                        # Check if errors increased since last fix - rollback if so
                        # Skip this check in pattern-only mode (post-rollback): we expect
                        # the same errors because the code was just restored to the pre-fix state.
                        _in_pattern_mode = getattr(self, '_force_pattern_only_fix', False)
                        if (not _in_pattern_mode
                            and hasattr(self, '_prev_error_count')
                            and current_error_count > self._prev_error_count * 1.2):
                            logger.warning(f"\n⚠️  Error count INCREASED after fix ({self._prev_error_count} → {current_error_count})")
                            logger.warning(f"   LLM fix introduced more problems! Rolling back...")
                            # Rollback from backup
                            if hasattr(self, '_file_backups') and self._file_backups:
                                for fpath, backup_content in self._file_backups.items():
                                    try:
                                        with open(fpath, 'w', encoding='utf-8') as f:
                                            f.write(backup_content)
                                        logger.info(f"   Restored: {os.path.basename(fpath)}")
                                    except Exception as e:
                                        logger.error(f"   Failed to restore {fpath}: {e}")

                            # Diagnose if this was a Windows SDK macro collision
                            sys_hdr_after = sum(1 for e in all_error_lines
                                if ('\\Windows Kits\\' in e or '\\MSVC\\' in e or '\\ucrt\\' in e or 'mingw64/include' in e or 'bits/' in e)
                                and ('error:' in e or 'error C' in e or 'fatal error' in e))
                            if sys_hdr_after > 5 and self._prev_error_count > 0:
                                logger.warning(f"   💥 MACRO COLLISION detected: LLM defined 'string', 'bool', or a VLA that broke Windows SDK headers ({sys_hdr_after} system header errors).")
                                logger.warning(f"   ➜ Retrying with generic pattern-fix only (no LLM for this file).")
                                # Reset error count and force pattern-only retry
                                self._prev_error_count = 0
                                self._force_pattern_only_fix = True  # flag for next attempt
                                _extra_attempt_granted = True  # allow one extra iteration for pattern-only
                                continue
                            else:
                                logger.warning(f"   ➜ LLM fix regressed ({self._prev_error_count} → {current_error_count} errors). Retrying with pattern-only fixes...")
                                self._prev_error_count = 0
                                self._force_pattern_only_fix = True
                                _extra_attempt_granted = True  # allow one extra iteration for pattern-only
                                continue
                        
                        self._prev_error_count = current_error_count
                        
                        # === DETECT SYSTEM HEADER CORRUPTION ===
                        if self.compiler_type == 'gcc':
                            system_header_errors = sum(1 for e in all_error_lines 
                                if ('mingw64/include' in e or 'msys64' in e or 'bits/' in e) 
                                and 'error:' in e)
                        else:
                            # MSVC: check for errors in MSVC/Windows SDK includes
                            system_header_errors = sum(1 for e in all_error_lines 
                                if ('\\MSVC\\' in e or '\\Windows Kits\\' in e or '\\ucrt\\' in e) 
                                and ('error C' in e or 'fatal error' in e))
                        total_errors = sum(1 for e in all_error_lines if ('error:' in e or 'error C' in e or 'fatal error' in e))
                        
                        if system_header_errors > 10 and total_errors > 0 and system_header_errors > total_errors * 0.5:
                            logger.warning(f"\n⚠️  System header corruption detected! ({system_header_errors}/{total_errors} errors in system headers)")
                            logger.warning(f"   This usually means a mutation broke fundamental type definitions.")
                            logger.warning(f"   LLM fix cannot help — skipping further fix attempts.")
                            break
                        
                        # === DETECT UNFIXABLE PROJECT ===
                        # With MSVC, most things are fixable (WDK/ATL available natively)
                        # Only truly unfixable if using GCC
                        if self.compiler_type == 'gcc':
                            _UNFIXABLE_PROJECT_PATTERNS = [
                                r'(?:fatal error|error):.*(?:ntddk|wdm|ndis|fltkernel|ntifs|wdf|ntstrsafe|fwpsk)(?:\.h)?.*No such file',
                                r'(?:fatal error|error):.*(?:atlbase|atlcom|atlwin|afx|afxwin)(?:\.h)?.*No such file',
                                r"unknown type name\s+'namespace'",
                                r"conflicting types for 'KAFFINITY'",
                            ]
                            import re as _re_check
                            _unfixable_count = 0
                            for _e in all_error_lines:
                                for _pat in _UNFIXABLE_PROJECT_PATTERNS:
                                    if _re_check.search(_pat, _e, _re_check.IGNORECASE):
                                        _unfixable_count += 1
                                        break
                            
                            if _unfixable_count > 0 and total_errors > 0 and _unfixable_count >= total_errors * 0.3:
                                logger.warning(f"\n⚠️  Project requires WDK/ATL/DirectX headers ({_unfixable_count}/{total_errors} unfixable errors)")
                                logger.warning(f"   These headers are not available in MinGW. Skipping fix attempts.")
                                break
                        
                        # Use LLM-powered fixer if available
                        if llm_fixer:
                            logger.info("   Using LLM-powered fixer...")
                            
                            # Backup all source files before fixing (for rollback)
                            self._file_backups = {}
                            for source_file in project.source_files:
                                try:
                                    with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                                        self._file_backups[source_file] = f.read()
                                except Exception as e:
                                    logger.debug(f"    Could not backup {source_file}: {e}")
                            
                            # Parse error messages and join MSVC continuation lines
                            raw_lines = [line.strip() for line in result.errors.split('\n') if line.strip()]
                            error_lines = []
                            for line in raw_lines:
                                # Check if this line is a continuation (no file path indicator)
                                # MSVC continuation lines start with just the identifier or message
                                # e.g., "'HCRYPTPROV'" after "error C2061: syntax error: identifier"
                                if error_lines and not re.match(r'^[a-zA-Z]:', line) and not re.match(r'^\w+[\\/]', line) and not re.match(r'^[\w.]+\(\d+\)', line):
                                    # This looks like a continuation line - append to previous
                                    error_lines[-1] = error_lines[-1] + ' ' + line
                                else:
                                    error_lines.append(line)
                            
                            # Prepare project-wide context string
                            project_context_str = None
                            if project_context and ENHANCED_TOOLS_AVAILABLE:
                                project_context_str = project_context.to_context_string(max_length=8000)
                            
                            # Fix each source file that has errors
                            files_fixed = 0
                            files_skipped_too_large = 0
                            _was_force_vla = getattr(self, '_force_pattern_only_fix', False)
                            
                            # Track previous errors per file for feedback to LLM
                            if not hasattr(self, '_prev_file_errors'):
                                self._prev_file_errors = {}
                            
                            # Include both source and header files for fixing
                            all_project_files = list(project.source_files) + list(getattr(project, 'header_files', []))
                            
                            for source_file in all_project_files:
                                # Find errors related to this file
                                # Use precise matching to avoid "core.cpp" matching "DllCore.cpp"
                                basename = os.path.basename(source_file)
                                stem = os.path.splitext(basename)[0]  # e.g. "common" from "common.c"

                                def _is_file_error(e: str, fname: str, full_path: str, fstem: str) -> bool:
                                    """Check if error e belongs to file fname (source or .obj linker error)."""
                                    # Full path match
                                    if full_path in e:
                                        return True
                                    import re as _re_fe
                                    # Source file match: fname( or fname: at word boundary
                                    pattern = r'(?:^|[\\/])' + _re_fe.escape(fname) + r'[:\(]'
                                    if _re_fe.search(pattern, e):
                                        return True
                                    # Linker error: stem.obj : error LNKxxxx  (MSVC)
                                    # e.g. "common.obj : error LNK2019:"
                                    lnk_pattern = r'(?:^|[\\/])' + _re_fe.escape(fstem) + r'\.obj\b'
                                    if _re_fe.search(lnk_pattern, e, _re_fe.IGNORECASE):
                                        return True
                                    return False

                                file_errors = [e for e in error_lines if _is_file_error(e, basename, source_file, stem)]
                                
                                if file_errors:
                                    # Skip files with extreme error counts — not fixable by LLM
                                    # But still allow pattern fixes: they handle C2065 cheaply at any scale
                                    c2065_count = sum(1 for e in file_errors if 'C2065' in e)
                                    _in_pattern_mode_file = getattr(self, '_force_pattern_only_fix', False)
                                    if len(file_errors) > 100 and not _in_pattern_mode_file and c2065_count < len(file_errors) * 0.5:
                                        logger.warning(f"   Skipping {os.path.basename(source_file)} ({len(file_errors)} errors — extreme)")
                                        continue
                                    
                                    logger.info(f"   Fixing {os.path.basename(source_file)}...")
                                    
                                    # If forced pattern-only fix mode (after macro collision rollback), skip LLM
                                    if getattr(self, '_force_pattern_only_fix', False):
                                        logger.info(f"      ⚡ Pattern-only mode (post-rollback): no LLM, using generic fixes")
                                    
                                    # Read current source code
                                    try:
                                        with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                                            source_code = f.read()
                                        
                                        # === MULTI-FILE CROSS-DEPENDENCY AUTO-FIX (BEFORE LLM) ===
                                        # Try to auto-inject forward declarations for cross-file dependencies
                                        cross_file_fixes = 0
                                        if multi_file_support:
                                            try:
                                                # Extract missing symbols from errors
                                                missing_symbols = multi_file_support.extract_missing_symbols_from_errors(file_errors)
                                                
                                                if missing_symbols:
                                                    # Resolve symbols from project index
                                                    resolved = multi_file_support.resolve_missing_symbols(missing_symbols)
                                                    
                                                    if resolved:
                                                        logger.info(f"      🔗 Found {len(resolved)} cross-file symbols: {', '.join(list(resolved.keys())[:5])}")
                                                        
                                                        # Generate and inject declarations
                                                        decl_block = multi_file_support.generate_forward_declarations(
                                                            set(resolved.keys()), source_file
                                                        )
                                                        
                                                        if decl_block and len(decl_block.strip()) > 100:
                                                            insert_pos = multi_file_support._find_insertion_point(source_code)
                                                            source_code = source_code[:insert_pos] + decl_block + source_code[insert_pos:]
                                                            cross_file_fixes = len(resolved)
                                                            logger.info(f"      ✓ Injected {cross_file_fixes} cross-file declarations")
                                            except Exception as e:
                                                logger.debug(f"      Cross-file auto-fix error: {e}")
                                        
                                        # Check file size before sending to LLM
                                        if len(source_code) > llm_fixer_max_code_length:
                                            logger.warning(f"      ⚠️  File too large ({len(source_code)} chars, max {llm_fixer_max_code_length})")
                                            logger.info(f"      🔪 Using surgical fix (error regions only)...")
                                            # Surgical fix is handled inside fix_compilation_errors
                                            # Just let it through — it will call fix_large_file_surgically internally
                                        
                                        # Get file-specific context (enhanced with multi-file info)
                                        file_context_str = None
                                        if project_context and ENHANCED_TOOLS_AVAILABLE:
                                            file_context_str = ProjectContextCollector.get_file_context(
                                                source_file, project_context, max_length=3000
                                            )
                                        
                                        # Add multi-file context for LLM
                                        multi_file_context = None
                                        if multi_file_support:
                                            try:
                                                multi_file_context = multi_file_support.get_context_for_file(
                                                    source_file, file_errors, max_length=4000
                                                )
                                            except Exception as e:
                                                logger.debug(f"      Multi-file context error: {e}")
                                        
                                        # Combine contexts
                                        if multi_file_context:
                                            if file_context_str:
                                                file_context_str = file_context_str + "\n\n" + multi_file_context
                                            else:
                                                file_context_str = multi_file_context
                                        
                                        # Add Clang AST context for this file
                                        if clang_analysis and CLANG_ANALYZER_AVAILABLE:
                                            try:
                                                clang_fix_ctx = clang_analysis.get_compilation_fix_context(
                                                    source_file, max_length=4000
                                                )
                                                if clang_fix_ctx:
                                                    if file_context_str:
                                                        file_context_str = file_context_str + "\n\n" + clang_fix_ctx
                                                    else:
                                                        file_context_str = clang_fix_ctx
                                            except Exception as e:
                                                logger.debug(f"      Clang fix context error: {e}")
                                        
                                        # === PRE-LLM GENERIC PATTERN-BASED FIXES ===
                                        # Apply comprehensive pattern fixes before LLM:
                                        # 1. VLA (C2065+C2057) → #define constants
                                        # 2. Undeclared local vars (C2065 alone) → add declaration
                                        # 3. Missing includes for known Win32 types
                                        import re as _re_vla
                                        pattern_fixed_code, pattern_fix_count, lnk_libs = AutoFixer.apply_generic_pattern_fixes(
                                            source_code, file_errors, language, file_path=source_file
                                        )
                                        if pattern_fix_count > 0:
                                            source_code = pattern_fixed_code
                                            logger.info(f"      ✓ Generic pattern fixes applied: {pattern_fix_count} fix(es)")
                                        # Add missing libraries detected from LNK errors
                                        if lnk_libs:
                                            new_libs = lnk_libs - set(self.libraries)
                                            if new_libs:
                                                self.libraries.extend(sorted(new_libs))
                                                logger.info(f"      ✓ Added linker libraries: {', '.join(sorted(new_libs))}")

                                        # Legacy VLA detection (for the skip-LLM logic below)
                                        # Note: VLA defines may already be added by apply_generic_pattern_fixes above.
                                        # We just re-check here for the skip-LLM decision.
                                        vla_fixed = 0
                                        vla_defines_to_add = []
                                        for _err in file_errors:
                                            _m = _re_vla.search(r"C2065.*'([^']+)'.*undeclared", _err)
                                            if _m:
                                                _ident = _m.group(1)
                                                # Confirm it's used as array size (C2057 + C2466/C2133)
                                                _is_array_size = any(
                                                    _ident in _e and ('C2057' in _e or 'C2466' in _e or 'C2133' in _e)
                                                    for _e in file_errors
                                                )
                                                if _is_array_size and _ident not in vla_defines_to_add:
                                                    vla_defines_to_add.append(_ident)
                                        # Count VLA fixes that were included in the pattern fix above
                                        vla_fixed = len(vla_defines_to_add) if vla_defines_to_add else 0

                                        # If ALL errors were fixed by pattern fixes, skip LLM
                                        if pattern_fix_count > 0:
                                            # Check if remaining errors are all covered
                                            # (all C2065 idents were fixed by pattern fix)
                                            _non_pattern_errors = []
                                            for _e in file_errors:
                                                _m2 = _re_vla.search(r"C2065.*'([^']+)'", _e)
                                                if _m2:
                                                    continue  # C2065 handled by pattern fix
                                                if any(code in _e for code in ('C2057', 'C2466', 'C2133')):
                                                    continue  # VLA-related
                                                _non_pattern_errors.append(_e)
                                            if len(_non_pattern_errors) <= 2:
                                                logger.info(f"      ✓ Pattern-only errors: writing fix directly (no LLM needed)")
                                                with open(source_file, 'w', encoding='utf-8') as f:
                                                    f.write(source_code)
                                                files_fixed += 1
                                                fix_history.append({
                                                    'attempt': compilation_attempt,
                                                    'file': os.path.basename(source_file),
                                                    'errors_count': len(file_errors),
                                                    'file_size': len(source_code),
                                                    'success': True,
                                                    'method': 'generic_pattern_fix'
                                                })
                                                continue

                                        # In force-pattern-only mode: apply generic fixes, skip LLM
                                        if getattr(self, '_force_pattern_only_fix', False):
                                            if pattern_fix_count > 0 or vla_fixed > 0:
                                                total_pfix = pattern_fix_count + vla_fixed
                                                logger.info(f"      ✓ Pattern-only mode: {total_pfix} fix(es) applied, writing without LLM")
                                                with open(source_file, 'w', encoding='utf-8') as f:
                                                    f.write(source_code)
                                                files_fixed += 1
                                                fix_history.append({
                                                    'attempt': compilation_attempt,
                                                    'file': os.path.basename(source_file),
                                                    'errors_count': len(file_errors),
                                                    'file_size': len(source_code),
                                                    'success': True,
                                                    'method': 'generic_pattern_fix'
                                                })
                                            else:
                                                logger.warning(f"      ⚠️  No pattern fix applicable in pattern-only mode, skipping LLM")
                                            continue

                                        # Use LLM to fix with enhanced context
                                        _prev_errs = self._prev_file_errors.get(source_file)
                                        fixed_code, fix_success, remaining_errors = llm_fixer.fix_compilation_errors(
                                            source_code,
                                            file_errors,
                                            language=language,
                                            max_attempts=2,
                                            max_code_length=llm_fixer_max_code_length,
                                            project_context=project_context_str,
                                            file_context=file_context_str,
                                            clang_analysis=clang_analysis,
                                            source_file_path=source_file,
                                            previous_fix_errors=_prev_errs,
                                        )
                                        # Store current errors for next attempt feedback
                                        self._prev_file_errors[source_file] = file_errors
                                        
                                        if fix_success and fixed_code and fixed_code != source_code:
                                            # === FILE-LEVEL VALIDATION GATE ===
                                            # Prevent catastrophic file destruction before writing to disk
                                            _orig_len = len(source_code)
                                            _fix_len = len(fixed_code)
                                            _orig_lines = len(source_code.splitlines())
                                            _fix_lines = len(fixed_code.splitlines())
                                            _write_ok = True
                                            
                                            # Check size ratio (reject if < 30% or > 500% of original)
                                            if _orig_len > 500:
                                                _size_ratio = _fix_len / _orig_len
                                                if _size_ratio < 0.30:
                                                    logger.warning(
                                                        f"      ❌ VALIDATION GATE: Fix shrunk file to {_size_ratio:.0%} "
                                                        f"({_fix_len} vs {_orig_len} chars). Rejecting to prevent file destruction."
                                                    )
                                                    _write_ok = False
                                                elif _size_ratio > 5.0:
                                                    logger.warning(
                                                        f"      ❌ VALIDATION GATE: Fix bloated file to {_size_ratio:.0%}. Rejecting."
                                                    )
                                                    _write_ok = False
                                            
                                            # Check line count ratio
                                            if _write_ok and _orig_lines > 20:
                                                _line_ratio = _fix_lines / _orig_lines
                                                if _line_ratio < 0.30:
                                                    logger.warning(
                                                        f"      ❌ VALIDATION GATE: Fix dropped to {_fix_lines} lines "
                                                        f"(was {_orig_lines}). Rejecting."
                                                    )
                                                    _write_ok = False
                                            
                                            if _write_ok:
                                                # Write fixed code back
                                                with open(source_file, 'w', encoding='utf-8') as f:
                                                    f.write(fixed_code)
                                                
                                                files_fixed += 1
                                                logger.info(f"      ✓ Fixed!")
                                                
                                                fix_history.append({
                                                    'attempt': compilation_attempt,
                                                    'file': os.path.basename(source_file),
                                                    'errors_count': len(file_errors),
                                                    'file_size': len(source_code),
                                                    'success': True
                                                })
                                            else:
                                                logger.warning(f"      ⚠️  Fix rejected by validation gate, keeping original")
                                                fix_history.append({
                                                    'attempt': compilation_attempt,
                                                    'file': os.path.basename(source_file),
                                                    'errors_count': len(file_errors),
                                                    'file_size': len(source_code),
                                                    'success': False,
                                                    'method': 'rejected_by_validation_gate'
                                                })
                                        else:
                                            logger.warning(f"      ⚠️  Could not fix")
                                            fix_history.append({
                                                'attempt': compilation_attempt,
                                                'file': os.path.basename(source_file),
                                                'errors_count': len(file_errors),
                                                'file_size': len(source_code),
                                                'success': False
                                            })
                                    
                                    except Exception as e:
                                        logger.error(f"      ❌ Error: {e}")
                            
                            if files_fixed > 0:
                                # Clear VLA-only flag after it's been used for one retry pass
                                if _was_force_vla:
                                    self._force_pattern_only_fix = False
                                    logger.info(f"   ✓ Pattern-only retry complete, resuming normal mode")
                                logger.info(f"   ✓ Fixed {files_fixed} file(s), retrying compilation...")
                            elif files_skipped_too_large > 0:
                                logger.warning(f"   ⚠️  {files_skipped_too_large} file(s) too large for LLM fix")
                                logger.info(f"   💡 Trying pattern-based fixer as fallback...")
                                # Try pattern-based fixer for large files
                                if auto_fixer:
                                    fixed, num_fixes = auto_fixer.fix_compilation_errors(
                                        project,
                                        result.errors,
                                        attempt=compilation_attempt
                                    )
                                    if fixed:
                                        logger.info(f"   ✓ Pattern-based fixer applied {num_fixes} fix(es)")
                                    else:
                                        logger.warning(f"   ⚠️  No fixes applied, stopping")
                                        break
                                else:
                                    logger.warning(f"   ⚠️  No fixes applied, stopping")
                                    break
                            else:
                                logger.warning(f"   ⚠️  No fixes applied, stopping")
                                break
                        
                        # Fallback to pattern-based fixer
                        elif auto_fixer:
                            logger.info("   Using pattern-based fixer...")
                            fixed, num_fixes = auto_fixer.fix_compilation_errors(
                                project,
                                result.errors,
                                attempt=compilation_attempt
                            )
                            
                            if fixed:
                                logger.info(f"   ✓ Applied {num_fixes} fix(es), retrying compilation...")
                            else:
                                logger.warning(f"   ⚠️  No fixes applied, stopping")
                                break
                        else:
                            logger.warning("   ⚠️  No fixer available")
                            break
                    else:
                        # No auto-fix or last attempt
                        break
        
        except subprocess.TimeoutExpired:
            logger.error(f"\n❌ Compilation timeout (5 minutes)")
            result.errors = "Compilation timeout"
            
        except Exception as e:
            logger.error(f"\n❌ Compilation exception: {e}")
            result.errors = str(e)
        
        # Add auto-fix summary to result
        if llm_fixer and fix_history:
            result.output += f"\n\n=== LLM AUTO-FIX SUMMARY ===\n"
            result.output += f"Total fix attempts: {len(fix_history)}\n"
            successful_fixes = sum(1 for h in fix_history if h['success'])
            result.output += f"Successful fixes: {successful_fixes}/{len(fix_history)}\n"
            
            if successful_fixes > 0:
                logger.info(f"\n📊 LLM Auto-Fix Summary:")
                logger.info(f"   Total attempts: {len(fix_history)}")
                logger.info(f"   Successful fixes: {successful_fixes}")
                logger.info(f"   Files fixed: {len(set(h['file'] for h in fix_history if h['success']))}")
            
            # Print Mahoraga session report if applicable
            if hasattr(llm_fixer, 'print_session_report'):
                llm_fixer.print_session_report()
            # Save Mahoraga memory if applicable
            if hasattr(llm_fixer, 'save_memory'):
                llm_fixer.save_memory()
            # Print fix path tracking summary
            if hasattr(llm_fixer, 'print_fix_tracking_summary'):
                llm_fixer.print_fix_tracking_summary()
        
        elif auto_fixer:
            fix_summary = auto_fixer.get_fix_summary()
            result.output += f"\n\n=== AUTO-FIX SUMMARY ===\n"
            result.output += f"Total attempts: {fix_summary['total_attempts']}\n"
            result.output += f"Total fixes: {fix_summary['total_fixes']}\n"
            
            if fix_summary['total_fixes'] > 0:
                logger.info(f"\n📊 Auto-Fix Summary:")
                logger.info(f"   Attempts: {fix_summary['total_attempts']}")
                logger.info(f"   Fixes applied: {fix_summary['total_fixes']}")
        
        # Save result
        result_file = os.path.join(output_dir, 'compilation_result.json')
        result_dict = result.to_dict()
        
        if llm_fixer and fix_history:
            result_dict['auto_fix_summary'] = {
                'type': 'mahoraga_adaptive' if hasattr(llm_fixer, 'get_session_stats') else 'llm_powered',
                'model': llm_model,
                'total_attempts': len(fix_history),
                'successful_fixes': sum(1 for h in fix_history if h['success']),
                'fix_history': fix_history
            }
            if hasattr(llm_fixer, 'get_session_stats'):
                result_dict['auto_fix_summary']['mahoraga_stats'] = llm_fixer.get_session_stats()
            if hasattr(llm_fixer, 'fix_tracking'):
                result_dict['auto_fix_summary']['fix_path_tracking'] = llm_fixer.fix_tracking
        elif auto_fixer:
            result_dict['auto_fix_summary'] = auto_fixer.get_fix_summary()
            result_dict['auto_fix_summary']['type'] = 'pattern_based'
        
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(result_dict, f, indent=2)
        
        # ── Evidence: log SHA-256 of the compiled PE so it can be verified later
        if result.success and result.executable_path and os.path.exists(result.executable_path):
            try:
                import hashlib as _hl
                _h = _hl.sha256()
                with open(result.executable_path, "rb") as _f:
                    for _chunk in iter(lambda: _f.read(65536), b""):
                        _h.update(_chunk)
                exe_sha256 = _h.hexdigest()
                exe_size = os.path.getsize(result.executable_path)
                logger.info(f"   📦 PE evidence: {os.path.basename(result.executable_path)} "
                            f"sha256={exe_sha256} size={exe_size}")
                # Persist hash alongside compile result for audit trail
                evidence_file = os.path.join(output_dir, "pe_evidence.json")
                evidence = {
                    "executable": os.path.basename(result.executable_path),
                    "sha256": exe_sha256,
                    "size_bytes": exe_size,
                    "compiled_at": None,
                    "project": project.name,
                }
                try:
                    from datetime import datetime as _dt
                    evidence["compiled_at"] = _dt.now().isoformat()
                except Exception:
                    pass
                with open(evidence_file, "w", encoding="utf-8") as _f:
                    json.dump(evidence, _f, indent=2)
            except Exception as _ev_err:
                logger.warning(f"   ⚠️  Could not compute PE evidence (file may have been quarantined): {_ev_err}")

        # ── Secure cleanup: wipe build intermediates ──────────────────────
        self.cleanup_build_intermediates(output_dir, keep_exe=True)

        return result
    
    # ──────────────────────────────────────────────────────────────────────
    # Python compilation via PyInstaller
    # ──────────────────────────────────────────────────────────────────────

    def _compile_python_project(
        self,
        project,
        output_dir: str,
        output_name: str = None,
    ) -> CompilationResult:
        """
        Package Python project into standalone executable using PyInstaller.

        Args:
            project: MalwareProject with .py source files
            output_dir: Output directory
            output_name: Output executable name

        Returns:
            CompilationResult
        """
        import time as _time
        result = CompilationResult()

        if not project.source_files:
            result.errors = "No Python source files"
            return result

        os.makedirs(output_dir, exist_ok=True)

        if not output_name:
            output_name = f"{project.name}_mutated"
        output_name = output_name.replace('.exe', '')

        # Find main entry point
        entry_file = self._find_python_entry_point(project)
        if not entry_file:
            result.errors = "Cannot determine Python entry point (no __main__ or main())"
            return result

        logger.info(f"\n{'='*60}")
        logger.info(f"🐍 PACKAGING PYTHON PROJECT: {project.name}")
        logger.info(f"{'='*60}")
        logger.info(f"Entry point: {entry_file}")
        logger.info(f"Source files: {len(project.source_files)}")
        logger.info(f"Output: {output_dir}/{output_name}.exe")

        # Pre-compilation: obfuscate all string/int literals in source files
        # This handles module-level constants (DB_PATH, SQL queries, URLs, etc.)
        # that the LLM mutation step never touches.
        try:
            import importlib.util as _ilu, sys as _sys
            _obf_path = os.path.join(os.path.dirname(__file__), 'python_source_obfuscator.py')
            _spec = _ilu.spec_from_file_location('python_source_obfuscator', _obf_path)
            _obf_mod = _ilu.module_from_spec(_spec)
            _spec.loader.exec_module(_obf_mod)
            _obf_stats = _obf_mod.obfuscate_project_dir(project.root_dir)
            logger.info(f"   🔐 Source obfuscation: {_obf_stats['files_modified']} files modified, "
                        f"{_obf_stats['files_failed']} failed")
        except Exception as _obf_err:
            logger.warning(f"   ⚠ Source obfuscation step failed (non-fatal): {_obf_err}")

        # Syntax check first
        for sf in project.source_files:
            try:
                with open(sf, 'r', encoding='utf-8', errors='ignore') as f:
                    compile(f.read(), sf, 'exec')
            except SyntaxError as e:
                result.errors = f"Syntax error in {sf}: {e}"
                logger.error(f"   ✗ {result.errors}")
                return result

        # Build PyInstaller command
        executable_path = os.path.join(output_dir, f"{output_name}.exe")
        dist_dir = os.path.join(output_dir, "dist")
        build_dir = os.path.join(output_dir, "build_pyinstaller")

        cmd = [
            sys.executable, '-m', 'PyInstaller',
            '--onefile',
            '--noconfirm',
            '--clean',
            '--distpath', dist_dir,
            '--workpath', build_dir,
            '--specpath', output_dir,
            '--name', output_name,
            '--log-level', 'WARN',
        ]

        # Add hidden imports for common malware modules
        hidden_imports = [
            'socket', 'ssl', 'ctypes', 'subprocess', 'winreg',
            'http.client', 'urllib.request', 'base64', 'hashlib',
            'threading', 'multiprocessing', 'struct', 'json',
        ]
        for hi in hidden_imports:
            cmd.extend(['--hidden-import', hi])

        # Add additional data/source files
        for sf in project.source_files:
            if sf != entry_file:
                rel = os.path.relpath(sf, project.root_dir)
                dest_dir = os.path.dirname(rel) or '.'
                cmd.extend(['--add-data', f'{sf}{os.pathsep}{dest_dir}'])

        cmd.append(entry_file)

        logger.info(f"   Command: {' '.join(cmd[:6])} ...")

        t0 = _time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=project.root_dir,
            )

            result.compile_time = _time.time() - t0
            result.output = proc.stdout
            result.errors = proc.stderr

            # PyInstaller puts output in dist/
            expected_exe = os.path.join(dist_dir, f"{output_name}.exe")
            if proc.returncode == 0 and os.path.exists(expected_exe):
                # Move to final location
                shutil.move(expected_exe, executable_path)
                result.success = True
                result.executable_path = executable_path
                result.executable_size = os.path.getsize(executable_path)
                logger.info(f"   ✓ Python executable created: {executable_path} "
                            f"({result.executable_size:,} bytes)")
            else:
                result.errors = (proc.stderr or proc.stdout or "PyInstaller failed")[:2000]
                logger.error(f"   ✗ PyInstaller failed (rc={proc.returncode})")

        except FileNotFoundError:
            result.errors = "PyInstaller not installed. Run: pip install pyinstaller"
            logger.error(f"   ✗ {result.errors}")
        except subprocess.TimeoutExpired:
            result.errors = "PyInstaller timed out (300s)"
            logger.error(f"   ✗ {result.errors}")
        except Exception as e:
            result.errors = f"PyInstaller exception: {e}"
            logger.error(f"   ✗ {result.errors}")

        return result

    @staticmethod
    def _find_python_entry_point(project) -> Optional[str]:
        """Find the main entry point for a Python project."""
        candidates = []
        for sf in project.source_files:
            if not sf.lower().endswith('.py'):
                continue
            basename = os.path.basename(sf).lower()
            # Highest priority: __main__.py
            if basename == '__main__.py':
                return sf
            try:
                with open(sf, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                # Check for if __name__ == "__main__" or main() call
                if re.search(r'if\s+__name__\s*==\s*["\']__main__["\']', content):
                    candidates.append((2, sf))
                elif basename in ('main.py', 'app.py', 'run.py', 'start.py'):
                    candidates.append((1, sf))
            except OSError:
                continue

        if candidates:
            candidates.sort(key=lambda x: -x[0])
            return candidates[0][1]
        # Fallback: first .py file
        for sf in project.source_files:
            if sf.lower().endswith('.py'):
                return sf
        return None

    # ──────────────────────────────────────────────────────────────────────
    # JavaScript compilation via pkg (Node.js → EXE)
    # ──────────────────────────────────────────────────────────────────────

    def _compile_javascript_project(
        self,
        project,
        output_dir: str,
        output_name: str = None,
    ) -> CompilationResult:
        """
        Package JavaScript/Node.js project into standalone executable using pkg.

        Falls back to nexe if pkg is not available.

        Args:
            project: MalwareProject with .js source files
            output_dir: Output directory
            output_name: Output executable name

        Returns:
            CompilationResult
        """
        import time as _time
        result = CompilationResult()

        if not project.source_files:
            result.errors = "No JavaScript source files"
            return result

        os.makedirs(output_dir, exist_ok=True)

        if not output_name:
            output_name = f"{project.name}_mutated"
        output_name = output_name.replace('.exe', '')

        entry_file = self._find_javascript_entry_point(project)
        if not entry_file:
            result.errors = "Cannot determine JavaScript entry point"
            return result

        logger.info(f"\n{'='*60}")
        logger.info(f"📦 PACKAGING JAVASCRIPT PROJECT: {project.name}")
        logger.info(f"{'='*60}")
        logger.info(f"Entry point: {entry_file}")
        logger.info(f"Source files: {len(project.source_files)}")

        executable_path = os.path.join(output_dir, f"{output_name}.exe")

        # Try pkg first, then nexe
        packagers = [
            self._try_pkg_compile,
            self._try_nexe_compile,
        ]

        t0 = _time.time()
        for packager in packagers:
            pack_result = packager(project, entry_file, executable_path, output_dir)
            if pack_result.success:
                pack_result.compile_time = _time.time() - t0
                logger.info(f"   ✓ JS executable created: {executable_path} "
                            f"({pack_result.executable_size:,} bytes)")
                return pack_result

        # All packagers failed
        result.compile_time = _time.time() - t0
        result.errors = ("JavaScript packaging failed. Install one of:\n"
                         "  npm install -g pkg\n"
                         "  npm install -g nexe")
        logger.error(f"   ✗ {result.errors}")
        return result

    def _try_pkg_compile(
        self, project, entry_file: str, executable_path: str, output_dir: str
    ) -> CompilationResult:
        """Try packaging with pkg."""
        result = CompilationResult()

        # Check if pkg is available
        pkg_cmd = shutil.which('pkg')
        node_cmd = shutil.which('node')
        if not pkg_cmd:
            # Try via npx
            npx_cmd = shutil.which('npx')
            if npx_cmd:
                pkg_cmd = npx_cmd
                cmd = [pkg_cmd, 'pkg', entry_file, '--target', 'node18-win-x64',
                       '--output', executable_path]
            else:
                result.errors = "pkg not found"
                return result
        else:
            # On Windows, .CMD wrappers fail under subprocess; call node directly
            pkg_js = os.path.join(os.path.dirname(pkg_cmd), 'node_modules', 'pkg', 'lib-es5', 'bin.js')
            if node_cmd and os.path.isfile(pkg_js):
                cmd = [node_cmd, pkg_js, entry_file, '--target', 'node18-win-x64',
                       '--output', executable_path]
            else:
                cmd = [pkg_cmd, entry_file, '--target', 'node18-win-x64',
                       '--output', executable_path]

        logger.info(f"   Trying pkg: {' '.join(str(c) for c in cmd[:4])} ...")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=project.root_dir,
            )
            result.output = proc.stdout
            result.errors = proc.stderr

            if proc.returncode == 0 and os.path.exists(executable_path):
                result.success = True
                result.executable_path = executable_path
                result.executable_size = os.path.getsize(executable_path)
            else:
                result.errors = (proc.stderr or proc.stdout or "pkg failed")[:2000]
        except FileNotFoundError:
            result.errors = "pkg command not found"
        except subprocess.TimeoutExpired:
            result.errors = "pkg timed out (300s)"
        except Exception as e:
            result.errors = f"pkg exception: {e}"

        return result

    def _try_nexe_compile(
        self, project, entry_file: str, executable_path: str, output_dir: str
    ) -> CompilationResult:
        """Try packaging with nexe."""
        result = CompilationResult()

        nexe_cmd = shutil.which('nexe')
        node_cmd = shutil.which('node')
        if not nexe_cmd:
            npx_cmd = shutil.which('npx')
            if npx_cmd:
                cmd = [npx_cmd, 'nexe', entry_file, '--output', executable_path,
                       '--target', 'windows-x64-14.15.3']
            else:
                result.errors = "nexe not found"
                return result
        else:
            # On Windows, .CMD wrappers fail under subprocess; call node directly
            nexe_js = os.path.join(os.path.dirname(nexe_cmd), 'node_modules', 'nexe', 'index.js')
            if node_cmd and os.path.isfile(nexe_js):
                cmd = [node_cmd, nexe_js, entry_file, '--output', executable_path,
                       '--target', 'windows-x64-14.15.3']
            else:
                cmd = [nexe_cmd, entry_file, '--output', executable_path,
                       '--target', 'windows-x64-14.15.3']

        logger.info(f"   Trying nexe: {' '.join(cmd[:4])} ...")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                cwd=project.root_dir,
            )
            result.output = proc.stdout
            result.errors = proc.stderr

            if proc.returncode == 0 and os.path.exists(executable_path):
                result.success = True
                result.executable_path = executable_path
                result.executable_size = os.path.getsize(executable_path)
            else:
                result.errors = (proc.stderr or proc.stdout or "nexe failed")[:2000]
        except FileNotFoundError:
            result.errors = "nexe command not found"
        except subprocess.TimeoutExpired:
            result.errors = "nexe timed out (600s)"
        except Exception as e:
            result.errors = f"nexe exception: {e}"

        return result

    @staticmethod
    def _find_javascript_entry_point(project) -> Optional[str]:
        """Find the main entry point for a JavaScript project."""
        # Check package.json first
        pkg_json = os.path.join(project.root_dir, 'package.json')
        if os.path.exists(pkg_json):
            try:
                with open(pkg_json, 'r', encoding='utf-8') as f:
                    pkg = json.load(f)
                main = pkg.get('main') or pkg.get('bin')
                if isinstance(main, str):
                    entry = os.path.join(project.root_dir, main)
                    if os.path.exists(entry):
                        return entry
                elif isinstance(main, dict):
                    for v in main.values():
                        entry = os.path.join(project.root_dir, v)
                        if os.path.exists(entry):
                            return entry
            except (json.JSONDecodeError, OSError):
                pass

        # Priority names
        priority_names = {'index.js', 'main.js', 'app.js', 'server.js', 'start.js'}
        for sf in project.source_files:
            if os.path.basename(sf).lower() in priority_names:
                return sf

        # Fallback: first .js file
        for sf in project.source_files:
            if sf.lower().endswith(('.js', '.mjs')):
                return sf
        return None

    def _verify_pe_file(self, executable_path: str):
        """Verify if file is valid PE executable"""
        try:
            with open(executable_path, 'rb') as f:
                # Check for MZ header
                header = f.read(2)
                if header == b'MZ':
                    logger.info(f"   ✓ Valid PE file (MZ header detected)")
                    
                    # Read PE header offset
                    f.seek(0x3C)
                    pe_offset = int.from_bytes(f.read(4), 'little')
                    
                    # Read PE signature
                    f.seek(pe_offset)
                    pe_sig = f.read(4)
                    if pe_sig == b'PE\x00\x00':
                        logger.info(f"   ✓ Valid PE signature")
                        
                        # Read machine type
                        machine = int.from_bytes(f.read(2), 'little')
                        if machine == 0x8664:
                            logger.info(f"   ✓ Architecture: x64 (AMD64)")
                        elif machine == 0x014c:
                            logger.info(f"   ✓ Architecture: x86 (i386)")
                        else:
                            logger.info(f"   ✓ Architecture: Unknown (0x{machine:04x})")
                else:
                    logger.warning(f"   ⚠️  Not a valid PE file (no MZ header)")
        except Exception as e:
            logger.warning(f"   ⚠️  Could not verify PE file: {e}")
    
    def compile_to_objects(
        self,
        project,
        output_dir: str
    ) -> CompilationResult:
        """
        Compile source files to object files (no linking)
        
        Args:
            project: MalwareProject object
            output_dir: Output directory for object files
            
        Returns:
            CompilationResult object
        """
        result = CompilationResult()
        
        os.makedirs(output_dir, exist_ok=True)
        
        language = project.get_language()
        compiler_cmd = self.compiler['cpp'] if language == 'cpp' else self.compiler['c']
        
        if not compiler_cmd:
            result.errors = f"No {language} compiler found"
            return result
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🔨 COMPILING TO OBJECTS: {project.name}")
        logger.info(f"{'='*60}")
        
        # Compile each source file to object file
        for source_file in project.source_files:
            source_name = os.path.splitext(os.path.basename(source_file))[0]
            
            logger.info(f"\n   Compiling: {os.path.basename(source_file)}")
            
            if self.compiler_type == 'msvc':
                object_file = os.path.join(output_dir, f"{source_name}.obj")
                cmd = [
                    compiler_cmd,
                    '/nologo', '/c',  # Compile only
                    source_file,
                    f'/Fo:{object_file}',
                    '/w',  # Suppress warnings
                ]
                for inc_dir in self.include_dirs:
                    cmd.append(f'/I{inc_dir}')
                run_env = getattr(self, '_project_msvc_env', self.msvc_env)
            else:
                object_file = os.path.join(output_dir, f"{source_name}.o")
                cmd = [
                    compiler_cmd,
                    '-c',  # Compile only
                    source_file,
                    '-o', object_file,
                ]
                for inc_dir in self.include_dirs:
                    cmd.extend(['-I', inc_dir])
                cmd.extend(['-w', '-fpermissive'])
                run_env = None
            
            try:
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    env=run_env
                )
                
                if process.returncode == 0 and os.path.exists(object_file):
                    result.object_files.append(object_file)
                    size = os.path.getsize(object_file)
                    logger.info(f"   ✓ Created: {os.path.basename(object_file)} ({size:,} bytes)")
                else:
                    logger.error(f"   ✗ Failed: {process.stderr[:200]}")
                    result.errors += f"\n{source_file}: {process.stderr}"
                    
            except Exception as e:
                logger.error(f"   ✗ Exception: {e}")
                result.errors += f"\n{source_file}: {e}"
        
        # Check success
        if len(result.object_files) == len(project.source_files):
            result.success = True
            logger.info(f"\n✅ All {len(result.object_files)} files compiled successfully!")
        else:
            logger.warning(f"\n⚠️  Compiled {len(result.object_files)}/{len(project.source_files)} files")
        
        return result


def main():
    """Test project compilation"""
    import sys
    from project_detector import ProjectDetector
    
    if len(sys.argv) < 2:
        print("Usage: python project_compiler.py <project_directory>")
        sys.exit(1)
    
    base_dir = sys.argv[1]
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s'
    )
    
    # Detect projects
    logger.info("Step 1: Detecting projects...")
    detector = ProjectDetector(base_dir)
    projects = detector.detect_projects()
    
    if not projects:
        logger.error("No projects found!")
        sys.exit(1)
    
    # Compile first project
    project = projects[0]
    logger.info(f"\nStep 2: Compiling project: {project.name}")
    
    compiler = ProjectCompiler()
    output_dir = f"compiled_{project.name}"
    
    result = compiler.compile_project(
        project,
        output_dir=output_dir,
    )
    
    if result.success:
        logger.info(f"\n🎉 SUCCESS! Executable: {result.executable_path}")
    else:
        logger.error(f"\n💥 FAILED!")
        sys.exit(1)


if __name__ == "__main__":
    main()

