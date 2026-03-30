"""
Compiler Compatibility Handler
==============================
Handles compiler-specific code (MSVC vs GCC).
Automatically wraps or converts incompatible features.
"""
import re
import logging
from typing import Tuple

logger = logging.getLogger(__name__)


class CompilerCompatibility:
    """Handle compiler-specific compatibility issues"""
    
    # Windows internal types that MinGW doesn't define but malware often uses
    MINGW_COMPAT_HEADER = r'''
/* ====== MinGW Compatibility Definitions ====== */
#ifdef __GNUC__

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef PROCESSINFOCLASS
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;
#endif

#ifndef SYSTEM_INFORMATION_CLASS
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemModuleInformation = 11,
    SystemKernelDebuggerInformation = 35
} SYSTEM_INFORMATION_CLASS;
#endif

#ifndef THREADINFOCLASS
typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0,
    ThreadHideFromDebugger = 17
} THREADINFOCLASS;
#endif

#ifndef OBJECT_ATTRIBUTES
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#endif

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}
#endif

/* GlobalAlloc/GlobalFree compatibility */
#ifndef GMEM_FIXED
#define GMEM_FIXED 0x0000
#endif
#ifndef GMEM_ZEROINIT
#define GMEM_ZEROINIT 0x0040
#endif
#ifndef GPTR
#define GPTR (GMEM_FIXED | GMEM_ZEROINIT)
#endif

#endif /* __GNUC__ */
/* ====== End MinGW Compatibility ====== */
'''
    
    @classmethod
    def make_gcc_compatible(cls, code: str, language: str = "c") -> Tuple[str, int]:
        """
        Make code compatible with GCC (MinGW).
        
        Args:
            code: Source code
            language: Programming language
            
        Returns:
            Tuple of (modified_code, num_changes)
        """
        original_code = code
        changes = 0
        
        # 1. Handle MSVC SEH (__try / __except)
        code, seh_changes = cls._handle_seh(code)
        changes += seh_changes
        
        # 2. Handle MSVC-specific intrinsics
        code, intrinsic_changes = cls._handle_intrinsics(code)
        changes += intrinsic_changes
        
        # 3. Handle wide string literal issues
        code, string_changes = cls._handle_wide_strings(code)
        changes += string_changes
        
        # 4. Handle MSVC pragmas
        code, pragma_changes = cls._handle_pragmas(code)
        changes += pragma_changes
        
        # 5. Inject MinGW compatibility definitions for missing types
        code, compat_changes = cls._inject_compat_definitions(code)
        changes += compat_changes
        
        # 6. Handle MSVC-specific type aliases
        code, alias_changes = cls._handle_type_aliases(code)
        changes += alias_changes
        
        # 7. Handle MSVC SAL annotations (__in, __out, _In_, _Out_, etc.)
        code, sal_changes = cls._handle_sal_annotations(code)
        changes += sal_changes
        
        # 8. Fix inline assembly register issues (32-bit push/pop in 64-bit mode)
        code, asm_changes = cls._handle_inline_asm(code)
        changes += asm_changes
        
        # 9. Fix Windows header dependency ordering
        code, header_changes = cls._handle_header_deps(code)
        changes += header_changes
        
        # 10. Handle MSVC #import directive (COM type library imports)
        code, import_changes = cls._handle_import_directive(code)
        changes += import_changes
        
        # 11. Handle missing Windows SDK defines
        code, winsdk_changes = cls._handle_winsdk_defines(code)
        changes += winsdk_changes
        
        # 12. Handle #error directives (comment out build config errors)
        code, error_dir_changes = cls._handle_error_directives(code)
        changes += error_dir_changes
        
        # 13. Handle missing Windows constants/macros
        code, winconst_changes = cls._handle_windows_constants(code)
        changes += winconst_changes
        
        # 14. Handle MSVC-specific safe functions (_snprintf_s, etc.)
        code, safe_func_changes = cls._handle_safe_functions(code)
        changes += safe_func_changes
        
        # 15. Handle C++ specific issues (std::nothrow, user-defined literal)
        code, cpp_changes = cls._handle_cpp_compat(code, language)
        changes += cpp_changes
        
        if changes > 0:
            logger.info(f"Applied {changes} GCC compatibility fix(es)")
        
        return code, changes
    
    @classmethod
    def _handle_seh(cls, code: str) -> Tuple[str, int]:
        """Handle MSVC SEH (__try/__except) for GCC compatibility.
        
        Instead of trying to match complex nested SEH blocks with regex,
        inject GCC-compatible macro definitions that approximate SEH behavior.
        __try blocks always execute, __except blocks never execute.
        """
        changes = 0
        
        if '__try' not in code or '__except' not in code:
            return code, 0
        
        # Already has the compat macros?
        if '__GNUC__' in code and '__try' in code.split('__GNUC__')[0][-200:]:
            return code, 0
        
        # Inject SEH compatibility macros at the top (or after includes)
        seh_compat = (
            '\n/* ====== SEH Compatibility for GCC ====== */\n'
            '#ifndef _MSC_VER\n'
            '#ifndef __try\n'
            '#define __try if(1)\n'
            '#endif\n'
            '#ifndef __except\n'
            '#define __except(x) if(0)\n'
            '#endif\n'
            '#ifndef __finally\n'
            '#define __finally\n'
            '#endif\n'
            '#ifndef __leave\n'
            '#define __leave\n'
            '#endif\n'
            '#ifndef GetExceptionCode\n'
            '#define GetExceptionCode() 0\n'
            '#endif\n'
            '#ifndef GetExceptionInformation\n'
            '#define GetExceptionInformation() NULL\n'
            '#endif\n'
            '#ifndef EXCEPTION_EXECUTE_HANDLER\n'
            '#define EXCEPTION_EXECUTE_HANDLER 1\n'
            '#endif\n'
            '#endif /* _MSC_VER */\n'
            '/* ====== End SEH Compatibility ====== */\n\n'
        )
        
        # Already have the compat block?
        if '/* ====== SEH Compatibility for GCC ====== */' in code:
            return code, 0
        
        # Find position after last #include
        include_positions = [m.end() for m in re.finditer(r'#\s*include\s*[<"][^>"]*[>"]', code)]
        if include_positions:
            insert_pos = max(include_positions)
            nl = code.find('\n', insert_pos)
            if nl != -1:
                insert_pos = nl + 1
        else:
            insert_pos = 0
        
        code = code[:insert_pos] + seh_compat + code[insert_pos:]
        changes = 1
        
        return code, changes
    
    @classmethod
    def _handle_intrinsics(cls, code: str) -> Tuple[str, int]:
        """Handle MSVC intrinsics"""
        changes = 0
        
        # Common MSVC intrinsics that need alternatives
        intrinsics = {
            '__fastfail': 'abort',
            '__debugbreak': '/* __debugbreak() not available */',
        }
        
        for msvc_func, gcc_replacement in intrinsics.items():
            if msvc_func in code:
                code = code.replace(f'{msvc_func}(', f'{gcc_replacement}(')
                changes += 1
        
        return code, changes
    
    @classmethod
    def _handle_wide_strings(cls, code: str) -> Tuple[str, int]:
        """Handle wide string literals in ANSI function calls"""
        changes = 0
        
        # Functions that expect ANSI strings but might receive wide strings
        ansi_functions = [
            'CreateWindowExA', 'CreateWindowA', 'LoadLibraryA', 
            'RegisterClassExA', 'RegisterClassA',
            'MessageBoxA', 'FindWindowA', 'GetProcAddress'
        ]
        
        for func in ansi_functions:
            # Pattern: FunctionName(..., L"string", ...)
            pattern = re.compile(rf'({func}\s*\([^)]*?)L"([^"]*)"', re.MULTILINE)
            
            def replace_wide_string(match):
                nonlocal changes
                before = match.group(1)
                string_content = match.group(2)
                changes += 1
                return f'{before}"{string_content}"'
            
            code = pattern.sub(replace_wide_string, code)
        
        return code, changes
    
    @classmethod
    def _handle_pragmas(cls, code: str) -> Tuple[str, int]:
        """Handle MSVC-specific pragmas"""
        changes = 0
        
        # MSVC pragmas that should be conditionally compiled
        msvc_pragmas = [
            'pragma comment',
            'pragma warning',
        ]
        
        for pragma in msvc_pragmas:
            pattern = re.compile(rf'^\s*#\s*{pragma}[^\n]*$', re.MULTILINE)
            
            def wrap_pragma(match):
                nonlocal changes
                pragma_line = match.group(0)
                
                # Check if already wrapped
                start_pos = match.start()
                if start_pos > 10:
                    before_code = code[max(0, start_pos-50):start_pos]
                    if '#ifdef _MSC_VER' in before_code:
                        return pragma_line  # Already wrapped
                
                changes += 1
                return f"#ifdef _MSC_VER\n{pragma_line}\n#endif"
            
            code = pattern.sub(wrap_pragma, code)
        
        return code, changes
    
    @classmethod
    def add_compatibility_header(cls, code: str) -> str:
        """Add compatibility macros at the beginning of file"""
        
        # Check if already has compatibility header
        if '/* GCC Compatibility */' in code or '__GNUC__' in code[:500]:
            return code
        
        compatibility_header = """
/* GCC Compatibility Macros */
#ifdef __GNUC__
  #ifndef _MSC_VER
    #define _MSC_VER 0
  #endif
  /* Add GCC-specific definitions here */
#endif

"""
        
        # Find first #include or beginning of file
        first_include = re.search(r'#\s*include', code)
        if first_include:
            insert_pos = first_include.start()
        else:
            # Skip initial comments
            match = re.search(r'^/\*.*?\*/', code, re.DOTALL)
            if match:
                insert_pos = match.end()
                nl = code.find('\n', insert_pos)
                if nl != -1:
                    insert_pos = nl + 1
            else:
                insert_pos = 0
        
        code = code[:insert_pos] + compatibility_header + code[insert_pos:]
        
        return code
    
    @classmethod
    def _inject_compat_definitions(cls, code: str) -> Tuple[str, int]:
        """Inject MinGW compatibility definitions if needed types are used 
        but NOT already defined in the file."""
        changes = 0
        
        # Only add definitions for types that are USED but NOT DEFINED in the file
        # Check 'typedef ... TYPE' or 'enum ... TYPE' or '#define TYPE' in existing code
        definitions_to_add = []
        
        # NTSTATUS
        if 'NTSTATUS' in code and 'typedef' not in code.split('NTSTATUS')[0][-100:] and '#define NTSTATUS' not in code:
            if 'typedef LONG NTSTATUS' not in code and 'typedef long NTSTATUS' not in code.lower():
                definitions_to_add.append('#ifndef NTSTATUS\ntypedef LONG NTSTATUS;\n#endif')
        
        # NT_SUCCESS
        if 'NT_SUCCESS' in code and '#define NT_SUCCESS' not in code:
            definitions_to_add.append('#ifndef NT_SUCCESS\n#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)\n#endif')
        
        # Don't inject enum types (PROCESSINFOCLASS, SYSTEM_INFORMATION_CLASS, etc.)
        # because they frequently conflict with source-defined versions.
        # Instead, just make sure NTSTATUS and macros are defined.
        
        if not definitions_to_add:
            return code, 0
        
        # Already injected?
        if '/* ====== MinGW Compatibility ====== */' in code:
            return code, 0
        
        compat_block = '\n/* ====== MinGW Compatibility ====== */\n#ifdef __GNUC__\n'
        compat_block += '\n'.join(definitions_to_add)
        compat_block += '\n#endif\n/* ====== End MinGW Compatibility ====== */\n\n'
        
        # Find position after last #include
        include_positions = [m.end() for m in re.finditer(r'#\s*include\s*[<"][^>"]*[>"]', code)]
        if include_positions:
            insert_pos = max(include_positions)
            nl = code.find('\n', insert_pos)
            if nl != -1:
                insert_pos = nl + 1
        else:
            insert_pos = 0
        
        code = code[:insert_pos] + compat_block + code[insert_pos:]
        changes += len(definitions_to_add)
        
        return code, changes
    
    @classmethod
    def _handle_header_deps(cls, code: str) -> Tuple[str, int]:
        """Fix Windows header dependency ordering for MinGW.
        
        Some MSVC code includes Windows-specific headers (wininet.h, winsock2.h, etc.)
        without including windows.h first. MSVC handles this internally, but MinGW
        requires explicit windows.h inclusion.
        """
        changes = 0
        
        # Headers that require windows.h to be included first
        win_dependent_headers = [
            'wininet.h', 'winsock2.h', 'winsock.h', 'ws2tcpip.h',
            'shellapi.h', 'shlobj.h', 'shlwapi.h', 'commdlg.h',
            'tlhelp32.h', 'psapi.h', 'dbghelp.h', 'winhttp.h',
        ]
        
        has_windows_h = '#include <windows.h>' in code or '#include "windows.h"' in code
        
        for header in win_dependent_headers:
            include_pattern = f'#include <{header}>'
            if include_pattern in code and not has_windows_h:
                # Add windows.h before the first dependent header include
                code = code.replace(
                    include_pattern,
                    f'#include <windows.h>\n{include_pattern}',
                    1  # Only first occurrence
                )
                has_windows_h = True
                changes += 1
                break  # One windows.h include is enough
        
        return code, changes
    
    @classmethod
    def _handle_inline_asm(cls, code: str) -> Tuple[str, int]:
        """Fix inline assembly issues for x86-64 GCC.
        
        Handles MSVC-to-GCC assembly conversion issues by wrapping
        inline asm blocks in #ifdef _MSC_VER to disable them on GCC.
        """
        changes = 0
        
        has_asm = ('__asm__' in code or '__asm' in code or 
                   re.search(r'\b_asm\b', code) is not None)
        if not has_asm:
            return code, 0
        
        # Already has our asm compat guard?
        if '/* ====== Inline ASM Compat' in code:
            return code, 0
        
        # Strategy 1: Wrap __asm__ __volatile__(...) blocks (GCC-converted asm)
        asm_volatile_pattern = re.compile(
            r'(__asm__\s+__volatile__\s*\((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*\)\s*;)',
            re.DOTALL
        )
        new_code = asm_volatile_pattern.sub(
            r'/* ====== Inline ASM Compat - disabled for GCC ====== */\n'
            r'#ifdef _MSC_VER\n\1\n#endif\n',
            code
        )
        if new_code != code:
            code = new_code
            changes += 1
        
        # Strategy 2: Wrap __asm { ... } and _asm { ... } blocks (MSVC multi-line asm)
        # Use word boundary to avoid matching __asm__ 
        msvc_asm_block = re.compile(
            r'((?:__asm|(?<![_\w])_asm)\s*\{[^}]*\})',
            re.DOTALL
        )
        new_code = msvc_asm_block.sub(
            r'#ifdef _MSC_VER\n\1\n#endif /* _MSC_VER */\n',
            code
        )
        if new_code != code:
            code = new_code
            changes += 1
        
        return code, changes
    
    @classmethod
    def _handle_type_aliases(cls, code: str) -> Tuple[str, int]:
        """Handle MSVC-specific type aliases that MinGW may lack."""
        changes = 0
        
        type_compat = ""
        
        # MSVC uses _stricmp, GCC uses strcasecmp
        if '_stricmp' in code and 'strcasecmp' not in code:
            type_compat += '#ifndef _stricmp\n#define _stricmp strcasecmp\n#endif\n'
            changes += 1
        
        if '_strnicmp' in code and 'strncasecmp' not in code:
            type_compat += '#ifndef _strnicmp\n#define _strnicmp strncasecmp\n#endif\n'
            changes += 1
        
        if '_snprintf' in code and 'snprintf' not in code:
            type_compat += '#ifndef _snprintf\n#define _snprintf snprintf\n#endif\n'
            changes += 1
        
        if '_vsnprintf' in code and 'vsnprintf' not in code:
            type_compat += '#ifndef _vsnprintf\n#define _vsnprintf vsnprintf\n#endif\n'
            changes += 1
        
        if '_alloca' in code:
            type_compat += '#ifndef _alloca\n#define _alloca alloca\n#endif\n'
            changes += 1
        
        # Replace __forceinline (MSVC) with inline __attribute__((always_inline))
        if '__forceinline' in code:
            code = re.sub(r'\b__forceinline\b', 'inline __attribute__((always_inline))', code)
            changes += 1
        
        # Replace __declspec(noinline) with __attribute__((noinline))
        if '__declspec(noinline)' in code:
            code = code.replace('__declspec(noinline)', '__attribute__((noinline))')
            changes += 1
        
        # Replace __declspec(dllexport) with __attribute__((dllexport))
        if '__declspec(dllexport)' in code:
            code = code.replace('__declspec(dllexport)', '__attribute__((dllexport))')
            changes += 1
        
        # Replace __declspec(dllimport) with __attribute__((dllimport))
        if '__declspec(dllimport)' in code:
            code = code.replace('__declspec(dllimport)', '__attribute__((dllimport))')
            changes += 1
        
        # Replace __declspec(align(x)) with __attribute__((aligned(x)))
        align_pattern = re.compile(r'__declspec\s*\(\s*align\s*\(\s*(\d+)\s*\)\s*\)')
        if align_pattern.search(code):
            code = align_pattern.sub(r'__attribute__((aligned(\1)))', code)
            changes += 1
        
        # Replace __declspec(naked) with __attribute__((naked))
        if '__declspec(naked)' in code:
            code = code.replace('__declspec(naked)', '__attribute__((naked))')
            changes += 1
        
        # Replace __declspec(novtable) - no GCC equivalent, just remove
        if '__declspec(novtable)' in code:
            code = code.replace('__declspec(novtable)', '')
            changes += 1
        
        # Replace __declspec(selectany) with __attribute__((weak))
        if '__declspec(selectany)' in code:
            code = code.replace('__declspec(selectany)', '__attribute__((weak))')
            changes += 1
        
        # Generic __declspec(...) handler - remove unknown ones
        remaining_declspec = re.compile(r'__declspec\s*\([^)]*\)')
        if remaining_declspec.search(code):
            unknowns = remaining_declspec.findall(code)
            for u in unknowns:
                if any(k in u for k in ['dllexport', 'dllimport', 'noinline', 'align', 'naked', 'novtable', 'selectany']):
                    continue  # Already handled
                code = code.replace(u, '/* ' + u + ' */')
                changes += 1
        
        # Handle __cdecl, __stdcall, __thiscall calling conventions
        # MinGW supports these but some code uses them differently
        # Just ensure they work - these should be available in MinGW
        
        # Handle MSVC _countof macro
        if '_countof' in code and '#define _countof' not in code:
            type_compat += '#ifndef _countof\n#define _countof(arr) (sizeof(arr)/sizeof((arr)[0]))\n#endif\n'
            changes += 1
        
        # Handle __pragma (MSVC-specific, different from #pragma)
        if '__pragma(' in code:
            code = re.sub(r'__pragma\s*\([^)]*\)', '/* __pragma removed */', code)
            changes += 1
        
        if type_compat:
            code = type_compat + code
        
        return code, changes
    
    @classmethod
    def _handle_sal_annotations(cls, code: str) -> Tuple[str, int]:
        """Handle MSVC SAL (Source Annotation Language) annotations.
        
        SAL annotations like __in, __out, _In_, _Out_, _Inout_ etc. are
        MSVC-specific parameter annotations used for static analysis.
        GCC/MinGW doesn't understand them, so we define them as empty macros.
        """
        changes = 0
        
        # Check if any SAL annotations are present
        sal_patterns = [
            '__in', '__out', '__inout', '__deref',
            '_In_', '_Out_', '_Inout_', '_Deref_',
            '_In_opt_', '_Out_opt_', '_Inout_opt_',
            '__in_opt', '__out_opt', '__inout_opt',
            '_In_z_', '_Out_z_', '_In_reads_', '_Out_writes_',
            '__reserved', '_Reserved_',
            '_Ret_maybenull_', '_Success_', '_Must_inspect_result_',
            '__callback', '_Pre_', '_Post_',
            '__out_data_source', '__in_data_source',
        ]
        
        has_sal = False
        for pattern in sal_patterns:
            if pattern in code:
                has_sal = True
                break
        
        if not has_sal:
            return code, 0
        
        # Inject SAL compatibility macros at the top of the file
        sal_compat = """
/* SAL annotation compatibility for GCC/MinGW */
#ifndef _MSC_VER
#ifndef __SAL_COMPAT_DEFINED__
#define __SAL_COMPAT_DEFINED__
#define __in
#define __out
#define __inout
#define __in_opt
#define __out_opt
#define __inout_opt
#define __in_ecount(x)
#define __out_ecount(x)
#define __in_bcount(x)
#define __out_bcount(x)
#define __deref_out
#define __deref_out_opt
#define __deref_inout
#define __reserved
#define __callback
#define __out_data_source(x)
#define __in_data_source(x)
#define _In_
#define _Out_
#define _Inout_
#define _In_opt_
#define _Out_opt_
#define _Inout_opt_
#define _In_z_
#define _Out_z_
#define _In_reads_(x)
#define _Out_writes_(x)
#define _In_reads_bytes_(x)
#define _Out_writes_bytes_(x)
#define _Deref_out_
#define _Deref_out_opt_
#define _Reserved_
#define _Ret_maybenull_
#define _Must_inspect_result_
#define _Success_(x)
#define _Pre_
#define _Post_
#endif /* __SAL_COMPAT_DEFINED__ */
#endif /* _MSC_VER */
"""
        code = sal_compat + code
        changes += 1
        
        return code, changes

    @classmethod
    def _handle_import_directive(cls, code: str) -> Tuple[str, int]:
        """Handle MSVC #import directive (COM type library imports).
        #import is MSVC-only for importing COM type libraries.
        Wrap in #ifdef _MSC_VER or comment out for GCC."""
        changes = 0
        
        # Match #import "file" or #import <file> with optional attributes
        import_pattern = re.compile(
            r'^(\s*)(#import\s+(?:"[^"]+"|<[^>]+>).*?)$',
            re.MULTILINE
        )
        
        def wrap_import(match):
            indent = match.group(1)
            directive = match.group(2)
            return (f"{indent}#ifdef _MSC_VER\n"
                    f"{indent}{directive}\n"
                    f"{indent}#endif /* _MSC_VER */")
        
        new_code = import_pattern.sub(wrap_import, code)
        if new_code != code:
            changes += 1
            code = new_code
            logger.info("Wrapped #import directives in #ifdef _MSC_VER")
        
        return code, changes

    @classmethod
    def _handle_winsdk_defines(cls, code: str) -> Tuple[str, int]:
        """Add missing Windows SDK defines that GCC/MinGW sometimes lacks."""
        changes = 0
        
        winsdk_compat = ""
        
        # SECURITY_WIN32 must be defined before including sspi.h or security.h
        if re.search(r'#include\s*[<"](?:sspi\.h|security\.h|Security\.h|Sspi\.h)[">]', code):
            if 'SECURITY_WIN32' not in code:
                winsdk_compat += """
/* Define SECURITY_WIN32 for sspi.h/security.h user-mode API */
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
"""
                changes += 1
                logger.info("Added SECURITY_WIN32 define for sspi.h")
        
        # DWL_MSGRESULT was removed in favor of DWLP_MSGRESULT in modern Windows SDK
        if 'DWL_MSGRESULT' in code or 'DWL_DLGPROC' in code or 'DWL_USER' in code:
            winsdk_compat += """
/* Deprecated dialog window long offsets - map to pointer-width versions */
#ifndef DWL_MSGRESULT
#define DWL_MSGRESULT DWLP_MSGRESULT
#endif
#ifndef DWL_DLGPROC
#define DWL_DLGPROC DWLP_DLGPROC
#endif
#ifndef DWL_USER
#define DWL_USER DWLP_USER
#endif
"""
            changes += 1
            logger.info("Added DWL_MSGRESULT -> DWLP_MSGRESULT compat defines")
        
        # Handle missing INTERNET_FLAG_* or other wininet constants
        if re.search(r'#include\s*[<"]wininet\.h[">]', code, re.IGNORECASE):
            # Ensure windows.h is included before wininet.h
            if not re.search(r'#include\s*[<"]windows\.h[">]', code, re.IGNORECASE):
                winsdk_compat += """
/* wininet.h requires windows.h */
#include <windows.h>
"""
                changes += 1
                logger.info("Added windows.h include before wininet.h")
        
        # Handle winsock2.h needing to come before windows.h
        if (re.search(r'#include\s*[<"]winsock2\.h[">]', code, re.IGNORECASE) and
            re.search(r'#include\s*[<"]windows\.h[">]', code, re.IGNORECASE)):
            # Check if winsock2 comes after windows.h
            ws2_pos = re.search(r'#include\s*[<"]winsock2\.h[">]', code, re.IGNORECASE).start()
            win_pos = re.search(r'#include\s*[<"]windows\.h[">]', code, re.IGNORECASE).start()
            if ws2_pos > win_pos:
                # Move winsock2 before windows.h by adding at top
                winsdk_compat = "#include <winsock2.h>\n" + winsdk_compat
                # Remove the original winsock2 include
                code = re.sub(r'#include\s*[<"]winsock2\.h[">]\s*\n?', '', code, count=1, flags=re.IGNORECASE)
                changes += 1
                logger.info("Moved winsock2.h before windows.h")
        
        # Handle NTSTATUS if ntdef.h or winternl.h is included
        if re.search(r'#include\s*[<"](?:ntdef\.h|winternl\.h|ntstatus\.h)[">]', code, re.IGNORECASE):
            if 'typedef' not in code or 'NTSTATUS' not in code.split('typedef')[0]:
                pass  # Already handled in _inject_compat_definitions
        
        # Handle COM-related defines
        if re.search(r'\bCLSID_\w+|\bIID_\w+|\bCoCreateInstance\b|\bCoInitialize\b', code):
            if not re.search(r'#include\s*[<"]objbase\.h[">]|#include\s*[<"]ole2\.h[">]', code, re.IGNORECASE):
                if re.search(r'#include\s*[<"]windows\.h[">]', code, re.IGNORECASE):
                    pass  # windows.h should pull in COM basics
                else:
                    winsdk_compat += """
/* COM support */
#include <objbase.h>
"""
                    changes += 1
        
        # Handle RtlSecureZeroMemory / SecureZeroMemory
        if 'SecureZeroMemory' in code or 'RtlSecureZeroMemory' in code:
            if not re.search(r'#include\s*[<"]windows\.h[">]', code, re.IGNORECASE):
                winsdk_compat += """
#ifndef SecureZeroMemory
#define SecureZeroMemory(ptr, cnt) memset((ptr), 0, (cnt))
#endif
#ifndef RtlSecureZeroMemory
#define RtlSecureZeroMemory(ptr, cnt) memset((ptr), 0, (cnt))
#endif
"""
                changes += 1
        
        if winsdk_compat:
            code = winsdk_compat + "\n" + code
        
        return code, changes


    @classmethod
    def _handle_error_directives(cls, code: str) -> Tuple[str, int]:
        """Comment out #error directives that fail due to missing build config macros.
        These are typically configuration checks like #error MEM_PERSONAL_HEAP not defined
        that we cannot satisfy without the original build system."""
        changes = 0
        
        # Pattern: #error SOMETHING_NOT_DEFINED or #error "message"
        # Only comment out if it's about missing defines, not security/platform checks
        error_pattern = re.compile(
            r'^(\s*)#\s*error\s+(.+)$',
            re.MULTILINE
        )
        
        def comment_error(match):
            nonlocal changes
            indent = match.group(1)
            msg = match.group(2).strip()
            # Only comment out configuration-related #error
            config_keywords = [
                'not defined', 'NOT DEFINED', 'undefined', 'UNDEFINED',
                'must be defined', 'MUST BE DEFINED', 'required', 'REQUIRED',
                'missing', 'MISSING', 'need', 'NEED', 'set', 'SET',
                'MEM_', 'CONFIG_', 'USE_', 'ENABLE_', 'DISABLE_',
                'BUILD_', 'PLATFORM_', 'TARGET_', 'VERSION_',
            ]
            if any(kw in msg for kw in config_keywords):
                changes += 1
                return f'{indent}/* #error {msg} */  /* commented out for GCC compat */'
            return match.group(0)
        
        new_code = error_pattern.sub(comment_error, code)
        if changes > 0:
            code = new_code
            logger.info(f"Commented out {changes} #error directive(s)")
        
        return code, changes
    
    @classmethod
    def _handle_windows_constants(cls, code: str) -> Tuple[str, int]:
        """Add missing Windows constants/macros that MinGW may not define."""
        changes = 0
        const_defs = ""
        
        # MAX_PATH
        if 'MAX_PATH' in code and '#define MAX_PATH' not in code:
            const_defs += '#ifndef MAX_PATH\n#define MAX_PATH 260\n#endif\n'
            changes += 1
        
        # MAKEWORD
        if 'MAKEWORD' in code and '#define MAKEWORD' not in code:
            const_defs += '#ifndef MAKEWORD\n#define MAKEWORD(a, b) ((WORD)(((BYTE)(((DWORD_PTR)(a)) & 0xff)) | ((WORD)((BYTE)(((DWORD_PTR)(b)) & 0xff))) << 8))\n#endif\n'
            changes += 1
        
        # INVALID_HANDLE_VALUE
        if 'INVALID_HANDLE_VALUE' in code and '#define INVALID_HANDLE_VALUE' not in code:
            const_defs += '#ifndef INVALID_HANDLE_VALUE\n#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)\n#endif\n'
            changes += 1
        
        # INVALID_FILE_SIZE
        if 'INVALID_FILE_SIZE' in code and '#define INVALID_FILE_SIZE' not in code:
            const_defs += '#ifndef INVALID_FILE_SIZE\n#define INVALID_FILE_SIZE ((DWORD)0xFFFFFFFF)\n#endif\n'
            changes += 1
        
        # INFINITE
        if re.search(r'\bINFINITE\b', code) and '#define INFINITE' not in code:
            const_defs += '#ifndef INFINITE\n#define INFINITE 0xFFFFFFFF\n#endif\n'
            changes += 1
        
        # VOID, PVOID, LPVOID for kernel-like code
        if re.search(r'\bVOID\b', code) and 'typedef' not in code[:500]:
            # Only if it looks like it's used as a type, not just in comments
            if re.search(r'\bVOID\s+\w|\bVOID\s*\*|\bVOID\s*\)', code):
                const_defs += '#ifndef VOID\n#define VOID void\n#endif\n'
                const_defs += '#ifndef PVOID\ntypedef void* PVOID;\n#endif\n'
                changes += 1
        
        # TRUE / FALSE
        if re.search(r'\bTRUE\b', code) and '#define TRUE' not in code:
            const_defs += '#ifndef TRUE\n#define TRUE 1\n#endif\n#ifndef FALSE\n#define FALSE 0\n#endif\n'
            changes += 1
        
        if const_defs:
            # Insert after includes
            include_positions = [m.end() for m in re.finditer(r'#\s*include\s*[<"][^>"]*[>"]', code)]
            if include_positions:
                insert_pos = max(include_positions)
                nl = code.find('\n', insert_pos)
                if nl != -1:
                    insert_pos = nl + 1
            else:
                insert_pos = 0
            
            block = '\n/* ====== Windows Constants Compat ====== */\n' + const_defs + '/* ====== End Constants Compat ====== */\n\n'
            code = code[:insert_pos] + block + code[insert_pos:]
        
        return code, changes
    
    @classmethod
    def _handle_safe_functions(cls, code: str) -> Tuple[str, int]:
        """Handle MSVC secure CRT functions (_s suffix variants)."""
        changes = 0
        safe_defs = ""
        
        # _snprintf_s → snprintf
        if '_snprintf_s' in code and '#define _snprintf_s' not in code:
            safe_defs += '#ifndef _snprintf_s\n#define _snprintf_s(buf, size, count, ...) snprintf(buf, size, __VA_ARGS__)\n#endif\n'
            changes += 1
        
        # _sprintf_s → sprintf (or snprintf)
        if '_sprintf_s' in code and '#define _sprintf_s' not in code:
            safe_defs += '#ifndef _sprintf_s\n#define _sprintf_s(buf, size, ...) snprintf(buf, size, __VA_ARGS__)\n#endif\n'
            changes += 1
        
        # _strcpy_s → strncpy
        if '_strcpy_s' in code and '#define _strcpy_s' not in code:
            safe_defs += '#ifndef _strcpy_s\n#define _strcpy_s(dst, size, src) strncpy(dst, src, size)\n#endif\n'
            changes += 1
        
        # _strcat_s → strncat
        if '_strcat_s' in code and '#define _strcat_s' not in code:
            safe_defs += '#ifndef _strcat_s\n#define _strcat_s(dst, size, src) strncat(dst, src, size - strlen(dst) - 1)\n#endif\n'
            changes += 1
        
        # _wcsncpy_s → wcsncpy
        if '_wcsncpy_s' in code and '#define _wcsncpy_s' not in code:
            safe_defs += '#ifndef _wcsncpy_s\n#define _wcsncpy_s(dst, size, src, count) wcsncpy(dst, src, count)\n#endif\n'
            changes += 1
        
        # _wcscpy_s → wcsncpy
        if '_wcscpy_s' in code and '#define _wcscpy_s' not in code:
            safe_defs += '#ifndef _wcscpy_s\n#define _wcscpy_s(dst, size, src) wcsncpy(dst, src, size)\n#endif\n'
            changes += 1
        
        # _itoa_s → snprintf
        if '_itoa_s' in code and '#define _itoa_s' not in code:
            safe_defs += '#ifndef _itoa_s\n#define _itoa_s(val, buf, size, radix) snprintf(buf, size, "%d", val)\n#endif\n'
            changes += 1
        
        # _splitpath_s / _wsplitpath_s
        if '_splitpath_s' in code and '#define _splitpath_s' not in code:
            safe_defs += '#ifndef _splitpath_s\n#define _splitpath_s(path, drive, ds, dir, dirs, fname, fs, ext, es) _splitpath(path, drive, dir, fname, ext)\n#endif\n'
            changes += 1
        
        if safe_defs:
            code = '/* ====== MSVC Safe CRT Compat ====== */\n' + safe_defs + '/* ====== End Safe CRT Compat ====== */\n\n' + code
        
        return code, changes
    
    @classmethod
    def _handle_cpp_compat(cls, code: str, language: str = "c") -> Tuple[str, int]:
        """Handle C++ specific compatibility issues."""
        changes = 0
        
        if language not in ('cpp', 'c++', 'cxx'):
            return code, 0
        
        # std::nothrow needs #include <new>
        if 'nothrow' in code:
            if not re.search(r'#include\s*<new>', code):
                # Add after last include
                include_positions = [m.end() for m in re.finditer(r'#\s*include\s*[<"][^>"]*[>"]', code)]
                if include_positions:
                    insert_pos = max(include_positions)
                    nl = code.find('\n', insert_pos)
                    if nl != -1:
                        insert_pos = nl + 1
                    code = code[:insert_pos] + '#include <new>\n' + code[insert_pos:]
                    changes += 1
        
        # User-defined literal: MSVC allows "string"MACRO, GCC needs space
        # Pattern: "..."identifier (no space between closing quote and identifier)
        udl_pattern = re.compile(r'("[^"]*")([A-Za-z_]\w*)')
        
        def fix_udl(match):
            nonlocal changes
            string_part = match.group(1)
            ident = match.group(2)
            # Known string literal suffixes are OK (s, sv, etc. for C++14+)
            if ident in ('s', 'sv', 'h', 'min', 'ms', 'us', 'ns', 'i', 'if', 'il'):
                return match.group(0)
            changes += 1
            return f'{string_part} {ident}'
        
        new_code = udl_pattern.sub(fix_udl, code)
        if new_code != code:
            code = new_code
        
        return code, changes


def main():
    """Test compiler compatibility"""
    test_code = """
    #include <windows.h>
    
    bool DetectVM() {
        __try {
            // Some VM detection code
            return true;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }
    
    void CreateWin() {
        CreateWindowExA(0, L"MyClass", L"Title", 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
    }
    """
    
    print("Testing Compiler Compatibility")
    print("=" * 60)
    
    fixed_code, changes = CompilerCompatibility.make_gcc_compatible(test_code)
    
    print(f"Changes applied: {changes}")
    print("\nFixed code:")
    print(fixed_code)


if __name__ == "__main__":
    main()





