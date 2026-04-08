"""
Compilation Validator
=====================
Pre-compilation and post-compilation validation.
Checks for common issues before attempting to compile.
"""
import os
import re
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ValidationIssue:
    """A validation issue found in the code"""
    severity: str  # 'error', 'warning', 'info'
    category: str
    message: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    suggestion: Optional[str] = None


class CompilationValidator:
    """Validate code before and after compilation"""
    
    # Entry point patterns - support various calling conventions
    ENTRY_POINTS = {
        'WinMain': re.compile(r'int\s+(?:WINAPI\s+|APIENTRY\s+|__stdcall\s+)?WinMain\s*\('),
        'wWinMain': re.compile(r'int\s+(?:WINAPI\s+|APIENTRY\s+|__stdcall\s+)?wWinMain\s*\('),
        'main': re.compile(r'int\s+main\s*\('),
        '_start': re.compile(r'void\s+_start\s*\('),
        'DllMain': re.compile(r'BOOL\s+(?:WINAPI\s+|APIENTRY\s+|__stdcall\s+)?DllMain\s*\('),
    }
    
    # System types that should not be redefined
    SYSTEM_TYPES = {
        'sockaddr', 'sockaddr_in', 'in_addr', 'hostent',
        'FILE', 'time_t', 'size_t', 'wchar_t',
        'SOCKET', 'HANDLE', 'DWORD', 'WORD', 'BYTE',
    }
    
    @classmethod
    def validate_project(cls, project, verbose: bool = True) -> Tuple[bool, List[ValidationIssue]]:
        """
        Validate entire project before compilation.
        
        Args:
            project: MalwareProject object
            verbose: Print detailed output
            
        Returns:
            Tuple of (is_valid, list of issues)
        """
        if verbose:
            logger.info("Validating project before compilation...")
        
        issues = []
        
        # Check for entry points
        entry_issues = cls._check_entry_points(project)
        issues.extend(entry_issues)
        
        # Check for duplicate symbols
        dup_issues = cls._check_duplicate_symbols(project)
        issues.extend(dup_issues)
        
        # Check for system type redefinitions
        redef_issues = cls._check_system_redefinitions(project)
        issues.extend(redef_issues)
        
        # Check for missing includes
        include_issues = cls._check_missing_includes(project)
        issues.extend(include_issues)
        
        # Check for missing symbols (cross-file dependencies)
        symbol_issues = cls._check_missing_symbols(project)
        issues.extend(symbol_issues)
        
        # Determine if valid
        error_count = sum(1 for issue in issues if issue.severity == 'error')
        warning_count = sum(1 for issue in issues if issue.severity == 'warning')
        
        if verbose:
            logger.info(f"  Validation complete: {error_count} errors, {warning_count} warnings")
        
        is_valid = error_count == 0
        
        return is_valid, issues
    
    @classmethod
    def _check_entry_points(cls, project) -> List[ValidationIssue]:
        """Check if project has a valid entry point"""
        issues = []
        
        found_entry_points = []
        
        for source_file in project.source_files:
            try:
                with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for entry_name, pattern in cls.ENTRY_POINTS.items():
                    if pattern.search(content):
                        found_entry_points.append((entry_name, source_file))
            
            except Exception as e:
                logger.warning(f"Failed to check entry point in {source_file}: {e}")
        
        if not found_entry_points:
            issues.append(ValidationIssue(
                severity='error',
                category='missing_entry_point',
                message='No entry point found (WinMain, main, etc.)',
                suggestion='Add a WinMain or main function to one of the source files'
            ))
        elif len(found_entry_points) > 1:
            issues.append(ValidationIssue(
                severity='warning',
                category='multiple_entry_points',
                message=f'Multiple entry points found: {[ep[0] for ep in found_entry_points]}',
                suggestion='Ensure only one entry point is defined'
            ))
        else:
            logger.info(f"  ✓ Entry point found: {found_entry_points[0][0]} in {os.path.basename(found_entry_points[0][1])}")
        
        return issues
    
    @classmethod
    def _check_duplicate_symbols(cls, project) -> List[ValidationIssue]:
        """Check for duplicate function definitions"""
        issues = []
        
        # Pattern for function definitions
        func_pattern = re.compile(
            r'^\s*(?:static\s+)?(?:inline\s+)?([A-Za-z_][\w\s\*]+?)\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*\{',
            re.MULTILINE
        )
        
        function_definitions = {}  # func_name -> [(file, line_num), ...]
        
        for source_file in project.source_files:
            try:
                with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for match in func_pattern.finditer(content):
                    func_name = match.group(2).strip()
                    line_num = content[:match.start()].count('\n') + 1
                    
                    # Skip static functions (file-local scope)
                    if 'static' in match.group(0):
                        continue
                    
                    if func_name not in function_definitions:
                        function_definitions[func_name] = []
                    function_definitions[func_name].append((source_file, line_num))
            
            except Exception as e:
                logger.warning(f"Failed to check duplicates in {source_file}: {e}")
        
        # Find duplicates
        for func_name, locations in function_definitions.items():
            if len(locations) > 1:
                files_str = ', '.join([os.path.basename(loc[0]) for loc in locations])
                issues.append(ValidationIssue(
                    severity='error',
                    category='duplicate_symbol',
                    message=f"Function '{func_name}' defined in multiple files: {files_str}",
                    suggestion=f"Make '{func_name}' static in one file or remove duplicate definitions"
                ))
        
        if issues:
            logger.warning(f"  ⚠️  Found {len(issues)} duplicate symbol(s)")
        
        return issues
    
    @classmethod
    def _check_system_redefinitions(cls, project) -> List[ValidationIssue]:
        """Check for system type redefinitions"""
        issues = []
        
        # Patterns for type definitions
        struct_pattern = re.compile(r'^\s*struct\s+([A-Za-z_]\w*)\s*\{', re.MULTILINE)
        typedef_pattern = re.compile(r'^\s*typedef\s+.*?\s+([A-Za-z_]\w*)\s*;', re.MULTILINE)
        
        for source_file in project.source_files + project.header_files:
            try:
                with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Check struct definitions
                for match in struct_pattern.finditer(content):
                    struct_name = match.group(1)
                    if struct_name in cls.SYSTEM_TYPES:
                        line_num = content[:match.start()].count('\n') + 1
                        issues.append(ValidationIssue(
                            severity='error',
                            category='system_redefinition',
                            message=f"Redefinition of system type 'struct {struct_name}'",
                            file_path=source_file,
                            line_number=line_num,
                            suggestion=f"Remove or rename the definition of 'struct {struct_name}'"
                        ))
                
                # Check typedef definitions
                for match in typedef_pattern.finditer(content):
                    type_name = match.group(1)
                    if type_name in cls.SYSTEM_TYPES:
                        line_num = content[:match.start()].count('\n') + 1
                        issues.append(ValidationIssue(
                            severity='warning',
                            category='system_redefinition',
                            message=f"Possible redefinition of system type '{type_name}'",
                            file_path=source_file,
                            line_number=line_num,
                            suggestion=f"Check if '{type_name}' conflicts with system headers"
                        ))
            
            except Exception as e:
                logger.warning(f"Failed to check redefinitions in {source_file}: {e}")
        
        if issues:
            logger.warning(f"  ⚠️  Found {len(issues)} system type redefinition(s)")
        
        return issues
    
    @classmethod
    def _check_missing_includes(cls, project) -> List[ValidationIssue]:
        """Check for common missing includes"""
        issues = []
        
        # Common functions and their required headers
        # Each value is (required_header, set_of_equivalent_headers)
        common_apis = {
            'socket': ('winsock2.h', {'winsock.h', 'winsock2.h'}),
            'WSAStartup': ('winsock2.h', {'winsock.h', 'winsock2.h'}),
            'CreateFile': ('windows.h', {'windows.h'}),
            'CreateProcess': ('windows.h', {'windows.h'}),
            'RegOpenKey': ('windows.h', {'windows.h'}),
            'malloc': ('stdlib.h', {'stdlib.h'}),
            'printf': ('stdio.h', {'stdio.h'}),
            'strlen': ('string.h', {'string.h'}),
        }
        
        for source_file in project.source_files:
            try:
                with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Extract includes
                includes = re.findall(r'#\s*include\s+[<"]([^>"]+)[>"]', content)
                include_set = set(includes)
                
                # Check for common API usage without includes
                for api_func, (required_header, equivalents) in common_apis.items():
                    if re.search(rf'\b{api_func}\s*\(', content):
                        if not (include_set & equivalents):
                            issues.append(ValidationIssue(
                                severity='warning',
                                category='missing_include',
                                message=f"Function '{api_func}' used but '{required_header}' not included",
                                file_path=source_file,
                                suggestion=f"#include <{required_header}>"
                            ))
            
            except Exception as e:
                logger.warning(f"Failed to check includes in {source_file}: {e}")
        
        return issues
    
    @classmethod
    def _check_missing_symbols(cls, project) -> List[ValidationIssue]:
        """Check for function calls to undefined functions (cross-file dependencies)"""
        issues = []
        
        # First pass: Extract all function definitions
        defined_functions = set()
        func_def_pattern = re.compile(
            r'^\s*(?:static\s+)?(?:inline\s+)?(?:extern\s+)?(?:[A-Za-z_][\w\s\*]+?)\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*\{',
            re.MULTILINE
        )
        
        for source_file in project.source_files:
            try:
                with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for match in func_def_pattern.finditer(content):
                    func_name = match.group(1).strip()
                    defined_functions.add(func_name)
            except Exception as e:
                logger.warning(f"Failed to extract definitions from {source_file}: {e}")
        
        # Second pass: Extract function declarations from headers
        declared_functions = set()
        func_decl_pattern = re.compile(
            r'^\s*(?:extern\s+)?(?:[A-Za-z_][\w\s\*]+?)\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*;',
            re.MULTILINE
        )
        
        for header_file in project.header_files:
            try:
                with open(header_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for match in func_decl_pattern.finditer(content):
                    func_name = match.group(1).strip()
                    declared_functions.add(func_name)
            except Exception as e:
                logger.warning(f"Failed to extract declarations from {header_file}: {e}")
        
        # Combine defined and declared
        all_known_functions = defined_functions | declared_functions
        
        # Third pass: Find function calls
        func_call_pattern = re.compile(r'\b([A-Za-z_]\w*)\s*\(')
        
        # Common Windows/C functions to ignore
        system_functions = {
            'printf', 'sprintf', 'fprintf', 'snprintf', 'scanf', 'strlen', 'strcpy', 'strcat', 'strcmp',
            'malloc', 'free', 'realloc', 'calloc', 'memcpy', 'memset', 'memmove', 'memcmp',
            'fopen', 'fclose', 'fread', 'fwrite', 'fseek', 'ftell',
            'CreateFile', 'ReadFile', 'WriteFile', 'CloseHandle', 'CreateProcess', 'TerminateProcess',
            'VirtualAlloc', 'VirtualFree', 'LoadLibrary', 'GetProcAddress', 'FreeLibrary',
            'RegOpenKey', 'RegCloseKey', 'RegQueryValue', 'RegSetValue',
            'socket', 'connect', 'send', 'recv', 'bind', 'listen', 'accept', 'closesocket',
            'WSAStartup', 'WSACleanup', 'GetLastError', 'SetLastError',
            'sizeof', 'if', 'while', 'for', 'switch', 'return',  # Control flow keywords
        }
        
        missing_by_file = {}
        
        for source_file in project.source_files:
            try:
                with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Remove comments and strings to avoid false positives
                content_no_comments = re.sub(r'//.*', '', content)
                content_no_comments = re.sub(r'/\*.*?\*/', '', content_no_comments, flags=re.DOTALL)
                content_no_comments = re.sub(r'"[^"]*"', '""', content_no_comments)
                content_no_comments = re.sub(r"'[^']*'", "''", content_no_comments)
                
                called_functions = set()
                for match in func_call_pattern.finditer(content_no_comments):
                    func_name = match.group(1)
                    called_functions.add(func_name)
                
                # Find missing functions
                missing_functions = called_functions - all_known_functions - system_functions
                
                # Filter out obvious false positives (macros, type casts, etc.)
                missing_functions = {f for f in missing_functions if not f[0].isupper() or f.startswith('Get') or f.startswith('Set')}
                
                if missing_functions:
                    missing_by_file[source_file] = missing_functions
            
            except Exception as e:
                logger.warning(f"Failed to check symbols in {source_file}: {e}")
        
        # Create issues for missing symbols
        for file_path, missing_funcs in missing_by_file.items():
            if len(missing_funcs) > 0 and len(missing_funcs) <= 20:  # Only report if reasonable number
                issues.append(ValidationIssue(
                    severity='warning',
                    category='missing_symbols',
                    message=f"Possibly undefined functions: {', '.join(sorted(list(missing_funcs)[:10]))}",
                    file_path=file_path,
                    suggestion='Add forward declarations or include appropriate headers'
                ))
        
        if issues:
            logger.warning(f"  ⚠️  Found {len(issues)} file(s) with possibly missing symbols")
        
        return issues
    
    @classmethod
    def auto_fix_issues(cls, project, issues: List[ValidationIssue]) -> int:
        """
        Automatically fix validation issues where possible.
        
        Returns:
            Number of issues fixed
        """
        fixes_applied = 0
        
        # Group issues by file
        issues_by_file = {}
        for issue in issues:
            if issue.file_path and issue.category in ['system_redefinition', 'missing_include']:
                if issue.file_path not in issues_by_file:
                    issues_by_file[issue.file_path] = []
                issues_by_file[issue.file_path].append(issue)
        
        # Fix issues in each file
        for file_path, file_issues in issues_by_file.items():
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                modified = False
                
                for issue in file_issues:
                    if issue.category == 'system_redefinition' and issue.line_number:
                        # Comment out the problematic line
                        lines = content.split('\n')
                        if 0 <= issue.line_number - 1 < len(lines):
                            original_line = lines[issue.line_number - 1]
                            if not original_line.strip().startswith('//'):
                                lines[issue.line_number - 1] = '// ' + original_line + '  // Auto-fixed: system type redefinition'
                                content = '\n'.join(lines)
                                modified = True
                                fixes_applied += 1
                                logger.info(f"  Fixed: Commented out system type redefinition at line {issue.line_number}")
                    
                    elif issue.category == 'missing_include':
                        # Add missing include
                        if '#include' in issue.suggestion:
                            # CRITICAL: Clean LLM-style instructions from suggestion
                            # "Add #include <X>" → "#include <X>"
                            suggestion_clean = issue.suggestion
                            if suggestion_clean.strip().startswith('Add #include'):
                                suggestion_clean = suggestion_clean.strip()[len('Add '):]
                            elif suggestion_clean.strip().startswith('Add include'):
                                suggestion_clean = '#include' + suggestion_clean.strip()[len('Add include'):]
                            
                            include_line = suggestion_clean + '\n'
                            # Find first include or top of file
                            first_include = re.search(r'#\s*include', content)
                            if first_include:
                                # Add after first include
                                pos = content.find('\n', first_include.start()) + 1
                                content = content[:pos] + include_line + content[pos:]
                            else:
                                # Add at top
                                content = include_line + content
                            modified = True
                            fixes_applied += 1
                            logger.info(f"  Fixed: Added {suggestion_clean}")
                
                if modified:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)
            
            except Exception as e:
                logger.error(f"Failed to auto-fix issues in {file_path}: {e}")
        
        # Fix missing entry point
        entry_point_issues = [i for i in issues if i.category == 'missing_entry_point']
        if entry_point_issues and project.source_files:
            try:
                # Add a minimal WinMain to the first source file
                first_source = project.source_files[0]
                with open(first_source, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Check if really missing
                if not any(cls.ENTRY_POINTS[ep].search(content) for ep in cls.ENTRY_POINTS):
                    entry_point_code = """
// Auto-generated entry point
#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Entry point placeholder
    return 0;
}
"""
                    content += entry_point_code
                    
                    with open(first_source, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    fixes_applied += 1
                    logger.info(f"  Fixed: Added WinMain entry point to {os.path.basename(first_source)}")
            
            except Exception as e:
                logger.error(f"Failed to add entry point: {e}")
        
        return fixes_applied
    
    @classmethod
    def format_issues_report(cls, issues: List[ValidationIssue]) -> str:
        """Format issues as a readable report"""
        if not issues:
            return "No validation issues found."
        
        lines = []
        lines.append(f"\n{'='*60}")
        lines.append(f"VALIDATION ISSUES ({len(issues)} total)")
        lines.append(f"{'='*60}")
        
        # Group by severity
        errors = [i for i in issues if i.severity == 'error']
        warnings = [i for i in issues if i.severity == 'warning']
        infos = [i for i in issues if i.severity == 'info']
        
        if errors:
            lines.append(f"\n❌ ERRORS ({len(errors)}):")
            for issue in errors:
                lines.append(f"  [{issue.category}] {issue.message}")
                if issue.file_path:
                    lines.append(f"    File: {os.path.basename(issue.file_path)}:{issue.line_number or '?'}")
                if issue.suggestion:
                    lines.append(f"    Suggestion: {issue.suggestion}")
        
        if warnings:
            lines.append(f"\n⚠️  WARNINGS ({len(warnings)}):")
            for issue in warnings[:10]:  # Limit to 10 warnings
                lines.append(f"  [{issue.category}] {issue.message}")
                if issue.suggestion:
                    lines.append(f"    Suggestion: {issue.suggestion}")
            if len(warnings) > 10:
                lines.append(f"  ... and {len(warnings) - 10} more warnings")
        
        if infos:
            lines.append(f"\nℹ️  INFO ({len(infos)}):")
            for issue in infos[:5]:
                lines.append(f"  [{issue.category}] {issue.message}")
        
        return '\n'.join(lines)


def main():
    """Test compilation validator"""
    from project_detector import ProjectDetector
    
    print("Testing Compilation Validator")
    print("=" * 60)
    print("Note: This requires a real project to test properly")


if __name__ == "__main__":
    main()

