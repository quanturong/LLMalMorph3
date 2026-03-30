"""
Project Auto-Fixer - Automatically Fix Compilation Errors
=========================================================
Automatically fixes compilation errors using LLM.

Features:
- Detect compilation errors
- Extract error context
- Generate fixes with LLM
- Apply fixes automatically
- Retry compilation
"""

import os
import re
import logging
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)


class ProjectAutoFixer:
    """Automatically fix compilation errors in projects"""
    
    def __init__(self, llm_model='codestral-2508', max_attempts=3):
        """
        Initialize auto-fixer
        
        Args:
            llm_model: LLM model to use for fixes
            max_attempts: Maximum fix attempts per error
        """
        self.llm_model = llm_model
        self.max_attempts = max_attempts
        self.fix_history = []
        
    def can_fix_error(self, error_message: str) -> bool:
        """
        Check if error is fixable
        
        Args:
            error_message: Compilation error message
            
        Returns:
            True if error can be fixed
        """
        # Fixable error patterns
        fixable_patterns = [
            r'undeclared identifier',
            r'was not declared in this scope',
            r'unknown type name',
            r'implicit declaration of function',
            r'conflicting types for',
            r'redefinition of',
            r'expected .* before',
            r'missing terminating',
            r'stray .* in program',
        ]
        
        for pattern in fixable_patterns:
            if re.search(pattern, error_message, re.IGNORECASE):
                return True
        
        return False
    
    def parse_compilation_errors(self, error_output: str) -> List[Dict]:
        """
        Parse compilation error output
        
        Args:
            error_output: Raw compiler error output
            
        Returns:
            List of parsed errors with file, line, and message
        """
        errors = []
        
        # Pattern: filepath:line:column: error: message
        error_pattern = r'([^:]+):(\d+):(\d+):\s*(error|fatal error):\s*(.+)'
        
        for match in re.finditer(error_pattern, error_output, re.MULTILINE):
            filepath = match.group(1)
            line_no = int(match.group(2))
            column = int(match.group(3))
            error_type = match.group(4)
            message = match.group(5)
            
            errors.append({
                'file': filepath,
                'line': line_no,
                'column': column,
                'type': error_type,
                'message': message,
                'fixable': self.can_fix_error(message)
            })
        
        return errors
    
    def get_error_context(self, filepath: str, line_no: int, context_lines: int = 5) -> str:
        """
        Get code context around error line
        
        Args:
            filepath: Path to file with error
            line_no: Line number of error
            context_lines: Number of lines before/after to include
            
        Returns:
            Code context as string
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            start = max(0, line_no - context_lines - 1)
            end = min(len(lines), line_no + context_lines)
            
            context = ''.join(lines[start:end])
            return context
            
        except Exception as e:
            logger.error(f"Could not read error context: {e}")
            return ""
    
    def generate_fix_with_llm(self, error_info: Dict, code_context: str) -> Optional[str]:
        """
        Generate fix using LLM
        
        Args:
            error_info: Error information
            code_context: Code context around error
            
        Returns:
            Fixed code or None
        """
        try:
            from pipeline_util import get_llm_name_from_input
            
            llm = get_llm_name_from_input(self.llm_model)
            
            system_prompt = (
                "You are an expert C/C++ compiler error fixer. "
                "Fix compilation errors while preserving code functionality. "
                "Return ONLY the fixed code, no explanations."
            )
            
            user_prompt = f"""
Compilation Error:
File: {error_info['file']}
Line: {error_info['line']}
Error: {error_info['message']}

Code Context:
```c
{code_context}
```

Fix this error and return the corrected code.
"""
            
            # Call LLM (simplified - you'd use proper API call)
            # For now, return None to indicate manual fix needed
            logger.warning(f"LLM fix generation not fully implemented")
            return None
            
        except Exception as e:
            logger.error(f"LLM fix generation failed: {e}")
            return None
    
    def apply_simple_fixes(self, errors: List[Dict], project) -> int:
        """
        Apply simple automatic fixes
        
        Args:
            errors: List of errors to fix
            project: MalwareProject object
            
        Returns:
            Number of fixes applied
        """
        fixes_applied = 0
        
        for error in errors:
            if not error['fixable']:
                continue
            
            message = error['message']
            filepath = error['file']
            
            # Fix 1: Add missing headers
            if 'was not declared' in message or 'undeclared identifier' in message:
                match = re.search(r"'([^']+)'", message)
                if match:
                    identifier = match.group(1)
                    fix = self._add_missing_declaration(filepath, identifier)
                    if fix:
                        fixes_applied += 1
                        logger.info(f"   ✓ Added declaration for: {identifier}")
            
            # Fix 2: Fix stray characters
            elif 'stray' in message and 'in program' in message:
                match = re.search(r"stray '(.+)' in program", message)
                if match:
                    char = match.group(1)
                    fix = self._remove_stray_character(filepath, error['line'], char)
                    if fix:
                        fixes_applied += 1
                        logger.info(f"   ✓ Removed stray character: {char}")
            
            # Fix 3: Add missing semicolons
            elif 'expected' in message and 'before' in message:
                fix = self._add_missing_semicolon(filepath, error['line'])
                if fix:
                    fixes_applied += 1
                    logger.info(f"   ✓ Added missing semicolon")
        
        return fixes_applied
    
    def _add_missing_declaration(self, filepath: str, identifier: str) -> bool:
        """Add missing variable/function declaration"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check if it's a common Windows type
            windows_types = {
                'DWORD': '#include <windows.h>',
                'HANDLE': '#include <windows.h>',
                'BOOL': '#include <windows.h>',
                'LPSTR': '#include <windows.h>',
                'HINSTANCE': '#include <windows.h>',
            }
            
            if identifier in windows_types:
                # Check if header already included
                if windows_types[identifier] not in content:
                    # Add header at top
                    new_content = windows_types[identifier] + '\n' + content
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Could not add declaration: {e}")
            return False
    
    def _remove_stray_character(self, filepath: str, line_no: int, char: str) -> bool:
        """Remove stray character from line"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            if 0 < line_no <= len(lines):
                # Remove the stray character
                lines[line_no - 1] = lines[line_no - 1].replace(char, '')
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.writelines(lines)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Could not remove stray character: {e}")
            return False
    
    def _add_missing_semicolon(self, filepath: str, line_no: int) -> bool:
        """Add missing semicolon"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            if 0 < line_no <= len(lines):
                line = lines[line_no - 1].rstrip()
                if not line.endswith(';') and not line.endswith('{') and not line.endswith('}'):
                    lines[line_no - 1] = line + ';\n'
                    
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.writelines(lines)
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Could not add semicolon: {e}")
            return False
    
    def fix_compilation_errors(
        self,
        project,
        error_output: str,
        attempt: int = 1
    ) -> Tuple[bool, int]:
        """
        Attempt to fix compilation errors
        
        Args:
            project: MalwareProject object
            error_output: Compiler error output
            attempt: Current fix attempt number
            
        Returns:
            (success, fixes_applied) tuple
        """
        logger.info(f"\n🔧 AUTO-FIX ATTEMPT {attempt}/{self.max_attempts}")
        logger.info("="*60)
        
        # Parse errors
        errors = self.parse_compilation_errors(error_output)
        
        if not errors:
            logger.warning("   No parseable errors found")
            return False, 0
        
        logger.info(f"   Found {len(errors)} errors")
        
        # Count fixable errors
        fixable = sum(1 for e in errors if e['fixable'])
        logger.info(f"   Fixable: {fixable}/{len(errors)}")
        
        if fixable == 0:
            logger.warning("   No fixable errors")
            return False, 0
        
        # Apply simple fixes
        fixes_applied = self.apply_simple_fixes(errors, project)
        
        logger.info(f"\n   ✅ Applied {fixes_applied} fixes")
        
        # Record fix attempt
        self.fix_history.append({
            'attempt': attempt,
            'errors': len(errors),
            'fixable': fixable,
            'fixes_applied': fixes_applied,
        })
        
        return fixes_applied > 0, fixes_applied
    
    def get_fix_summary(self) -> Dict:
        """Get summary of all fix attempts"""
        if not self.fix_history:
            return {
                'total_attempts': 0,
                'total_fixes': 0,
            }
        
        return {
            'total_attempts': len(self.fix_history),
            'total_fixes': sum(h['fixes_applied'] for h in self.fix_history),
            'history': self.fix_history,
        }


def main():
    """Test auto-fixer"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python project_auto_fixer.py <error_log_file>")
        sys.exit(1)
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s'
    )
    
    error_file = sys.argv[1]
    
    with open(error_file, 'r') as f:
        error_output = f.read()
    
    fixer = ProjectAutoFixer()
    errors = fixer.parse_compilation_errors(error_output)
    
    print(f"\n📋 Parsed {len(errors)} errors:")
    for i, error in enumerate(errors, 1):
        fixable = "✅" if error['fixable'] else "❌"
        print(f"{i}. {fixable} Line {error['line']}: {error['message'][:80]}")


if __name__ == "__main__":
    main()

