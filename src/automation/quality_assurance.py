"""
Quality Assurance module for LLMalMorph.
Checks code quality, security, and functionality preservation.
"""
import subprocess
import logging
import tempfile
import os
import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class IssueSeverity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class QualityIssue:
    """Represents a code quality issue"""
    severity: IssueSeverity
    message: str
    line: Optional[int] = None
    column: Optional[int] = None
    rule: Optional[str] = None
    file: Optional[str] = None


class QualityAssurance:
    """
    Quality assurance checks for generated code.
    Includes syntax validation, security checks, and functionality verification.
    """
    
    def __init__(self, language: str = "c"):
        """
        Initialize QA module.
        
        Args:
            language: Programming language
        """
        self.language = language.lower()
        logger.info(f"Initialized QA for language: {language}")
    
    def check_syntax(self, code: str, file_path: Optional[str] = None) -> Tuple[bool, List[QualityIssue]]:
        """
        Check syntax correctness.
        
        Args:
            code: Source code to check
            file_path: Optional file path (for better error messages)
        
        Returns:
            Tuple of (is_valid, issues)
        """
        issues = []
        
        if self.language == "python":
            return self._check_python_syntax(code, file_path)
        elif self.language in ["c", "cpp"]:
            return self._check_c_syntax(code, file_path)
        else:
            logger.warning(f"Syntax checking not implemented for {self.language}")
            return True, []
    
    def _check_python_syntax(self, code: str, file_path: Optional[str]) -> Tuple[bool, List[QualityIssue]]:
        """Check Python syntax"""
        issues = []
        
        try:
            compile(code, file_path or '<string>', 'exec')
            return True, []
        except SyntaxError as e:
            issues.append(QualityIssue(
                severity=IssueSeverity.ERROR,
                message=str(e),
                line=e.lineno,
                column=e.offset,
                file=file_path,
            ))
            return False, issues
        except Exception as e:
            issues.append(QualityIssue(
                severity=IssueSeverity.ERROR,
                message=f"Syntax check error: {e}",
                file=file_path,
            ))
            return False, issues
    
    def _check_c_syntax(self, code: str, file_path: Optional[str]) -> Tuple[bool, List[QualityIssue]]:
        """Check C/C++ syntax using compiler"""
        issues = []
        
        # Write to temp file
        temp_dir = tempfile.gettempdir()
        os.makedirs(temp_dir, exist_ok=True)
        
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.c' if self.language == 'c' else '.cpp',
            delete=False,
            dir=temp_dir
        ) as f:
            f.write(code)
            f.flush()  # Ensure data is written
            temp_file = f.name
        
        # Verify file exists
        if not os.path.exists(temp_file):
            issues.append(QualityIssue(
                severity=IssueSeverity.ERROR,
                message=f"Failed to create temp file for syntax check: {temp_file}",
            ))
            return False, issues
        
        try:
            # Use compiler to check syntax only (no linking)
            compiler = 'gcc' if self.language == 'c' else 'g++'
            cmd = [compiler, '-fsyntax-only', '-Wall', '-Wextra', temp_file]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            if result.returncode == 0:
                return True, []
            
            # Parse errors
            for line in result.stderr.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # Parse compiler error format
                # Example: "file.c:5:10: error: ..."
                match = re.match(r'(.+):(\d+):(\d+):\s*(error|warning):\s*(.+)', line)
                if match:
                    file, line_num, col, severity, message = match.groups()
                    # Check if it's a missing header file error
                    # These are often expected for standalone files and can be auto-fixed
                    is_missing_header = (
                        'no such file or directory' in message.lower() or
                        'fatal error' in severity.lower() and 'no such file' in message.lower()
                    )
                    
                    # Missing headers are warnings (can be auto-fixed), other errors are errors
                    issue_severity = IssueSeverity.WARNING if is_missing_header else (
                        IssueSeverity.ERROR if severity == 'error' else IssueSeverity.WARNING
                    )
                    
                    issues.append(QualityIssue(
                        severity=issue_severity,
                        message=message,
                        line=int(line_num),
                        column=int(col),
                        file=file,
                    ))
                else:
                    # Generic error
                    if 'error:' in line.lower():
                        # Check if it's a missing header
                        is_missing_header = 'no such file' in line.lower()
                        issues.append(QualityIssue(
                            severity=IssueSeverity.WARNING if is_missing_header else IssueSeverity.ERROR,
                            message=line,
                        ))
            
            return False, issues
        
        except Exception as e:
            logger.error(f"Syntax check error: {e}")
            return False, [QualityIssue(
                severity=IssueSeverity.ERROR,
                message=f"Syntax check failed: {e}",
            )]
        
        finally:
            # Cleanup temp file safely
            try:
                if 'temp_file' in locals() and os.path.exists(temp_file):
                    os.remove(temp_file)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp file in syntax check: {e}")
    
    def check_security(self, code: str, file_path: Optional[str] = None) -> List[QualityIssue]:
        """
        Check for security issues.
        
        Args:
            code: Source code to check
            file_path: Optional file path
        
        Returns:
            List of security issues
        """
        issues = []
        
        # Basic security checks
        security_patterns = {
            'c': [
                (r'strcpy\s*\(', 'Use of unsafe strcpy(), consider strncpy() or strcpy_s()'),
                (r'gets\s*\(', 'Use of unsafe gets(), use fgets() instead'),
                (r'sprintf\s*\(', 'Use of unsafe sprintf(), consider snprintf()'),
                (r'scanf\s*\(', 'Use of unsafe scanf(), consider fgets() + sscanf()'),
            ],
            'cpp': [
                (r'strcpy\s*\(', 'Use of unsafe strcpy(), use std::string instead'),
                (r'gets\s*\(', 'Use of unsafe gets(), use std::getline() instead'),
            ],
            'python': [
                (r'eval\s*\(', 'Use of eval() is dangerous'),
                (r'exec\s*\(', 'Use of exec() is dangerous'),
                (r'__import__\s*\(', 'Direct use of __import__() is dangerous'),
            ],
        }
        
        patterns = security_patterns.get(self.language, [])
        
        for i, line in enumerate(code.split('\n'), 1):
            for pattern, message in patterns:
                if re.search(pattern, line):
                    issues.append(QualityIssue(
                        severity=IssueSeverity.WARNING,
                        message=message,
                        line=i,
                        file=file_path,
                        rule='security',
                    ))
        
        return issues
    
    def verify_functionality(
        self,
        original_code: str,
        variant_code: str,
        test_cases: Optional[List[Dict]] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Verify that variant preserves functionality.
        
        Args:
            original_code: Original code
            variant_code: Variant code
            test_cases: Optional test cases
        
        Returns:
            Tuple of (preserves_functionality, issues)
        """
        issues = []
        
        # Basic checks
        # 1. Check if function signatures match
        original_funcs = self._extract_functions(original_code)
        variant_funcs = self._extract_functions(variant_code)
        
        if len(original_funcs) != len(variant_funcs):
            issues.append(
                f"Function count mismatch: original has {len(original_funcs)}, "
                f"variant has {len(variant_funcs)}"
            )
        
        # 2. Check function names match
        original_names = {f['name'] for f in original_funcs}
        variant_names = {f['name'] for f in variant_funcs}
        
        if original_names != variant_names:
            missing = original_names - variant_names
            extra = variant_names - original_names
            if missing:
                issues.append(f"Missing functions: {missing}")
            if extra:
                issues.append(f"Extra functions: {extra}")
        
        # 3. If test cases provided, run them
        if test_cases:
            # Would need to compile and run both versions
            # This is a placeholder
            pass
        
        return len(issues) == 0, issues
    
    def _extract_functions(self, code: str) -> List[Dict]:
        """Extract function information from code"""
        functions = []
        
        if self.language == 'c':
            # Match C function definitions
            pattern = r'(\w+\s+\w+\s*\([^)]*\))\s*\{'
            for match in re.finditer(pattern, code):
                functions.append({
                    'name': match.group(1).split('(')[0].split()[-1],
                    'signature': match.group(1),
                })
        elif self.language == 'python':
            # Match Python function definitions
            pattern = r'def\s+(\w+)\s*\([^)]*\):'
            for match in re.finditer(pattern, code):
                functions.append({
                    'name': match.group(1),
                    'signature': match.group(0),
                })
        
        return functions
    
    def get_quality_score(self, code: str) -> float:
        """
        Calculate overall quality score (0.0 - 1.0).
        
        Args:
            code: Source code
        
        Returns:
            Quality score
        """
        is_valid, syntax_issues = self.check_syntax(code)
        security_issues = self.check_security(code)
        
        if not is_valid:
            return 0.0
        
        # Calculate score based on issues
        total_issues = len(syntax_issues) + len(security_issues)
        
        # Simple scoring: fewer issues = higher score
        # Max score is 1.0, reduce by 0.1 per issue (min 0.0)
        score = max(0.0, 1.0 - (total_issues * 0.1))
        
        return score

