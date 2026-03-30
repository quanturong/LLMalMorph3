"""
Python language plugin for LLMalMorph.
Supports parsing and mutating Python code.
"""
import os
import re
from typing import List, Dict, Any, Optional, Tuple
from .base import Language, CodeStructure, Function, Class, Module

try:
    import tree_sitter_python as ts_python
    from tree_sitter import Language as TSLanguage, Parser
    PYTHON_AVAILABLE = True
except ImportError:
    PYTHON_AVAILABLE = False


class PythonLanguage(Language):
    """Python language plugin"""
    
    def __init__(self):
        self._parser = None
        self._language = None
        
        if PYTHON_AVAILABLE:
            try:
                # Try to load pre-built language
                self._language = TSLanguage(ts_python.language())
                self._parser = Parser(self._language)
            except Exception:
                # Fallback: try to build from source
                try:
                    from tree_sitter import Language
                    if os.path.exists("build/my-languages.so"):
                        self._language = Language("build/my-languages.so", "python")
                        self._parser = Parser(self._language)
                except Exception:
                    pass
    
    @property
    def name(self) -> str:
        return "python"
    
    @property
    def extensions(self) -> List[str]:
        return ['.py', '.pyw']
    
    def can_parse(self, content: str) -> bool:
        """Check if content is Python code"""
        # Check for Python-specific patterns
        patterns = [
            r'^#!/usr/bin/env python',
            r'^#!/usr/bin/python',
            r'^import\s+\w+',
            r'^from\s+\w+\s+import',
            r'def\s+\w+\s*\(',
            r'class\s+\w+',
        ]
        
        lines = content.split('\n')[:10]  # Check first 10 lines
        for line in lines:
            for pattern in patterns:
                if re.match(pattern, line.strip()):
                    return True
        
        return False
    
    def get_parser(self):
        """Get Python parser"""
        if self._parser is None:
            raise RuntimeError(
                "Python parser not available. "
                "Install tree-sitter-python: pip install tree-sitter-python"
            )
        return self._parser
    
    def parse(self, file_path: str, content: str) -> CodeStructure:
        """
        Parse Python code into CodeStructure.
        
        This is a simplified implementation. Full implementation would:
        - Parse imports
        - Parse functions (including async, decorators)
        - Parse classes and methods
        - Parse global variables
        - Handle Python-specific constructs
        """
        if not PYTHON_AVAILABLE:
            # Fallback: simple regex-based parsing
            return self._parse_simple(content)
        
        try:
            parser = self.get_parser()
            tree = parser.parse(bytes(content, 'utf8'))
            return self._parse_tree_sitter(tree, content)
        except Exception as e:
            # Fallback to simple parsing
            return self._parse_simple(content)
    
    def _parse_tree_sitter(self, tree, content: str) -> CodeStructure:
        """Parse using tree-sitter (full implementation needed)"""
        # TODO: Implement full tree-sitter parsing
        # This is a placeholder
        return self._parse_simple(content)
    
    def _parse_simple(self, content: str) -> CodeStructure:
        """Simple regex-based parsing (fallback)"""
        lines = content.split('\n')
        
        headers = []  # imports
        globals = []  # module-level variables
        functions = []
        classes = []
        
        current_function = None
        current_class = None
        in_function = False
        in_class = False
        indent_level = 0
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip empty lines and comments
            if not stripped or stripped.startswith('#'):
                continue
            
            # Parse imports
            if stripped.startswith('import ') or stripped.startswith('from '):
                headers.append(stripped)
                continue
            
            # Parse class definition
            class_match = re.match(r'^class\s+(\w+)(?:\([^)]+\))?:', stripped)
            if class_match:
                class_name = class_match.group(1)
                classes.append(Class(
                    name=class_name,
                    body=stripped,
                    start_line=i,
                    end_line=i,
                ))
                continue
            
            # Parse function definition
            func_match = re.match(
                r'^(?:async\s+)?(?:@\w+\s+)*def\s+(\w+)\s*\(([^)]*)\)\s*->\s*([^:]+)?:',
                stripped
            )
            if not func_match:
                func_match = re.match(
                    r'^(?:async\s+)?(?:@\w+\s+)*def\s+(\w+)\s*\(([^)]*)\):',
                    stripped
                )
            
            if func_match:
                func_name = func_match.group(1)
                params_str = func_match.group(2) if len(func_match.groups()) > 1 else ""
                return_type = func_match.group(3) if len(func_match.groups()) > 2 else "None"
                
                # Parse parameters
                parameters = []
                if params_str.strip():
                    for param in params_str.split(','):
                        param = param.strip()
                        if '=' in param:
                            param_name, default = param.split('=', 1)
                            parameters.append({
                                "name": param_name.strip(),
                                "type": "Any",  # Would need type hints
                                "default": default.strip()
                            })
                        else:
                            parameters.append({
                                "name": param.strip(),
                                "type": "Any"
                            })
                
                functions.append(Function(
                    name=func_name,
                    name_with_params=f"{func_name}({params_str})",
                    return_type=return_type,
                    parameters=parameters,
                    body=stripped,  # Simplified - would need full body extraction
                    start_line=i,
                    end_line=i,
                    is_async=stripped.startswith('async'),
                ))
                continue
        
        return CodeStructure(
            headers=headers,
            globals=globals,
            functions=functions,
            classes=classes,
            language=self.name
        )
    
    def get_system_prompt(self) -> str:
        """Python-specific system prompt"""
        return (
            "You are an intelligent Python coding assistant expert in "
            "writing, editing, refactoring and debugging Python code. "
            "You follow PEP 8 style guidelines and Python best practices. "
            "You specialize in systems programming and security research."
        )
    
    def get_mutation_prompt(
        self,
        num_functions: int,
        function_names: List[str],
        strategy: str = "optimization"
    ) -> str:
        """Python-specific mutation prompt"""
        func_list = ", ".join([f"***{name}***" for name in function_names])
        
        return f"""
Generate VARIANT(s) of {num_functions} Python function(s): {func_list}

Instructions:
1. Remove code redundancies and improve readability
2. Identify performance bottlenecks (use profiling if needed)
3. Simplify code logic using Pythonic idioms
4. Use modern Python features (type hints, f-strings, etc.)
5. Follow PEP 8 style guidelines
6. Maintain backward compatibility if needed

REMEMBER: 
- Maintain the same FUNCTIONALITY as the original code
- Keep function signatures compatible
- Preserve side effects and error handling
- Use appropriate Python standard library functions
"""
    
    def format_code_block(self, code: str) -> str:
        """Format Python code block"""
        return f"```python\n{code}\n```"
    
    def validate_syntax(self, code: str) -> Tuple[bool, Optional[str]]:
        """Validate Python syntax"""
        try:
            compile(code, '<string>', 'exec')
            return True, None
        except SyntaxError as e:
            return False, str(e)

