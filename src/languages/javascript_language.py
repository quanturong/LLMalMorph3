"""
JavaScript language plugin for LLMalMorph.
Supports parsing and mutating JavaScript/Node.js code.
"""
import os
import re
from typing import List, Dict, Any, Optional
from .base import Language, CodeStructure, Function, Class, Module


class JavaScriptLanguage(Language):
    """JavaScript/Node.js language plugin"""

    def __init__(self):
        self._parser = None

    @property
    def name(self) -> str:
        return "javascript"

    @property
    def extensions(self) -> List[str]:
        return ['.js', '.mjs']

    def can_parse(self, content: str) -> bool:
        """Check if content is JavaScript code"""
        patterns = [
            r'^\s*const\s+\w+\s*=\s*require\s*\(',
            r'^\s*import\s+.*\s+from\s+',
            r'^\s*module\.exports\s*=',
            r'^\s*exports\.\w+\s*=',
            r'^\s*function\s+\w+\s*\(',
            r'^\s*var\s+\w+\s*=\s*function',
            r'^\s*const\s+\w+\s*=\s*\(',
            r'^\s*class\s+\w+',
        ]
        lines = content.split('\n')[:15]
        for line in lines:
            for pattern in patterns:
                if re.match(pattern, line.strip()):
                    return True
        return False

    def get_parser(self):
        """No tree-sitter parser; uses regex fallback."""
        return None

    def parse(self, file_path: str, content: str) -> CodeStructure:
        """Parse JavaScript code into CodeStructure using regex."""
        return self._parse_simple(content)

    def _parse_simple(self, content: str) -> CodeStructure:
        """Regex-based JavaScript parsing."""
        lines = content.split('\n')
        headers = []
        globals_list = []
        functions = []
        classes = []

        i = 0
        while i < len(lines):
            stripped = lines[i].strip()

            # Skip empty / comments
            if not stripped or stripped.startswith('//'):
                i += 1
                continue

            # require / import
            if re.match(r"^(?:const|let|var)\s+.*=\s*require\s*\(", stripped) or \
               re.match(r"^import\s+", stripped):
                headers.append(stripped)
                i += 1
                continue

            # Class definition
            cls_match = re.match(r'^class\s+(\w+)', stripped)
            if cls_match:
                classes.append(Class(
                    name=cls_match.group(1),
                    body=stripped,
                    start_line=i + 1,
                    end_line=i + 1,
                ))
                i += 1
                continue

            # Named function: function name(...)
            func_match = re.match(
                r'^(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)', stripped
            )
            # Arrow / const function: const name = (...) => or const name = function(...)
            if not func_match:
                func_match = re.match(
                    r'^(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function\s*)?\(([^)]*)\)',
                    stripped,
                )
            # Method shorthand inside object: name(...) {
            if not func_match:
                func_match = re.match(
                    r'^(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{', stripped
                )

            if func_match:
                func_name = func_match.group(1)
                params_str = func_match.group(2) if func_match.lastindex >= 2 else ""
                start_line = i + 1

                # Find function end by brace counting
                brace_count = stripped.count('{') - stripped.count('}')
                end_idx = i
                if brace_count > 0:
                    for j in range(i + 1, len(lines)):
                        brace_count += lines[j].count('{') - lines[j].count('}')
                        end_idx = j
                        if brace_count <= 0:
                            break

                body = '\n'.join(lines[i:end_idx + 1])
                parameters = []
                if params_str.strip():
                    for param in params_str.split(','):
                        param = param.strip()
                        if '=' in param:
                            pname, default = param.split('=', 1)
                            parameters.append({"name": pname.strip(), "type": "any", "default": default.strip()})
                        else:
                            parameters.append({"name": param, "type": "any"})

                functions.append(Function(
                    name=func_name,
                    name_with_params=f"{func_name}({params_str})",
                    return_type="any",
                    parameters=parameters,
                    body=body,
                    start_line=start_line,
                    end_line=end_idx + 1,
                    is_async='async' in stripped,
                ))
                i = end_idx + 1
                continue

            # Global variable
            gvar_match = re.match(r'^(?:const|let|var)\s+(\w+)\s*=', stripped)
            if gvar_match:
                globals_list.append(stripped)

            i += 1

        return CodeStructure(
            headers=headers,
            globals=globals_list,
            functions=functions,
            classes=classes,
            language=self.name,
        )

    def get_system_prompt(self) -> str:
        """JavaScript-specific system prompt"""
        return (
            "You are a JavaScript/Node.js code transformation expert. "
            "You specialize in writing, editing, refactoring and debugging JavaScript code. "
            "You follow best practices and maintain identical functionality."
        )
