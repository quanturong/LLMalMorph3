"""
C++ language plugin - wraps existing C++ parser.
Maintains backward compatibility.
"""
import re
from typing import List
from .base import Language, CodeStructure
import sys
import os

# Add parent directory to path to import existing parser
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from tree_sitter_parser import (
        initialize_parser,
        read_source_code,
        extract_functions_globals_headers,
    )
    CPP_PARSER_AVAILABLE = True
except ImportError:
    CPP_PARSER_AVAILABLE = False


class CppLanguage(Language):
    """C++ language plugin - wraps existing parser"""
    
    @property
    def name(self) -> str:
        return "cpp"
    
    @property
    def extensions(self) -> List[str]:
        return ['.cpp', '.cxx', '.cc', '.hpp', '.h']
    
    def can_parse(self, content: str) -> bool:
        """Check if content is C++ code"""
        patterns = [
            r'#include\s*<',
            r'#include\s*"',
            r'using\s+namespace',
            r'class\s+\w+',
            r'std::',
            r'namespace\s+\w+',
        ]
        
        lines = content.split('\n')[:10]
        for line in lines:
            for pattern in patterns:
                if re.match(pattern, line.strip()):
                    return True
        return False
    
    def get_parser(self):
        """Get C++ parser"""
        if not CPP_PARSER_AVAILABLE:
            raise RuntimeError("C++ parser not available")
        return None
    
    def parse(self, file_path: str, content: str) -> CodeStructure:
        """Parse C++ code using existing parser"""
        if not CPP_PARSER_AVAILABLE:
            raise RuntimeError("C++ parser not available")
        
        parser = initialize_parser(file_path)
        tree = parser.parse(bytes(content, 'utf8'))
        headers, globals, functions, classes, structs = extract_functions_globals_headers(content, tree)
        
        # Convert to unified structure
        from .base import Function, Class
        
        func_objects = []
        for func in functions:
            func_objects.append(Function(
                name=func['name_only'],
                name_with_params=func['name_with_params'],
                return_type=func['return_type'],
                parameters=[],  # Would need to parse parameters
                body=func['body'],
                start_line=func['start_line'],
                end_line=func['end_line'],
            ))
        
        class_objects = []
        for cls in classes:
            class_objects.append(Class(
                name=cls['name'],
                body=cls['body'],
                start_line=cls['start_line'],
                end_line=cls['end_line'],
            ))
        
        return CodeStructure(
            headers=headers,
            globals=globals,
            functions=func_objects,
            classes=class_objects,
            language=self.name
        )
    
    def get_system_prompt(self) -> str:
        """C++-specific system prompt"""
        return (
            "You are an intelligent C++ coding assistant expert in "
            "writing, editing, refactoring and debugging C++ code. "
            "You listen to exact instructions and specialize in "
            "systems programming and use of C++ language with Windows platforms."
        )

