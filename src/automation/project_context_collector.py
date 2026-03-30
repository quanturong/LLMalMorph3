"""
Project Context Collector
==========================
Collects comprehensive context about the project to help LLM auto-fixer.
Provides information about:
- Other files in the project
- Existing function definitions
- Header file declarations
- Cross-file dependencies
"""
import os
import re
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class FunctionSignature:
    """Function signature information"""
    name: str
    return_type: str
    parameters: str
    file_path: str
    line_number: int
    is_declaration: bool = False
    is_definition: bool = False


@dataclass
class TypeDefinition:
    """Type definition (struct, enum, union, typedef)"""
    type_kind: str  # struct, enum, union, typedef
    name: str
    file_path: str
    line_number: int
    definition: str


@dataclass
class ProjectContext:
    """Complete project context"""
    project_name: str
    source_files: List[str]
    header_files: List[str]
    functions: Dict[str, List[FunctionSignature]]
    types: Dict[str, TypeDefinition]
    includes: Dict[str, List[str]]  # file -> list of includes
    global_variables: Dict[str, str]  # name -> declaration
    dependencies: Dict[str, Set[str]]  # file -> dependent files
    
    def to_context_string(self, max_length: int = 10000) -> str:
        """Convert to string for LLM context"""
        lines = []
        
        lines.append("=== PROJECT CONTEXT ===")
        lines.append(f"Project: {self.project_name}")
        lines.append(f"Source files: {len(self.source_files)}")
        lines.append(f"Header files: {len(self.header_files)}")
        lines.append("")
        
        # Add function signatures
        if self.functions:
            lines.append("--- AVAILABLE FUNCTIONS ---")
            count = 0
            for func_name, signatures in list(self.functions.items())[:50]:  # Limit to 50 functions
                for sig in signatures[:1]:  # First signature only
                    lines.append(f"{sig.return_type} {sig.name}({sig.parameters});")
                    count += 1
                    if count >= 30:  # Limit total signatures
                        break
                if count >= 30:
                    break
            if len(self.functions) > 50:
                lines.append(f"... and {len(self.functions) - 50} more functions")
            lines.append("")
        
        # Add type definitions
        if self.types:
            lines.append("--- AVAILABLE TYPES ---")
            for type_name in list(self.types.keys())[:30]:  # Limit to 30 types
                type_def = self.types[type_name]
                lines.append(f"{type_def.type_kind} {type_name}")
            if len(self.types) > 30:
                lines.append(f"... and {len(self.types) - 30} more types")
            lines.append("")
        
        # Add global variables
        if self.global_variables:
            lines.append("--- GLOBAL VARIABLES ---")
            for var_name, var_decl in list(self.global_variables.items())[:20]:
                lines.append(var_decl)
            if len(self.global_variables) > 20:
                lines.append(f"... and {len(self.global_variables) - 20} more variables")
            lines.append("")
        
        context_str = "\n".join(lines)
        
        # Truncate if too long
        if len(context_str) > max_length:
            context_str = context_str[:max_length] + "\n... (truncated)"
        
        return context_str


class ProjectContextCollector:
    """Collect context about the project"""
    
    # Regex patterns
    FUNCTION_PATTERN = re.compile(
        r'^\s*([A-Za-z_][\w\s\*]*?)\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*[{;]',
        re.MULTILINE
    )
    
    STRUCT_PATTERN = re.compile(
        r'^\s*(struct|enum|union)\s+([A-Za-z_]\w*)\s*[{;]',
        re.MULTILINE
    )
    
    TYPEDEF_PATTERN = re.compile(
        r'^\s*typedef\s+.*?\s+([A-Za-z_]\w*)\s*;',
        re.MULTILINE
    )
    
    INCLUDE_PATTERN = re.compile(
        r'^\s*#\s*include\s+[<"]([^>"]+)[>"]',
        re.MULTILINE
    )
    
    GLOBAL_VAR_PATTERN = re.compile(
        r'^\s*(?:extern\s+)?([A-Za-z_][\w\s\*]+?)\s+([A-Za-z_]\w*)\s*(?:=|;)',
        re.MULTILINE
    )
    
    @classmethod
    def collect_project_context(cls, project, parse_result=None) -> ProjectContext:
        """
        Collect complete project context.
        
        Args:
            project: MalwareProject object
            parse_result: Optional ProjectParseResult for enhanced info
            
        Returns:
            ProjectContext object
        """
        logger.info("Collecting project context...")
        
        context = ProjectContext(
            project_name=project.name,
            source_files=project.source_files.copy(),
            header_files=project.header_files.copy(),
            functions={},
            types={},
            includes={},
            global_variables={},
            dependencies={}
        )
        
        # Collect from headers first (declarations)
        for header_file in project.header_files:
            cls._parse_header_file(header_file, context)
        
        # Collect from source files (definitions)
        for source_file in project.source_files:
            cls._parse_source_file(source_file, context)
        
        # Use parse_result if available for better info
        if parse_result:
            cls._enhance_with_parse_result(parse_result, context)
        
        # Build dependency graph
        cls._build_dependency_graph(context)
        
        logger.info(f"  Functions: {len(context.functions)}")
        logger.info(f"  Types: {len(context.types)}")
        logger.info(f"  Global vars: {len(context.global_variables)}")
        
        return context
    
    @classmethod
    def _parse_header_file(cls, file_path: str, context: ProjectContext):
        """Parse header file for declarations"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract includes
            includes = cls.INCLUDE_PATTERN.findall(content)
            context.includes[file_path] = includes
            
            # Extract function declarations
            for match in cls.FUNCTION_PATTERN.finditer(content):
                return_type = match.group(1).strip()
                func_name = match.group(2).strip()
                params = match.group(3).strip()
                line_num = content[:match.start()].count('\n') + 1
                
                # Skip if it's a definition (has '{')
                is_declaration = ';' in content[match.start():match.end() + 1]
                
                sig = FunctionSignature(
                    name=func_name,
                    return_type=return_type,
                    parameters=params,
                    file_path=file_path,
                    line_number=line_num,
                    is_declaration=is_declaration,
                    is_definition=not is_declaration
                )
                
                if func_name not in context.functions:
                    context.functions[func_name] = []
                context.functions[func_name].append(sig)
            
            # Extract type definitions
            for match in cls.STRUCT_PATTERN.finditer(content):
                type_kind = match.group(1)
                type_name = match.group(2)
                line_num = content[:match.start()].count('\n') + 1
                
                context.types[type_name] = TypeDefinition(
                    type_kind=type_kind,
                    name=type_name,
                    file_path=file_path,
                    line_number=line_num,
                    definition=match.group(0)
                )
            
            # Extract typedefs
            for match in cls.TYPEDEF_PATTERN.finditer(content):
                type_name = match.group(1)
                line_num = content[:match.start()].count('\n') + 1
                
                if type_name not in context.types:
                    context.types[type_name] = TypeDefinition(
                        type_kind='typedef',
                        name=type_name,
                        file_path=file_path,
                        line_number=line_num,
                        definition=match.group(0)
                    )
        
        except Exception as e:
            logger.warning(f"Failed to parse header {file_path}: {e}")
    
    @classmethod
    def _parse_source_file(cls, file_path: str, context: ProjectContext):
        """Parse source file for definitions"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract includes
            includes = cls.INCLUDE_PATTERN.findall(content)
            context.includes[file_path] = includes
            
            # Extract function definitions (with body)
            for match in cls.FUNCTION_PATTERN.finditer(content):
                return_type = match.group(1).strip()
                func_name = match.group(2).strip()
                params = match.group(3).strip()
                line_num = content[:match.start()].count('\n') + 1
                
                # Check if it's a definition (has '{')
                is_definition = '{' in content[match.start():match.end() + 10]
                
                if is_definition:
                    sig = FunctionSignature(
                        name=func_name,
                        return_type=return_type,
                        parameters=params,
                        file_path=file_path,
                        line_number=line_num,
                        is_declaration=False,
                        is_definition=True
                    )
                    
                    if func_name not in context.functions:
                        context.functions[func_name] = []
                    context.functions[func_name].append(sig)
        
        except Exception as e:
            logger.warning(f"Failed to parse source {file_path}: {e}")
    
    @classmethod
    def _enhance_with_parse_result(cls, parse_result, context: ProjectContext):
        """Enhance context with parse result data"""
        try:
            # Use parsed function information if available
            for file_path, file_info in parse_result.file_results.items():
                for func in file_info.get('functions', []):
                    func_name = func.get('name_only', '')
                    if func_name and func_name not in context.functions:
                        # Add from parse result
                        sig = FunctionSignature(
                            name=func_name,
                            return_type=func.get('return_type', 'void'),
                            parameters=func.get('parameters', ''),
                            file_path=file_path,
                            line_number=func.get('start_line', 0),
                            is_definition=True
                        )
                        context.functions[func_name] = [sig]
        
        except Exception as e:
            logger.warning(f"Failed to enhance with parse result: {e}")
    
    @classmethod
    def _build_dependency_graph(cls, context: ProjectContext):
        """Build file dependency graph based on includes"""
        for file_path, includes in context.includes.items():
            deps = set()
            
            # Find actual header files that match the includes
            for include in includes:
                include_basename = os.path.basename(include)
                for header_file in context.header_files:
                    if os.path.basename(header_file) == include_basename:
                        deps.add(header_file)
                        break
            
            context.dependencies[file_path] = deps
    
    @classmethod
    def get_file_context(cls, file_path: str, context: ProjectContext, max_length: int = 5000) -> str:
        """
        Get context specific to a single file.
        
        Args:
            file_path: Path to the file
            context: Project context
            max_length: Maximum context length
            
        Returns:
            Context string for the file
        """
        lines = []
        
        lines.append(f"=== CONTEXT FOR: {os.path.basename(file_path)} ===")
        
        # Add file includes
        if file_path in context.includes:
            lines.append("\n--- INCLUDES IN THIS FILE ---")
            for include in context.includes[file_path]:
                lines.append(f"#include \"{include}\"")
        
        # Add dependencies
        if file_path in context.dependencies:
            deps = context.dependencies[file_path]
            if deps:
                lines.append("\n--- DEPENDENT HEADERS ---")
                for dep in list(deps)[:10]:
                    lines.append(f"  - {os.path.basename(dep)}")
        
        # Add functions defined in this file
        file_functions = [
            sig for func_list in context.functions.values()
            for sig in func_list
            if sig.file_path == file_path
        ]
        
        if file_functions:
            lines.append("\n--- FUNCTIONS IN THIS FILE ---")
            for sig in file_functions[:20]:
                lines.append(f"{sig.return_type} {sig.name}({sig.parameters});")
        
        context_str = "\n".join(lines)
        
        if len(context_str) > max_length:
            context_str = context_str[:max_length] + "\n... (truncated)"
        
        return context_str
    
    @classmethod
    def find_cross_file_references(cls, context: ProjectContext) -> Dict[str, Set[str]]:
        """
        Find functions that are referenced across multiple files.
        
        Returns:
            Dict mapping function name to set of files that reference it
        """
        cross_refs = {}
        
        for func_name, signatures in context.functions.items():
            files = set(sig.file_path for sig in signatures)
            if len(files) > 1:
                cross_refs[func_name] = files
        
        return cross_refs


def main():
    """Test project context collector"""
    from project_detector import ProjectDetector
    
    print("Testing Project Context Collector")
    print("=" * 60)
    
    # This would need a real project to test
    print("Note: This requires a real project to test properly")


if __name__ == "__main__":
    main()

