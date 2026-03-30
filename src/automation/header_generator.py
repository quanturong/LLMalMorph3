"""
Header File Generator
=====================
Generates and updates header files with missing declarations.
Prevents declaration duplication in source files.
"""
import os
import re
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class Declaration:
    """A function or variable declaration"""
    kind: str  # 'function', 'variable', 'typedef', 'struct', 'enum'
    name: str
    declaration: str
    source_file: Optional[str] = None


class HeaderGenerator:
    """Generate and update header files with missing declarations"""
    
    @classmethod
    def generate_project_header(
        cls,
        project,
        output_path: Optional[str] = None,
        header_name: str = "project_declarations.h"
    ) -> str:
        """
        Generate a comprehensive header file for the project.
        
        Args:
            project: MalwareProject object
            output_path: Directory to save header (default: project root)
            header_name: Name of the header file
            
        Returns:
            Path to generated header file
        """
        if not output_path:
            output_path = project.root_dir
        
        header_path = os.path.join(output_path, header_name)
        
        logger.info(f"Generating project header: {header_name}")
        
        # Collect all declarations from source files
        declarations = cls._collect_declarations(project)
        
        # Generate header content
        content = cls._generate_header_content(
            declarations,
            project.name,
            header_name
        )
        
        # Write header file
        with open(header_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info(f"  ✓ Generated: {header_path}")
        logger.info(f"  Functions: {sum(1 for d in declarations if d.kind == 'function')}")
        logger.info(f"  Types: {sum(1 for d in declarations if d.kind in ['struct', 'enum', 'typedef'])}")
        
        return header_path
    
    @classmethod
    def _collect_declarations(cls, project) -> List[Declaration]:
        """Collect all public declarations from source files"""
        declarations = []
        seen_names = set()
        
        # Patterns for extracting declarations
        func_pattern = re.compile(
            r'^\s*(?!static)([A-Za-z_][\w\s\*]+?)\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{',
            re.MULTILINE
        )
        
        struct_pattern = re.compile(
            r'^\s*typedef\s+struct\s+([A-Za-z_]\w*)?\s*\{[^}]+\}\s*([A-Za-z_]\w*)\s*;',
            re.MULTILINE | re.DOTALL
        )
        
        enum_pattern = re.compile(
            r'^\s*typedef\s+enum\s*\{[^}]+\}\s*([A-Za-z_]\w*)\s*;',
            re.MULTILINE | re.DOTALL
        )
        
        for source_file in project.source_files:
            try:
                with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Extract function definitions (non-static)
                for match in func_pattern.finditer(content):
                    return_type = match.group(1).strip()
                    func_name = match.group(2).strip()
                    params = match.group(3).strip()
                    
                    # Skip main/WinMain
                    if func_name in ['main', 'WinMain', 'wWinMain', '_start']:
                        continue
                    
                    if func_name not in seen_names:
                        declaration_str = f"{return_type} {func_name}({params});"
                        declarations.append(Declaration(
                            kind='function',
                            name=func_name,
                            declaration=declaration_str,
                            source_file=source_file
                        ))
                        seen_names.add(func_name)
                
                # Extract struct typedefs
                for match in struct_pattern.finditer(content):
                    struct_name = match.group(2).strip() if match.group(2) else match.group(1)
                    if struct_name and struct_name not in seen_names:
                        # Create forward declaration
                        declaration_str = f"typedef struct {struct_name} {struct_name};"
                        declarations.append(Declaration(
                            kind='typedef',
                            name=struct_name,
                            declaration=declaration_str,
                            source_file=source_file
                        ))
                        seen_names.add(struct_name)
                
                # Extract enum typedefs
                for match in enum_pattern.finditer(content):
                    enum_name = match.group(1).strip()
                    if enum_name and enum_name not in seen_names:
                        # Create forward declaration
                        declaration_str = f"typedef enum {enum_name} {enum_name};"
                        declarations.append(Declaration(
                            kind='typedef',
                            name=enum_name,
                            declaration=declaration_str,
                            source_file=source_file
                        ))
                        seen_names.add(enum_name)
            
            except Exception as e:
                logger.warning(f"Failed to collect declarations from {source_file}: {e}")
        
        return declarations
    
    @classmethod
    def _generate_header_content(
        cls,
        declarations: List[Declaration],
        project_name: str,
        header_name: str
    ) -> str:
        """Generate header file content"""
        lines = []
        
        # Header guard
        guard = f"_{header_name.upper().replace('.', '_').replace('-', '_')}_"
        
        lines.append(f"/*")
        lines.append(f" * Auto-generated header for project: {project_name}")
        lines.append(f" * This file contains forward declarations for all public functions and types.")
        lines.append(f" */")
        lines.append(f"")
        lines.append(f"#ifndef {guard}")
        lines.append(f"#define {guard}")
        lines.append(f"")
        
        # Common includes
        lines.append("/* Common system includes */")
        lines.append("#include <windows.h>")
        lines.append("#include <stdio.h>")
        lines.append("#include <stdlib.h>")
        lines.append("")
        
        # Group declarations by kind
        functions = [d for d in declarations if d.kind == 'function']
        types = [d for d in declarations if d.kind in ['typedef', 'struct', 'enum']]
        
        # Type declarations
        if types:
            lines.append("/* Type forward declarations */")
            for decl in types:
                lines.append(decl.declaration)
            lines.append("")
        
        # Function declarations
        if functions:
            lines.append("/* Function declarations */")
            for decl in functions:
                lines.append(decl.declaration)
            lines.append("")
        
        # End header guard
        lines.append(f"#endif /* {guard} */")
        lines.append("")
        
        return '\n'.join(lines)
    
    @classmethod
    def add_declarations_to_header(
        cls,
        header_path: str,
        new_declarations: List[str],
        section: str = "auto_generated"
    ) -> bool:
        """
        Add new declarations to an existing header file.
        
        Args:
            header_path: Path to header file
            new_declarations: List of declaration strings to add
            section: Section identifier for organization
            
        Returns:
            True if successful
        """
        if not os.path.exists(header_path):
            logger.error(f"Header file not found: {header_path}")
            return False
        
        if not new_declarations:
            return True
        
        try:
            with open(header_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Find insertion point (before #endif or at end)
            insertion_point = content.rfind('#endif')
            
            if insertion_point == -1:
                # No header guard, append at end
                insertion_point = len(content)
            else:
                # Find the newline before #endif
                while insertion_point > 0 and content[insertion_point - 1] in ['\n', '\r', ' ', '\t']:
                    insertion_point -= 1
            
            # Build new section
            new_section_lines = []
            new_section_lines.append(f"\n/* Auto-generated declarations - {section} */")
            for decl in new_declarations:
                if not decl.strip().endswith(';'):
                    decl += ';'
                new_section_lines.append(decl)
            new_section_lines.append("")
            
            new_section = '\n'.join(new_section_lines)
            
            # Insert new section
            modified_content = content[:insertion_point] + new_section + content[insertion_point:]
            
            # Write back
            with open(header_path, 'w', encoding='utf-8') as f:
                f.write(modified_content)
            
            logger.info(f"  ✓ Added {len(new_declarations)} declaration(s) to {os.path.basename(header_path)}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to add declarations to header: {e}")
            return False
    
    @classmethod
    def extract_missing_declarations_from_errors(
        cls,
        errors: List[str]
    ) -> List[str]:
        """
        Extract missing function/variable declarations from error messages.
        
        Args:
            errors: List of compilation error messages
            
        Returns:
            List of declaration stubs to add
        """
        declarations = []
        seen_names = set()
        
        # Pattern for undefined references
        undefined_pattern = re.compile(
            r"undefined reference to\s+[`'](.+?)'|"
            r"implicit declaration of function\s+[`'](.+?)'|"
            r"[`'](.+?)'\s+undeclared"
        )
        
        for error in errors:
            match = undefined_pattern.search(error)
            if match:
                # Get the symbol name from any of the groups
                symbol_name = next((g for g in match.groups() if g), None)
                
                if symbol_name and symbol_name not in seen_names:
                    seen_names.add(symbol_name)
                    
                    # Create a generic declaration
                    # For functions, create a void function with void params
                    if '(' not in symbol_name:
                        # Likely a function
                        declarations.append(f"void {symbol_name}(void);")
                    else:
                        # Complex symbol, create extern variable
                        declarations.append(f"extern void* {symbol_name};")
        
        return declarations
    
    @classmethod
    def create_stub_implementations(
        cls,
        declarations: List[str],
        output_path: str,
        stub_file_name: str = "stubs.c"
    ) -> str:
        """
        Create stub implementations for declarations.
        
        Args:
            declarations: List of function declarations
            output_path: Directory to save stub file
            stub_file_name: Name of the stub file
            
        Returns:
            Path to stub file
        """
        stub_path = os.path.join(output_path, stub_file_name)
        
        lines = []
        lines.append("/*")
        lines.append(" * Auto-generated stub implementations")
        lines.append(" */")
        lines.append("")
        lines.append("#include <stdio.h>")
        lines.append("#include <stdlib.h>")
        lines.append("")
        
        for decl in declarations:
            # Convert declaration to stub implementation
            if decl.strip().endswith(';'):
                decl = decl.strip()[:-1]  # Remove semicolon
            
            # Simple stub that just returns
            lines.append(f"{decl} {{")
            
            # Determine return type
            if decl.strip().startswith('void '):
                lines.append("    /* Stub implementation */")
                lines.append("    return;")
            elif decl.strip().startswith('int '):
                lines.append("    /* Stub implementation */")
                lines.append("    return 0;")
            elif '*' in decl.split('(')[0]:
                lines.append("    /* Stub implementation */")
                lines.append("    return NULL;")
            else:
                lines.append("    /* Stub implementation */")
            
            lines.append("}")
            lines.append("")
        
        content = '\n'.join(lines)
        
        with open(stub_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info(f"  ✓ Created stub implementations: {stub_path}")
        return stub_path


def main():
    """Test header generator"""
    from project_detector import ProjectDetector
    
    print("Testing Header Generator")
    print("=" * 60)
    print("Note: This requires a real project to test properly")


if __name__ == "__main__":
    main()

