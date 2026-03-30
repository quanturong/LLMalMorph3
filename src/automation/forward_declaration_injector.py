"""
Forward Declaration Injector
============================
Automatically injects forward declarations for missing symbols.
"""
import os
import re
from typing import List, Dict, Set, Tuple
import logging

logger = logging.getLogger(__name__)


class ForwardDeclarationInjector:
    """Inject forward declarations for missing symbols"""
    
    @classmethod
    def inject_declarations(
        cls,
        source_file_path: str,
        missing_symbols: Set[str],
        project_declarations: Dict[str, str]
    ) -> bool:
        """
        Inject forward declarations for missing symbols into a source file.
        
        Args:
            source_file_path: Path to source file
            missing_symbols: Set of missing symbol names
            project_declarations: Dict mapping symbol names to their declarations
            
        Returns:
            True if successful
        """
        if not missing_symbols:
            return True
        
        try:
            with open(source_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Find insertion point (after last #include)
            insertion_point = cls._find_insertion_point(content)
            
            # Build forward declarations block
            declarations_block = cls._build_declarations_block(
                missing_symbols,
                project_declarations
            )
            
            if not declarations_block:
                logger.info(f"No declarations to inject for {os.path.basename(source_file_path)}")
                return True
            
            # Insert declarations
            new_content = (
                content[:insertion_point] +
                declarations_block +
                content[insertion_point:]
            )
            
            # Write modified file
            with open(source_file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            logger.info(f"✓ Injected {len(declarations_block.splitlines())} declarations into {os.path.basename(source_file_path)}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to inject declarations: {e}")
            return False
    
    @classmethod
    def _find_insertion_point(cls, content: str) -> int:
        """Find best insertion point for forward declarations"""
        
        # Find last #include
        include_matches = list(re.finditer(r'#\s*include\s+[<"][^>"]+[>"]', content))
        
        if include_matches:
            # Insert after last include
            last_include = include_matches[-1]
            insertion_point = content.find('\n', last_include.end()) + 1
        else:
            # No includes, insert at beginning after any initial comments
            # Skip initial comment block
            match = re.search(r'^/\*.*?\*/', content, re.DOTALL)
            if match:
                insertion_point = match.end()
                # Find next newline
                nl = content.find('\n', insertion_point)
                if nl != -1:
                    insertion_point = nl + 1
            else:
                insertion_point = 0
        
        return insertion_point
    
    @classmethod
    def _build_declarations_block(
        cls,
        missing_symbols: Set[str],
        project_declarations: Dict[str, str]
    ) -> str:
        """Build forward declarations block"""
        
        lines = [
            "\n/* Auto-injected forward declarations */\n"
        ]
        
        found_count = 0
        for symbol in sorted(missing_symbols):
            if symbol in project_declarations:
                decl = project_declarations[symbol]
                if not decl.strip().endswith(';'):
                    decl += ';'
                lines.append(decl + '\n')
                found_count += 1
        
        if found_count == 0:
            # No declarations found, add a comment
            lines.append("/* Note: Some symbols may be defined in system headers or other libraries */\n")
        
        lines.append("\n")
        
        return ''.join(lines)
    
    @classmethod
    def extract_project_declarations(cls, project) -> Dict[str, str]:
        """
        Extract all public declarations from project files.
        
        Args:
            project: MalwareProject object
            
        Returns:
            Dict mapping symbol names to declaration strings
        """
        declarations = {}
        
        # Pattern for function definitions
        func_pattern = re.compile(
            r'^\s*(?!static)([A-Za-z_][\w\s\*]+?)\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{',
            re.MULTILINE
        )
        
        for source_file in project.source_files:
            try:
                with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for match in func_pattern.finditer(content):
                    return_type = match.group(1).strip()
                    func_name = match.group(2).strip()
                    params = match.group(3).strip()
                    
                    # Skip entry points
                    if func_name in ['main', 'WinMain', 'wWinMain', '_start']:
                        continue
                    
                    # Create declaration
                    declaration = f"{return_type} {func_name}({params})"
                    declarations[func_name] = declaration
            
            except Exception as e:
                logger.warning(f"Failed to extract declarations from {source_file}: {e}")
        
        # Also extract from header files
        for header_file in project.header_files:
            try:
                with open(header_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Extract function declarations
                decl_pattern = re.compile(
                    r'^\s*(?:extern\s+)?([A-Za-z_][\w\s\*]+?)\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*;',
                    re.MULTILINE
                )
                
                for match in decl_pattern.finditer(content):
                    return_type = match.group(1).strip()
                    func_name = match.group(2).strip()
                    params = match.group(3).strip()
                    
                    declaration = f"{return_type} {func_name}({params})"
                    declarations[func_name] = declaration
            
            except Exception as e:
                logger.warning(f"Failed to extract declarations from {header_file}: {e}")
        
        logger.info(f"Extracted {len(declarations)} declarations from project")
        return declarations


def main():
    """Test forward declaration injector"""
    print("Forward Declaration Injector")
    print("=" * 60)
    print("Note: This requires a real project to test")


if __name__ == "__main__":
    main()





