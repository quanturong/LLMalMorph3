"""
Project Parser - Parse Multi-File Malware Projects
==================================================
Parses complete projects with multiple source and header files.

Features:
- Multi-file parsing
- Cross-file function extraction
- Global variable tracking
- Header dependency resolution
"""

import os
import sys
import ast
import re
from pathlib import Path
from typing import List, Dict, Tuple, Set
import logging

# Import tree-sitter parser
from tree_sitter_parser import (
    initialize_parser,
    read_source_code,
    extract_functions_globals_headers,
)

logger = logging.getLogger(__name__)


class ProjectParseResult:
    """Result of parsing a complete project"""
    
    def __init__(self, project_name: str):
        self.project_name = project_name
        
        # Per-file results
        self.file_results: Dict[str, Dict] = {}
        
        # Aggregated results
        self.all_functions = []
        self.all_globals = []
        self.all_headers = []
        self.all_classes = []
        self.all_structs = []
        
        # Statistics
        self.total_files = 0
        self.parsed_files = 0
        self.failed_files = 0
        self.total_functions = 0
        self.total_lines = 0
        
    def add_file_result(self, filepath: str, result: Dict):
        """Add parsing result for a file"""
        self.file_results[filepath] = result
        self.total_files += 1
        
        if result.get('success'):
            self.parsed_files += 1
            
            # Aggregate functions
            functions = result.get('functions', [])
            for func in functions:
                # Add source file info to function
                func['source_file'] = filepath
                self.all_functions.append(func)
            
            # Aggregate globals
            globals_vars = result.get('globals', [])
            for g in globals_vars:
                # Globals might be strings or dicts
                if isinstance(g, str):
                    self.all_globals.append({'name': g, 'source_file': filepath})
                else:
                    g['source_file'] = filepath
                    self.all_globals.append(g)
            
            # Aggregate headers
            headers = result.get('headers', [])
            self.all_headers.extend(headers)
            
            # Aggregate classes
            classes = result.get('classes', [])
            for c in classes:
                if isinstance(c, dict):
                    c['source_file'] = filepath
                    self.all_classes.append(c)
                else:
                    self.all_classes.append({'name': str(c), 'source_file': filepath})
            
            # Aggregate structs
            structs = result.get('structs', [])
            for s in structs:
                if isinstance(s, dict):
                    s['source_file'] = filepath
                    self.all_structs.append(s)
                else:
                    self.all_structs.append({'name': str(s), 'source_file': filepath})
            
            self.total_lines += result.get('lines', 0)
        else:
            self.failed_files += 1
    
    def update_statistics(self):
        """Update statistics"""
        self.total_functions = len(self.all_functions)
        self.all_headers = sorted(set(self.all_headers))
    
    def to_dict(self):
        """Convert to dictionary"""
        self.update_statistics()
        
        return {
            'project_name': self.project_name,
            'statistics': {
                'total_files': self.total_files,
                'parsed_files': self.parsed_files,
                'failed_files': self.failed_files,
                'total_functions': self.total_functions,
                'total_lines': self.total_lines,
                'total_globals': len(self.all_globals),
                'total_headers': len(self.all_headers),
                'total_classes': len(self.all_classes),
                'total_structs': len(self.all_structs),
            },
            'functions': self.all_functions,
            'globals': self.all_globals,
            'headers': self.all_headers,
            'classes': self.all_classes,
            'structs': self.all_structs,
            'file_results': self.file_results,
        }
    
    def get_functions_by_file(self, filepath: str) -> List[Dict]:
        """Get functions from specific file"""
        return [f for f in self.all_functions if f['source_file'] == filepath]
    
    def get_function_by_name(self, func_name: str) -> Dict:
        """Find function by name"""
        for func in self.all_functions:
            if func.get('name_only') == func_name or func.get('name_with_params') == func_name:
                return func
        return None
    
    def print_summary(self):
        """Print parsing summary"""
        self.update_statistics()
        
        print("\n" + "="*70)
        print(f"PROJECT PARSE SUMMARY: {self.project_name}")
        print("="*70)
        print(f"Files:")
        print(f"  Total: {self.total_files}")
        print(f"  Parsed: {self.parsed_files}")
        print(f"  Failed: {self.failed_files}")
        print(f"\nCode Elements:")
        print(f"  Functions: {self.total_functions}")
        print(f"  Global Variables: {len(self.all_globals)}")
        print(f"  Classes: {len(self.all_classes)}")
        print(f"  Structs: {len(self.all_structs)}")
        print(f"  Unique Headers: {len(self.all_headers)}")
        print(f"\nLines of Code:")
        print(f"  Total: {self.total_lines:,}")
        print("="*70)


class ProjectParser:
    """Parse complete C/C++ projects"""
    
    def __init__(self):
        self.parse_results = {}
        
    def parse_project(self, project) -> ProjectParseResult:
        """
        Parse complete project
        
        Args:
            project: MalwareProject object from project_detector
            
        Returns:
            ProjectParseResult object
        """
        logger.info(f"\n{'='*60}")
        logger.info(f"📖 PARSING PROJECT: {project.name}")
        logger.info(f"{'='*60}")
        logger.info(f"Source files: {len(project.source_files)}")
        logger.info(f"Header files: {len(project.header_files)}")
        
        result = ProjectParseResult(project.name)
        
        # Parse all source files
        for i, source_file in enumerate(project.source_files, 1):
            logger.info(f"\n[{i}/{len(project.source_files)}] Parsing: {os.path.basename(source_file)}")
            
            file_result = self._parse_file(source_file)
            result.add_file_result(source_file, file_result)
            
            if file_result.get('success'):
                funcs = len(file_result.get('functions', []))
                globs = len(file_result.get('globals', []))
                logger.info(f"   ✓ Functions: {funcs}, Globals: {globs}")
            else:
                logger.warning(f"   ✗ Failed: {file_result.get('error', 'Unknown error')}")
        
        # Update statistics
        result.update_statistics()
        
        # Store result
        self.parse_results[project.name] = result
        
        # Print summary
        result.print_summary()
        
        return result
    
    def _parse_file(self, filepath: str) -> Dict:
        """
        Parse a single source file
        
        Args:
            filepath: Path to source file
            
        Returns:
            Dictionary with parsing results
        """
        try:
            # Read source code
            source_code = read_source_code(filepath)

            # Python fallback parser: AST-based extraction for .py files
            if filepath.lower().endswith('.py'):
                return self._parse_python_file(filepath, source_code)

            # JavaScript regex parser for .js/.mjs files
            if filepath.lower().endswith(('.js', '.mjs')):
                return self._parse_javascript_file(filepath, source_code)
            
            # Initialize parser
            parser = initialize_parser(filepath)
            if not parser:
                return {
                    'success': False,
                    'error': 'Could not initialize parser'
                }
            
            # Parse
            tree = parser.parse(bytes(source_code, "utf8"))
            
            # Extract functions, globals, headers
            parsed_info = extract_functions_globals_headers(source_code, tree)
            headers, globals_vars, functions, classes, structs = parsed_info
            
            return {
                'success': True,
                'filepath': filepath,
                'headers': headers,
                'globals': globals_vars,
                'functions': functions,
                'classes': classes,
                'structs': structs,
                'lines': len(source_code.split('\n')),
                'size': len(source_code),
            }
            
        except Exception as e:
            logger.debug(f"Error parsing {filepath}: {e}")
            return {
                'success': False,
                'filepath': filepath,
                'error': str(e),
            }

    def _parse_python_file(self, filepath: str, source_code: str) -> Dict:
        """Parse Python source using built-in AST and map to common function schema."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            # Python 2 syntax (e.g., print statement) fails in Python 3 AST.
            # Fall back to a tolerant text parser so legacy files are still indexed.
            return self._parse_python_legacy_fallback(filepath, source_code, str(e))

        lines = source_code.split('\n')
        functions = []
        globals_vars = []
        imports = []
        classes = []
        structs = []

        def _end_lineno(node):
            end = getattr(node, 'end_lineno', None)
            if end is not None:
                return end
            return getattr(node, 'lineno', 1)

        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                imports.append(ast.get_source_segment(source_code, node) or '')
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        globals_vars.append({'name': target.id})
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                globals_vars.append({'name': node.target.id})
            elif isinstance(node, ast.ClassDef):
                classes.append({'name': node.name})
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start_line = getattr(node, 'lineno', 1)
                end_line = _end_lineno(node)
                body_text = '\n'.join(lines[start_line - 1:end_line])

                arg_names = []
                for arg in getattr(node.args, 'posonlyargs', []):
                    arg_names.append(arg.arg)
                for arg in node.args.args:
                    arg_names.append(arg.arg)
                if node.args.vararg:
                    arg_names.append('*' + node.args.vararg.arg)
                for arg in node.args.kwonlyargs:
                    arg_names.append(arg.arg)
                if node.args.kwarg:
                    arg_names.append('**' + node.args.kwarg.arg)

                signature = f"{node.name}({', '.join(arg_names)})"

                functions.append({
                    'name_only': node.name,
                    'name_with_params': signature,
                    'body': body_text,
                    'start_line': start_line,
                    'end_line': end_line,
                })

        imports = [i for i in imports if i]

        return {
            'success': True,
            'filepath': filepath,
            'headers': imports,
            'globals': globals_vars,
            'functions': functions,
            'classes': classes,
            'structs': structs,
            'lines': len(lines),
            'size': len(source_code),
        }

    def _parse_python_legacy_fallback(self, filepath: str, source_code: str, parse_error: str) -> Dict:
        """Best-effort parser for Python 2 / syntactically invalid Python files."""
        lines = source_code.split('\n')
        imports = []
        globals_vars = []
        classes = []
        structs = []
        functions = []

        import_re = re.compile(r'^\s*(import\s+.+|from\s+.+\s+import\s+.+)\s*$')
        class_re = re.compile(r'^\s*class\s+([A-Za-z_]\w*)\b')
        def_re = re.compile(r'^\s*def\s+([A-Za-z_]\w*)\s*\((.*?)\)\s*:')
        global_re = re.compile(r'^\s*([A-Za-z_]\w*)\s*=')

        # Collect top-level imports, globals, classes, functions.
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue

            if import_re.match(line):
                imports.append(stripped)
                continue

            if not line.startswith((' ', '\t')):
                class_match = class_re.match(line)
                if class_match:
                    classes.append({'name': class_match.group(1)})
                    continue

                global_match = global_re.match(line)
                if global_match and not stripped.startswith(('def ', 'class ', 'if ', 'for ', 'while ', 'try:', 'with ')):
                    globals_vars.append({'name': global_match.group(1)})

        # Extract top-level function blocks by indentation boundaries.
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith((' ', '\t')):
                i += 1
                continue

            def_match = def_re.match(line)
            if not def_match:
                i += 1
                continue

            func_name = def_match.group(1)
            params = def_match.group(2).strip()
            start_line = i + 1
            def_indent = len(line) - len(line.lstrip(' \t'))
            j = i + 1

            while j < len(lines):
                candidate = lines[j]
                candidate_stripped = candidate.strip()
                if not candidate_stripped:
                    j += 1
                    continue

                candidate_indent = len(candidate) - len(candidate.lstrip(' \t'))
                if candidate_indent <= def_indent and not candidate_stripped.startswith('#'):
                    break
                j += 1

            end_line = j if j > i + 1 else i + 1
            body_text = '\n'.join(lines[i:end_line])

            functions.append({
                'name_only': func_name,
                'name_with_params': f"{func_name}({params})",
                'body': body_text,
                'start_line': start_line,
                'end_line': end_line,
            })

            i = j

        return {
            'success': True,
            'filepath': filepath,
            'headers': sorted(set(imports)),
            'globals': globals_vars,
            'functions': functions,
            'classes': classes,
            'structs': structs,
            'lines': len(lines),
            'size': len(source_code),
            'parser_mode': 'python_legacy_fallback',
            'warning': f'AST parse failed; used legacy fallback parser: {parse_error}',
        }

    def _parse_javascript_file(self, filepath: str, source_code: str) -> Dict:
        """Parse JavaScript source using regex-based extraction."""
        lines = source_code.split('\n')
        imports = []
        globals_vars = []
        classes = []
        structs = []
        functions = []

        require_re = re.compile(r"^\s*(?:const|let|var)\s+.*=\s*require\s*\(")
        import_re = re.compile(r"^\s*import\s+")
        export_re = re.compile(r"^\s*(?:module\.)?exports")
        class_re = re.compile(r"^\s*class\s+(\w+)")
        # Named function
        func_re = re.compile(r"^\s*(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)")
        # Arrow / const function
        arrow_re = re.compile(
            r"^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function\s*)?\(([^)]*)\)"
        )

        i = 0
        while i < len(lines):
            stripped = lines[i].strip()
            if not stripped or stripped.startswith('//'):
                i += 1
                continue

            # Require / import
            if require_re.match(stripped) or import_re.match(stripped):
                imports.append(stripped)
                i += 1
                continue

            # Class
            cls_match = class_re.match(stripped)
            if cls_match:
                classes.append({'name': cls_match.group(1)})
                i += 1
                continue

            # Export line (skip)
            if export_re.match(stripped):
                i += 1
                continue

            # Function definitions
            func_match = func_re.match(stripped) or arrow_re.match(stripped)
            if func_match:
                func_name = func_match.group(1)
                params = func_match.group(2).strip() if func_match.lastindex >= 2 else ""
                start_line = i + 1

                # Find end by brace counting
                brace_count = stripped.count('{') - stripped.count('}')
                end_idx = i
                if brace_count > 0:
                    for j in range(i + 1, len(lines)):
                        brace_count += lines[j].count('{') - lines[j].count('}')
                        end_idx = j
                        if brace_count <= 0:
                            break
                else:
                    end_idx = i

                body_text = '\n'.join(lines[i:end_idx + 1])
                functions.append({
                    'name_only': func_name,
                    'name_with_params': f"{func_name}({params})",
                    'body': body_text,
                    'start_line': start_line,
                    'end_line': end_idx + 1,
                })
                i = end_idx + 1
                continue

            # Global variable (top-level const/let/var that is not a function)
            gvar_match = re.match(r'^\s*(?:const|let|var)\s+(\w+)\s*=', stripped)
            if gvar_match:
                globals_vars.append({'name': gvar_match.group(1)})

            i += 1

        return {
            'success': True,
            'filepath': filepath,
            'headers': imports,
            'globals': globals_vars,
            'functions': functions,
            'classes': classes,
            'structs': structs,
            'lines': len(lines),
            'size': len(source_code),
        }
    
    def select_functions_for_mutation(
        self,
        parse_result: ProjectParseResult,
        num_functions: int = 10,
        selection_strategy: str = 'largest'
    ) -> List[Dict]:
        """
        Select functions from project for mutation
        
        Args:
            parse_result: ProjectParseResult object
            num_functions: Number of functions to select
            selection_strategy: 'largest', 'random', 'all'
            
        Returns:
            List of selected function objects
        """
        all_functions = parse_result.all_functions
        
        if not all_functions:
            logger.warning("No functions found in project")
            return []
        
        logger.info(f"\n📋 Selecting {num_functions} functions for mutation...")
        logger.info(f"   Strategy: {selection_strategy}")
        logger.info(f"   Available: {len(all_functions)} functions")
        
        selected = []
        
        if selection_strategy == 'largest':
            # Sort by function size (body length)
            sorted_funcs = sorted(
                all_functions,
                key=lambda f: len(f.get('body', '')),
                reverse=True
            )
            selected = sorted_funcs[:num_functions]
            
        elif selection_strategy == 'random':
            import random
            selected = random.sample(
                all_functions,
                min(num_functions, len(all_functions))
            )
            
        elif selection_strategy == 'all':
            selected = all_functions[:num_functions]
        
        else:
            # Default: first N functions
            selected = all_functions[:num_functions]
        
        logger.info(f"   ✓ Selected {len(selected)} functions")
        
        # Print selected functions
        for i, func in enumerate(selected, 1):
            source_file = os.path.basename(func.get('source_file', 'unknown'))
            func_name = func.get('name_only', 'unknown')
            func_size = len(func.get('body', ''))
            logger.info(f"      {i}. {func_name} ({source_file}, {func_size} chars)")
        
        return selected
    
    def export_parse_result(self, parse_result: ProjectParseResult, output_file: str):
        """Export parse result to JSON"""
        import json
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(parse_result.to_dict(), f, indent=2)
        
        logger.info(f"\n✅ Exported parse result to: {output_file}")


def main():
    """Test project parsing"""
    import sys
    from project_detector import ProjectDetector
    
    if len(sys.argv) < 2:
        print("Usage: python project_parser.py <base_directory>")
        sys.exit(1)
    
    base_dir = sys.argv[1]
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s'
    )
    
    # Step 1: Detect projects
    logger.info("Step 1: Detecting projects...")
    detector = ProjectDetector(base_dir)
    projects = detector.detect_projects()
    
    if not projects:
        logger.error("No projects found!")
        sys.exit(1)
    
    # Step 2: Parse first project
    project = projects[0]
    logger.info(f"\nStep 2: Parsing project: {project.name}")
    
    parser = ProjectParser()
    result = parser.parse_project(project)
    
    # Step 3: Export results
    output_file = f"parsed_{project.name}.json"
    parser.export_parse_result(result, output_file)
    
    # Step 4: Select functions
    selected = parser.select_functions_for_mutation(result, num_functions=5)
    
    logger.info(f"\n✅ Done!")


if __name__ == "__main__":
    main()

