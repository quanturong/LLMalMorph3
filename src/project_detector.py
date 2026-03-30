"""
Project Detector - Identify and Parse Complete Malware Projects
================================================================
Detects complete projects with multiple source files, headers, and dependencies.

Features:
- Auto-detect project boundaries
- Identify headers and source files
- Parse project structure
- Group related files
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Set, Tuple
import logging

logger = logging.getLogger(__name__)


class MalwareProject:
    """Represents a complete malware project with all dependencies"""
    
    def __init__(self, name: str, root_dir: str):
        self.name = name
        self.root_dir = root_dir
        self.source_files: List[str] = []
        self.header_files: List[str] = []
        self.other_files: List[str] = []
        self.dependencies: Set[str] = set()
        self.build_files: List[str] = []
        
    def add_source_file(self, filepath: str):
        """Add source file to project"""
        self.source_files.append(filepath)
        
    def add_header_file(self, filepath: str):
        """Add header file to project"""
        self.header_files.append(filepath)
        
    def add_dependency(self, dep: str):
        """Add external dependency"""
        self.dependencies.add(dep)
    
    def get_all_files(self) -> List[str]:
        """Get all project files"""
        return self.source_files + self.header_files + self.other_files
    
    def get_source_extensions(self) -> Set[str]:
        """Get unique source file extensions"""
        exts = set()
        for f in self.source_files:
            exts.add(os.path.splitext(f)[1])
        return exts
    
    def is_c_project(self) -> bool:
        """Check if C project"""
        exts = self.get_source_extensions()
        return '.c' in exts and '.cpp' not in exts
    
    def is_cpp_project(self) -> bool:
        """Check if C++ project"""
        exts = self.get_source_extensions()
        return any(ext in exts for ext in ['.cpp', '.cxx', '.cc'])

    def is_python_project(self) -> bool:
        """Check if Python project"""
        exts = self.get_source_extensions()
        has_cpp = any(ext in exts for ext in ['.cpp', '.cxx', '.cc'])
        has_c = '.c' in exts and not has_cpp
        return '.py' in exts and not has_c and not has_cpp

    def is_javascript_project(self) -> bool:
        """Check if JavaScript/Node.js project"""
        exts = self.get_source_extensions()
        has_cpp = any(ext in exts for ext in ['.cpp', '.cxx', '.cc'])
        has_c = '.c' in exts and not has_cpp
        has_py = '.py' in exts
        return any(ext in exts for ext in ['.js', '.mjs']) and not has_c and not has_cpp and not has_py

    def get_language(self) -> str:
        """Get project language"""
        if self.is_cpp_project():
            return 'cpp'
        elif self.is_c_project():
            return 'c'
        elif self.is_python_project():
            return 'python'
        elif self.is_javascript_project():
            return 'javascript'
        return 'unknown'
    
    def __repr__(self):
        return (f"MalwareProject(name={self.name}, "
                f"sources={len(self.source_files)}, "
                f"headers={len(self.header_files)}, "
                f"language={self.get_language()})")


class ProjectDetector:
    """Detect and parse complete malware projects"""
    
    # Source file extensions
    SOURCE_EXTS = {'.c', '.cpp', '.cxx', '.cc', '.C', '.py', '.js', '.mjs'}
    HEADER_EXTS = {'.h', '.hpp', '.hxx', '.hh', '.H'}
    BUILD_EXTS = {'.vcproj', '.vcxproj', '.sln', '.dsp', '.dsw', 'Makefile', 'CMakeLists.txt', 'package.json', 'requirements.txt', 'setup.py'}
    
    # Minimum files to be considered a project (default)
    MIN_FILES_FOR_PROJECT = 1
    
    def __init__(self, base_dir: str, min_files: int = None):
        self.base_dir = Path(base_dir)
        self.projects: List[MalwareProject] = []
        # Allow overriding the minimum files threshold
        if min_files is not None:
            self.MIN_FILES_FOR_PROJECT = min_files
        
    def detect_projects(self, recursive: bool = True) -> List[MalwareProject]:
        """
        Detect all projects in base directory
        
        Args:
            recursive: Search recursively for projects
            
        Returns:
            List of detected MalwareProject objects
        """
        logger.info(f"🔍 Detecting projects in: {self.base_dir}")
        
        if not self.base_dir.exists():
            logger.error(f"Directory not found: {self.base_dir}")
            return []
        
        # Find all directories that could be projects
        potential_project_dirs = self._find_potential_project_dirs()
        
        # Remove nested sub-directories (merge into parent projects)
        potential_project_dirs = self._remove_nested_projects(potential_project_dirs)
        
        logger.info(f"   Found {len(potential_project_dirs)} potential project directories")
        
        # Analyze each directory
        for project_dir in potential_project_dirs:
            project = self._analyze_directory(project_dir)
            if project:
                self.projects.append(project)
                logger.info(f"   ✓ Detected project: {project.name}")
        
        logger.info(f"\n✅ Total projects detected: {len(self.projects)}")
        
        return self.projects
    
    def _find_potential_project_dirs(self) -> List[Path]:
        """Find directories that might contain projects"""
        potential_dirs = []
        
        # Strategy 1: Look for directories with multiple source files
        for dirpath, dirnames, filenames in os.walk(self.base_dir):
            dir_path = Path(dirpath)
            
            # Skip hidden directories and build directories
            if any(part.startswith('.') for part in dir_path.parts):
                continue
            if any(part.lower() in ['build', 'obj', 'debug', 'release'] 
                   for part in dir_path.parts):
                continue
            
            # Count source files in this directory (non-recursive)
            source_files = [
                f for f in filenames 
                if os.path.splitext(f)[1].lower() in self.SOURCE_EXTS
            ]
            
            if len(source_files) >= self.MIN_FILES_FOR_PROJECT:
                potential_dirs.append(dir_path)
        
        # Strategy 2: Look for directories with build files
        for dirpath, dirnames, filenames in os.walk(self.base_dir):
            dir_path = Path(dirpath)
            
            # Check for build files
            has_build_file = any(
                f for f in filenames 
                if any(f.endswith(ext) or f == ext 
                       for ext in self.BUILD_EXTS)
            )
            
            if has_build_file and dir_path not in potential_dirs:
                # Count source files recursively (all supported languages)
                source_count = len(list(dir_path.rglob('*.[cC]'))) + \
                              len(list(dir_path.rglob('*.cpp'))) + \
                              len(list(dir_path.rglob('*.cxx'))) + \
                              len(list(dir_path.rglob('*.py'))) + \
                              len(list(dir_path.rglob('*.js'))) + \
                              len(list(dir_path.rglob('*.mjs')))
                
                if source_count >= self.MIN_FILES_FOR_PROJECT:
                    potential_dirs.append(dir_path)
        
        return sorted(set(potential_dirs))
    
    def _remove_nested_projects(self, dirs: List[Path]) -> List[Path]:
        """Remove child directories when a parent directory is also a project.
        
        This prevents splitting a single project (e.g., KINS with builder/clientdll/common
        sub-directories) into multiple separate projects.
        """
        if not dirs:
            return dirs
        
        sorted_dirs = sorted(dirs, key=lambda p: len(p.parts))
        result = []
        
        for d in sorted_dirs:
            # Check if any existing result is a parent of this directory
            is_child = False
            for parent in result:
                try:
                    d.relative_to(parent)
                    is_child = True
                    break
                except ValueError:
                    continue
            
            if not is_child:
                result.append(d)
        
        if len(dirs) != len(result):
            removed = len(dirs) - len(result)
            logger.info(f"   Merged {removed} sub-directories into parent projects")
        
        return result
    
    def _analyze_directory(self, project_dir: Path) -> MalwareProject:
        """
        Analyze a directory and create MalwareProject
        
        Args:
            project_dir: Path to project directory
            
        Returns:
            MalwareProject or None if not a valid project
        """
        project_name = project_dir.name
        project = MalwareProject(project_name, str(project_dir))
        
        # Scan all files in directory (including subdirectories)
        for root, dirs, files in os.walk(project_dir):
            # Skip build directories
            dirs[:] = [d for d in dirs 
                      if d.lower() not in ['build', 'obj', 'debug', 'release', '.git']]
            
            for filename in files:
                filepath = os.path.join(root, filename)
                ext = os.path.splitext(filename)[1].lower()
                
                # Categorize file
                if ext in self.SOURCE_EXTS:
                    project.add_source_file(filepath)
                elif ext in self.HEADER_EXTS:
                    project.add_header_file(filepath)
                elif any(filename.endswith(bext) or filename == bext 
                        for bext in self.BUILD_EXTS):
                    project.build_files.append(filepath)
                else:
                    project.other_files.append(filepath)
        
        # Extract dependencies from source files
        self._extract_dependencies(project)
        
        # Validate project
        if len(project.source_files) < self.MIN_FILES_FOR_PROJECT:
            return None
        
        return project
    
    def _extract_dependencies(self, project: MalwareProject):
        """Extract dependencies from source files (#include, import, require)."""
        include_pattern = re.compile(r'#include\s*[<"]([^>"]+)[>"]')
        py_import_pattern = re.compile(r'^\s*(?:import|from)\s+(\w[\w.]*)', re.MULTILINE)
        js_require_pattern = re.compile(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""")
        js_import_pattern = re.compile(r"""^\s*import\s+.*?\s+from\s+['"]([^'"]+)['"]""", re.MULTILINE)
        
        for source_file in project.source_files + project.header_files:
            try:
                with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                ext = os.path.splitext(source_file)[1].lower()

                if ext in ('.py', '.pyw'):
                    # Python imports
                    for match in py_import_pattern.finditer(content):
                        project.add_dependency(match.group(1))
                elif ext in ('.js', '.mjs'):
                    # JavaScript require / import
                    for match in js_require_pattern.finditer(content):
                        project.add_dependency(match.group(1))
                    for match in js_import_pattern.finditer(content):
                        project.add_dependency(match.group(1))
                else:
                    # C/C++ includes
                    for match in include_pattern.finditer(content):
                        include_file = match.group(1)
                        
                        # Check if it's a local header
                        if not include_file.startswith(('<', 'windows', 'sys/', 'std')):
                            # Try to resolve relative to project
                            header_path = os.path.join(project.root_dir, include_file)
                            if os.path.exists(header_path):
                                if header_path not in project.header_files:
                                    project.add_header_file(header_path)
                            else:
                                # External dependency
                                project.add_dependency(include_file)
                        else:
                            # System dependency
                            project.add_dependency(include_file)
                        
            except Exception as e:
                logger.debug(f"Could not read {source_file}: {e}")
    
    def get_project_by_name(self, name: str) -> MalwareProject:
        """Get project by name"""
        for project in self.projects:
            if project.name.lower() == name.lower():
                return project
        return None
    
    def list_projects(self):
        """Print list of detected projects"""
        if not self.projects:
            print("No projects detected")
            return
        
        print("\n" + "="*70)
        print("📚 DETECTED MALWARE PROJECTS")
        print("="*70)
        
        for i, project in enumerate(self.projects, 1):
            print(f"\n{i}. {project.name}")
            print(f"   Path: {project.root_dir}")
            print(f"   Language: {project.get_language().upper()}")
            print(f"   Source files: {len(project.source_files)}")
            print(f"   Header files: {len(project.header_files)}")
            print(f"   Dependencies: {len(project.dependencies)}")
            
            # List source files
            if project.source_files:
                print(f"   Sources:")
                for src in sorted(project.source_files)[:5]:
                    print(f"     - {os.path.basename(src)}")
                if len(project.source_files) > 5:
                    print(f"     ... and {len(project.source_files) - 5} more")
        
        print("\n" + "="*70)


def main():
    """Test project detection"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python project_detector.py <base_directory>")
        sys.exit(1)
    
    base_dir = sys.argv[1]
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s'
    )
    
    # Detect projects
    detector = ProjectDetector(base_dir)
    projects = detector.detect_projects()
    
    # List projects
    detector.list_projects()
    
    # Export to JSON
    if projects:
        import json
        output = {
            'total_projects': len(projects),
            'projects': [
                {
                    'name': p.name,
                    'root_dir': p.root_dir,
                    'language': p.get_language(),
                    'source_files': p.source_files,
                    'header_files': p.header_files,
                    'dependencies': list(p.dependencies),
                }
                for p in projects
            ]
        }
        
        output_file = 'detected_projects.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n✅ Exported to: {output_file}")


if __name__ == "__main__":
    main()

