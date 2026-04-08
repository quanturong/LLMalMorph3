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
        
        # Build configuration detected from project files
        self.target_msvc_version: str = ''      # e.g. 'msvc6', 'msvc7', 'msvc8', 'msvc9', 'msvc14+'
        self.target_arch: str = 'x64'            # 'x86' or 'x64'
        self.nodefaultlib: bool = False           # Project excludes CRT
        self.custom_entry: str = ''               # Custom entry point (e.g. '_entryPoint')
        self.has_custom_ntdll_h: bool = False     # Has custom ntdll.h that conflicts with SDK
        self.excluded_sources: List[str] = []     # Source files to exclude from compilation
        self.extra_defines: List[str] = []        # Extra /D defines needed
        self.needs_gs_disabled: bool = False      # Needs /GS- (buffer security check off)
        
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
        
        # Detect build configuration from project files and source analysis
        self._detect_build_config(project)
        
        # Apply exclusions
        if project.excluded_sources:
            project.source_files = [f for f in project.source_files
                                    if f not in project.excluded_sources]
        
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

    def _detect_build_config(self, project: MalwareProject):
        """Detect MSVC version, target arch, CRT settings from build/source files."""
        import re as _re

        # --- 1. Detect MSVC version from build files ---
        for bf in project.build_files:
            bname = os.path.basename(bf).lower()
            try:
                content = open(bf, 'r', errors='ignore').read()
            except Exception:
                continue

            # .dsp / .dsw = MSVC 6.0
            if bname.endswith(('.dsp', '.dsw')):
                project.target_msvc_version = 'msvc6'
                # .dsp files specify target machine
                if 'machine:I386' in content or '/machine:IX86' in content:
                    project.target_arch = 'x86'

            # .vcproj = MSVC 7/7.1/8/9 (2003–2008)
            elif bname.endswith('.vcproj'):
                if 'Version="7' in content:
                    project.target_msvc_version = 'msvc7'
                elif 'Version="8' in content:
                    project.target_msvc_version = 'msvc8'
                elif 'Version="9' in content:
                    project.target_msvc_version = 'msvc9'
                else:
                    project.target_msvc_version = 'msvc7'
                if 'Win32' in content and 'x64' not in content:
                    project.target_arch = 'x86'

            # .vcxproj = MSVC 10+ (2010+)
            elif bname.endswith('.vcxproj'):
                m = _re.search(r'<PlatformToolset>v(\d+)', content)
                if m:
                    ver = int(m.group(1))
                    if ver >= 140:
                        project.target_msvc_version = 'msvc14+'
                    elif ver >= 120:
                        project.target_msvc_version = 'msvc12'
                    elif ver >= 110:
                        project.target_msvc_version = 'msvc11'
                    else:
                        project.target_msvc_version = 'msvc10'
                else:
                    project.target_msvc_version = 'msvc10'
                # Platform
                if '<Platform>Win32</Platform>' in content:
                    project.target_arch = 'x86'
                elif '<Platform>x64</Platform>' in content:
                    project.target_arch = 'x64'

            # .sln - check format version
            elif bname.endswith('.sln'):
                if 'Format Version 8' in content:
                    if not project.target_msvc_version:
                        project.target_msvc_version = 'msvc7'
                elif 'Format Version 9' in content:
                    if not project.target_msvc_version:
                        project.target_msvc_version = 'msvc8'
                elif 'Format Version 10' in content:
                    if not project.target_msvc_version:
                        project.target_msvc_version = 'msvc9'
                elif 'Format Version 11' in content:
                    if not project.target_msvc_version:
                        project.target_msvc_version = 'msvc10'
                elif 'Format Version 12' in content:
                    if not project.target_msvc_version:
                        project.target_msvc_version = 'msvc14+'

        # --- 2. Scan source files for build-relevant patterns ---
        all_content = ""
        for src_file in project.source_files[:20] + project.header_files[:20]:
            try:
                with open(src_file, 'r', encoding='utf-8', errors='ignore') as f:
                    all_content += f.read()
            except Exception:
                continue

        # Detect /NODEFAULTLIB pragma  
        if _re.search(r'#pragma\s+comment\s*\(\s*linker\s*,\s*"[^"]*NODEFAULTLIB', all_content, _re.IGNORECASE):
            project.nodefaultlib = True
            project.needs_gs_disabled = True

        # Detect custom entry point
        m = _re.search(r'#pragma\s+comment\s*\(\s*linker\s*,\s*"[^"]*(?:/ENTRY:|/entry:)(\w+)', all_content)
        if m:
            project.custom_entry = m.group(1)
            # Custom entry + /NODEFAULTLIB often means project manages its own CRT
            if project.nodefaultlib:
                project.needs_gs_disabled = True

        # Detect x86 target from pragmas
        if _re.search(r'#pragma\s+comment\s*\(\s*linker\s*,\s*"[^"]*(?:/machine:I386|/machine:IX86|/machine:X86)', all_content, _re.IGNORECASE):
            project.target_arch = 'x86'
        # x86 stdcall decoration patterns (e.g. @8 suffixes in function pointers)
        if _re.search(r'#pragma\s+comment\s*\(\s*linker\s*,\s*"[^"]*FILEALIGN:0x200', all_content):
            # Old /FILEALIGN: pragma is a strong MSVC 6.0 x86 indicator
            if not project.target_msvc_version:
                project.target_msvc_version = 'msvc6'
            project.target_arch = 'x86'

        # Detect custom ntdll.h that would conflict with modern Windows SDK
        for hf in project.header_files:
            if os.path.basename(hf).lower() == 'ntdll.h':
                try:
                    hcontent = open(hf, 'r', errors='ignore').read()
                    # If it redefines types that also exist in modern SDK headers
                    conflict_types = ['IO_COUNTERS', 'EXCEPTION_REGISTRATION_RECORD',
                                      'RTL_OSVERSIONINFOW', 'UNICODE_STRING']
                    if any(t in hcontent for t in conflict_types):
                        project.has_custom_ntdll_h = True
                except Exception:
                    pass

        # --- 3a. Detect .cpp/.c files that are #included by other source files ---
        # Old code pattern: one .cpp #includes another .cpp (not meant to be compiled separately)
        included_cpps = set()
        for sf in project.source_files:
            try:
                with open(sf, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        m = _re.match(r'\s*#\s*include\s*"([^"]+\.(?:cpp|cc|cxx|c))"', line, _re.IGNORECASE)
                        if m:
                            inc_name = m.group(1).lower()
                            included_cpps.add(inc_name)
            except Exception:
                pass
        if included_cpps:
            for sf in project.source_files:
                bn = os.path.basename(sf).lower()
                if bn in included_cpps:
                    project.excluded_sources.append(sf)

        # --- 3b. Detect duplicate/variant source files to exclude ---
        # Common patterns: main.c + main_changed.c, Lastmain.c + main-OK.c + main.c
        source_basenames = {}
        for sf in project.source_files:
            bn = os.path.basename(sf).lower()
            source_basenames.setdefault(bn, []).append(sf)

        # Group by stem to find variants
        stems = {}
        variant_suffix_re = _re.compile(r'[-_]?(changed|modified|old|new|backup|bak|orig(?:inal)?|copy|ok)', _re.IGNORECASE)
        # Suffixes indicating "older/original" version (to be excluded when a "newer" version exists)
        old_suffixes_re = _re.compile(r'[-_]?(original|orig|old|backup|bak|copy)', _re.IGNORECASE)
        for sf in project.source_files:
            bn = os.path.basename(sf).lower()
            stem = os.path.splitext(bn)[0]
            # Normalize: remove common variant suffixes
            clean_stem = variant_suffix_re.sub('', stem)
            if clean_stem and clean_stem != stem:
                stems.setdefault(clean_stem, []).append(sf)

        # For each stem group with variants, exclude duplicates
        for clean_stem, variant_files in stems.items():
            # Find the canonical file (the one whose stem exactly matches clean_stem)
            canonical = [sf for sf in project.source_files
                         if os.path.splitext(os.path.basename(sf).lower())[0] == clean_stem
                         and sf not in variant_files]
            if canonical:
                # Canonical exists → exclude all variants
                project.excluded_sources.extend(variant_files)
            elif len(variant_files) > 1:
                # No canonical, but multiple variants → keep the "newest" one, exclude old versions
                old_versions = [sf for sf in variant_files
                                if old_suffixes_re.search(os.path.splitext(os.path.basename(sf))[0])]
                if old_versions and len(old_versions) < len(variant_files):
                    # Exclude old versions, keep newer ones
                    project.excluded_sources.extend(old_versions)
                else:
                    # Can't distinguish → keep first, exclude rest
                    project.excluded_sources.extend(variant_files[1:])

        # Check for main-like duplicate files
        main_variants = []
        for sf in project.source_files:
            bn = os.path.basename(sf).lower()
            stem = os.path.splitext(bn)[0]
            if _re.match(r'^(main[-_]?\w*|lastmain|winmain)$', stem, _re.IGNORECASE) and stem != 'main':
                main_variants.append(sf)
        
        # If we have 'main.c' and also 'main_changed.c', 'main-OK.c', etc. → exclude variants
        has_main = any(os.path.basename(sf).lower() in ('main.c', 'main.cpp') for sf in project.source_files)
        if has_main and main_variants:
            # Extend but avoid duplicates (some may already be excluded by stem logic)
            for mv in main_variants:
                if mv not in project.excluded_sources:
                    project.excluded_sources.append(mv)

        # --- 4. Extra defines for old MSVC projects ---
        if project.target_msvc_version in ('msvc6', 'msvc7', 'msvc8'):
            # Old projects often need these for compatibility with modern SDK
            project.extra_defines.extend([
                'WC_NO_BEST_FIT_CHARS=0x00000400',
                '_WINSOCK_DEPRECATED_NO_WARNINGS',
                'PSAPI_VERSION=1',  # Use old-style psapi.lib imports (not K32* wrappers)
            ])

        logger.debug(f"Build config for {project.name}: "
                     f"msvc={project.target_msvc_version or 'unknown'}, "
                     f"arch={project.target_arch}, "
                     f"nodefaultlib={project.nodefaultlib}, "
                     f"custom_entry={project.custom_entry or 'none'}, "
                     f"custom_ntdll={project.has_custom_ntdll_h}, "
                     f"gs_disabled={project.needs_gs_disabled}, "
                     f"excluded={len(project.excluded_sources)}")

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

