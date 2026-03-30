"""
Mutation Strategy Improver
===========================
Improves mutation strategy to preserve critical code structures.
- Preserves critical declarations and system includes
- Avoids mutating function signatures referenced across files
- Maintains project structure (entry points, dependencies)
"""
import os
import re
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class MutationConstraints:
    """Constraints for mutation"""
    preserve_functions: Set[str]  # Function names to not mutate
    preserve_types: Set[str]  # Type names to not mutate
    preserve_signatures: bool = True  # Keep function signatures unchanged
    preserve_entry_points: bool = True  # Don't mutate main/WinMain
    preserve_system_includes: bool = True  # Keep system includes
    preserve_exports: bool = True  # Don't mutate exported functions


class MutationStrategyImprover:
    """Improve mutation strategy to preserve critical code"""
    
    # Entry points that should never be mutated
    ENTRY_POINTS = {'main', 'WinMain', 'wWinMain', '_start', 'DllMain'}
    
    # System includes that should be preserved
    SYSTEM_INCLUDES = {
        'windows.h', 'stdio.h', 'stdlib.h', 'string.h', 'winsock2.h',
        'ws2tcpip.h', 'process.h', 'time.h', 'malloc.h', 'memory.h',
    }
    
    # Only truly critical prefixes (entry points, DLL exports)
    # NOTE: Get/Set/Create/Read/Write/Open/Close/Init/Start etc. are NORMAL
    # function names in C/C++ and should NOT be preserved
    CRITICAL_PREFIXES = {
        'Dll',  # DLL entry/export functions
    }
    
    @classmethod
    def analyze_project_for_mutation(
        cls,
        project,
        project_context=None,
        parse_result=None
    ) -> MutationConstraints:
        """
        Analyze project to determine what should not be mutated.
        
        Args:
            project: MalwareProject object
            project_context: Optional ProjectContext
            parse_result: Optional ProjectParseResult
            
        Returns:
            MutationConstraints object
        """
        logger.info("Analyzing project for mutation constraints...")
        
        preserve_functions = set(cls.ENTRY_POINTS)
        preserve_types = set()
        
        # Find cross-file referenced functions
        if project_context:
            cross_refs = cls._find_cross_file_references(project_context)
            preserve_functions.update(cross_refs)
            logger.info(f"  Cross-file functions to preserve: {len(cross_refs)}")
        
        # Find exported functions
        exported = cls._find_exported_functions(project)
        preserve_functions.update(exported)
        logger.info(f"  Exported functions to preserve: {len(exported)}")
        
        # Find critical API-like functions
        critical = cls._find_critical_functions(project)
        preserve_functions.update(critical)
        logger.info(f"  Critical functions to preserve: {len(critical)}")
        
        # Find system types
        system_types = cls._find_system_types(project)
        preserve_types.update(system_types)
        
        constraints = MutationConstraints(
            preserve_functions=preserve_functions,
            preserve_types=preserve_types,
            preserve_signatures=True,
            preserve_entry_points=True,
            preserve_system_includes=True,
            preserve_exports=True
        )
        
        logger.info(f"  Total functions to preserve: {len(constraints.preserve_functions)}")
        logger.info(f"  Total types to preserve: {len(constraints.preserve_types)}")
        
        return constraints
    
    # Shared utility helpers that are commonly used across files and must
    # never be mutated because other translation units depend on their
    # exact signatures and semantics.
    SHARED_HELPER_NAMES = {
        'memcpy', '_memcpy', 'memset', '_memset', 'memcmp', '_memcmp',
        'strlen', '_strlen', 'strcpy', '_strcpy', 'strcmp', '_strcmp',
        'strncpy', '_strncpy', 'strcat', '_strcat', 'strstr', '_strstr',
        'sprintf', '_sprintf', 'snprintf', '_snprintf',
        'malloc', '_malloc', 'free', '_free', 'calloc', '_calloc',
        'realloc', '_realloc',
    }

    @classmethod
    def _find_cross_file_references(cls, project_context) -> Set[str]:
        """Find functions that are shared across files.
        
        Detects:
        1. Functions DEFINED in multiple source files.
        2. Functions DEFINED in one file but CALLED from other files
           (shared helpers like _memcpy, _memset, etc.).
        3. Well-known shared helper names (SHARED_HELPER_NAMES).
        """
        cross_refs = set()
        
        # --- Pass 1: functions defined in multiple source files ---
        definitions = {}  # func_name -> set of source files where defined
        for func_name, signatures in project_context.functions.items():
            source_files = set()
            for sig in signatures:
                ext = os.path.splitext(sig.file_path)[1].lower()
                if ext in ('.c', '.cpp', '.cc', '.cxx'):
                    source_files.add(sig.file_path)
            definitions[func_name] = source_files
            if len(source_files) > 1:
                cross_refs.add(func_name)
        
        # --- Pass 2: functions called from files other than where defined ---
        # Build a caller map: for each project source file, collect all
        # identifiers that look like function calls.
        try:
            all_source_files = set()
            for sigs in project_context.functions.values():
                for sig in sigs:
                    ext = os.path.splitext(sig.file_path)[1].lower()
                    if ext in ('.c', '.cpp', '.cc', '.cxx'):
                        all_source_files.add(sig.file_path)
            
            call_pattern = re.compile(r'\b(\w+)\s*\(')
            calls_per_file = {}  # file -> set of called names
            for src in all_source_files:
                try:
                    with open(src, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    calls_per_file[src] = set(call_pattern.findall(content))
                except Exception:
                    pass
            
            for func_name, def_files in definitions.items():
                if func_name in cross_refs:
                    continue  # already protected
                if not def_files:
                    continue
                # Check if this function is called from a file where it is NOT defined
                for src, calls in calls_per_file.items():
                    if func_name in calls and src not in def_files:
                        cross_refs.add(func_name)
                        break
        except Exception as e:
            logger.debug(f"Cross-file call scan failed: {e}")
        
        # --- Pass 3: always protect well-known shared helpers ---
        defined_names = set(definitions.keys())
        for helper in cls.SHARED_HELPER_NAMES:
            if helper in defined_names:
                cross_refs.add(helper)
        
        return cross_refs
    
    @classmethod
    def _find_exported_functions(cls, project) -> Set[str]:
        """Find functions that are explicitly exported (e.g., DllExport).
        
        NOTE: WINAPI and CALLBACK are calling conventions, NOT export markers.
        They should NOT prevent mutation. Only __declspec(dllexport) is a
        true export marker.
        """
        exported = set()
        
        export_patterns = [
            r'__declspec\s*\(\s*dllexport\s*\)\s*\w+\s+(\w+)\s*\(',
        ]
        
        for source_file in project.source_files + project.header_files:
            try:
                with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for pattern in export_patterns:
                    matches = re.findall(pattern, content)
                    exported.update(matches)
            
            except Exception as e:
                logger.warning(f"Failed to scan exports in {source_file}: {e}")
        
        return exported
    
    @classmethod
    def _find_critical_functions(cls, project) -> Set[str]:
        """Find functions with critical prefixes"""
        critical = set()
        
        func_pattern = re.compile(r'\b(\w+)\s*\([^)]*\)\s*\{', re.MULTILINE)
        
        for source_file in project.source_files:
            try:
                with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for match in func_pattern.finditer(content):
                    func_name = match.group(1)
                    
                    # Check if function name starts with critical prefix
                    for prefix in cls.CRITICAL_PREFIXES:
                        if func_name.startswith(prefix):
                            critical.add(func_name)
                            break
            
            except Exception as e:
                logger.warning(f"Failed to scan critical functions in {source_file}: {e}")
        
        return critical
    
    @classmethod
    def _find_system_types(cls, project) -> Set[str]:
        """Find system type names that shouldn't be redefined"""
        system_types = {
            'sockaddr', 'sockaddr_in', 'in_addr', 'hostent',
            'SOCKET', 'HANDLE', 'DWORD', 'WORD', 'BYTE',
            'HWND', 'HDC', 'HINSTANCE', 'LPSTR', 'LPCSTR',
        }
        
        return system_types
    
    @classmethod
    def should_mutate_function(
        cls,
        func_name: str,
        constraints: MutationConstraints,
        func_info: Optional[Dict] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Determine if a function should be mutated.
        
        Returns:
            Tuple of (should_mutate, reason_if_not)
        """
        # Check if in preserve list
        if func_name in constraints.preserve_functions:
            return False, "Function is marked for preservation (cross-file or critical)"
        
        # Check if it's an entry point
        if constraints.preserve_entry_points and func_name in cls.ENTRY_POINTS:
            return False, "Function is an entry point"
        
        # Check if it has export markers (only __declspec(dllexport), NOT WINAPI/CALLBACK)
        # WINAPI and CALLBACK are calling conventions, not export markers
        if constraints.preserve_exports and func_info:
            func_body = func_info.get('body', '')
            if '__declspec' in func_body and 'dllexport' in func_body:
                return False, "Function has export markers"
        
        # Check if it's too small (likely a critical stub)
        if func_info:
            func_body = func_info.get('body', '')
            # Count lines (excluding braces and empty lines)
            lines = [l.strip() for l in func_body.split('\n') if l.strip() and l.strip() not in ['{', '}']]
            if len(lines) < 3:
                return False, "Function is too small (likely critical stub)"
        
        return True, None
    
    @classmethod
    def filter_mutation_candidates(
        cls,
        functions: List[Dict],
        constraints: MutationConstraints,
        verbose: bool = True
    ) -> List[Dict]:
        """
        Filter function list to only safe mutation candidates.
        
        Args:
            functions: List of function dictionaries
            constraints: Mutation constraints
            verbose: Print filtering info
            
        Returns:
            Filtered list of functions safe to mutate
        """
        safe_functions = []
        filtered_out = []
        
        for func in functions:
            func_name = func.get('name_only', '')
            should_mutate, reason = cls.should_mutate_function(func_name, constraints, func)
            
            if should_mutate:
                safe_functions.append(func)
            else:
                filtered_out.append((func_name, reason))
        
        if verbose:
            logger.info(f"\n📋 Mutation Filtering:")
            logger.info(f"  Total functions: {len(functions)}")
            logger.info(f"  Safe to mutate: {len(safe_functions)}")
            logger.info(f"  Filtered out: {len(filtered_out)}")
            
            if filtered_out and len(filtered_out) <= 10:
                logger.info(f"\n  Preserved functions:")
                for func_name, reason in filtered_out:
                    logger.info(f"    - {func_name}: {reason}")
        
        # FALLBACK: If ALL functions were filtered out, return the largest ones
        # anyway. It's better to mutate something than to skip the entire project.
        if not safe_functions and functions:
            logger.warning(f"⚠️ All {len(functions)} functions were filtered out!")
            logger.warning(f"  Falling back: returning largest functions for mutation")
            # Sort by body length (largest first) and take the top ones
            sorted_funcs = sorted(
                functions,
                key=lambda f: len(f.get('body', '')),
                reverse=True
            )
            # Return up to 5 largest functions, excluding entry points
            for func in sorted_funcs:
                func_name = func.get('name_only', '')
                if func_name not in cls.ENTRY_POINTS:
                    safe_functions.append(func)
                    if len(safe_functions) >= 5:
                        break
            logger.info(f"  Fallback selected {len(safe_functions)} functions")
        
        return safe_functions
    
    @classmethod
    def _extract_param_names_from_signature(cls, signature: str) -> List[str]:
        """
        Extract parameter names from a C/C++ function signature string.
        
        Handles signatures like:
            'static int foo(const JSON_Value *value, char *buf, int level)'
            'void bar(DWORD dwFlags, LPCSTR lpName)'
            'int baz(void)'
            
        Returns list of parameter names in order.
        """
        # Find the parameter list between parentheses
        paren_start = signature.find('(')
        paren_end = signature.rfind(')')
        if paren_start < 0 or paren_end < 0 or paren_end <= paren_start:
            return []
        
        param_str = signature[paren_start + 1:paren_end].strip()
        
        # Handle void or empty params
        if not param_str or param_str == 'void':
            return []
        
        # Split by comma (respecting nested parens/templates)
        params = []
        depth = 0
        current = ''
        for ch in param_str:
            if ch in '(<':
                depth += 1
                current += ch
            elif ch in ')>':
                depth -= 1
                current += ch
            elif ch == ',' and depth == 0:
                params.append(current.strip())
                current = ''
            else:
                current += ch
        if current.strip():
            params.append(current.strip())
        
        # Extract the last identifier from each parameter declaration
        names = []
        for param in params:
            param = param.strip()
            if not param or param == 'void' or param == '...':
                continue
            # Remove array brackets at end: e.g., "char buf[256]" -> "char buf"
            param = re.sub(r'\[.*?\]\s*$', '', param).strip()
            # The parameter name is the last word/identifier
            # Handle pointer/ref: "const char *name" -> name, "int &ref" -> ref
            # Remove trailing pointer/ref from name: sometimes "char* name" or "char *name"
            tokens = re.findall(r'[A-Za-z_]\w*', param)
            if tokens:
                # Last token is the name (unless it's a type keyword with no name, rare)
                names.append(tokens[-1])
        
        return names
    
    @classmethod
    def preserve_function_signature(
        cls,
        original_func: Dict,
        mutated_func: Dict
    ) -> Dict:
        """
        Ensure mutated function preserves the original signature.
        Also renames any parameters in the body that the LLM renamed,
        so the body uses the original parameter names matching the restored signature.
        
        Args:
            original_func: Original function info (from tree-sitter extraction)
            mutated_func: Mutated function info (from LLM response extraction)
            
        Returns:
            Mutated function with preserved signature
        """
        # Extract the original signature from the original function's body
        # This is the most reliable way since 'body' contains the full definition
        orig_body = original_func.get('body', '')
        orig_signature = ''
        
        if orig_body:
            brace_pos = orig_body.find('{')
            if brace_pos > 0:
                orig_signature = orig_body[:brace_pos].rstrip()
        
        # Fallback: reconstruct signature from components
        if not orig_signature:
            orig_return_type = original_func.get('return_type', '')
            orig_name = original_func.get('name_only', '')
            
            # Build params from parameter lists (tree-sitter uses these keys)
            param_types = original_func.get('parameter_type_list', [])
            param_names = original_func.get('parameter_name_list', [])
            
            if param_types and param_names and len(param_types) == len(param_names):
                params = ', '.join(f"{t} {n}" for t, n in zip(param_types, param_names))
            elif original_func.get('name_with_params', ''):
                # Extract params from name_with_params: "FuncName(type1 param1, type2 param2)"
                nwp = original_func['name_with_params']
                paren_pos = nwp.find('(')
                if paren_pos >= 0:
                    params = nwp[paren_pos + 1:].rstrip(')')
                else:
                    params = ''
            else:
                params = original_func.get('parameters', '')
            
            orig_signature = f"{orig_return_type} {orig_name}({params})"
        
        # Update mutated function to use original signature
        mutated_body = mutated_func.get('body', '')
        
        if mutated_body and orig_signature:
            # Find first opening brace in mutated body
            brace_pos = mutated_body.find('{')
            if brace_pos > 0:
                # --- PARAMETER RENAME FIX ---
                # Before replacing the signature, extract param names from BOTH
                # signatures to detect any renames the LLM made.
                mutated_signature = mutated_body[:brace_pos].rstrip()
                
                # Get original param names (prefer tree-sitter data, fallback to parsing)
                orig_param_names = original_func.get('parameter_name_list', [])
                if not orig_param_names:
                    orig_param_names = cls._extract_param_names_from_signature(orig_signature)
                
                # Get mutated param names (always parse from signature string)
                mutated_param_names = cls._extract_param_names_from_signature(mutated_signature)
                
                # Get body content (everything from first {)
                body_content = mutated_body[brace_pos:]
                
                # Rename any changed parameters in the body
                if (orig_param_names and mutated_param_names 
                        and len(orig_param_names) == len(mutated_param_names)):
                    # Build rename map: mutated_name -> original_name
                    rename_map = {}
                    for orig_name, mut_name in zip(orig_param_names, mutated_param_names):
                        if orig_name != mut_name:
                            rename_map[mut_name] = orig_name
                    
                    if rename_map:
                        logger.info(f"  Parameter rename fix: {rename_map}")
                        # Use two-phase replacement to avoid conflicts
                        # Phase 1: replace mutated names with unique placeholders
                        placeholders = {}
                        for i, (mut_name, orig_name) in enumerate(rename_map.items()):
                            placeholder = f"__PARAM_PLACEHOLDER_{i}_{id(body_content)}__"
                            placeholders[placeholder] = orig_name
                            body_content = re.sub(
                                r'\b' + re.escape(mut_name) + r'\b',
                                placeholder,
                                body_content
                            )
                        # Phase 2: replace placeholders with original names
                        for placeholder, orig_name in placeholders.items():
                            body_content = body_content.replace(placeholder, orig_name)
                
                # Reconstruct with original signature
                new_body = f"{orig_signature} {body_content}"
                
                mutated_func['body'] = new_body
                mutated_func['return_type'] = original_func.get('return_type', '')
                mutated_func['name_only'] = original_func.get('name_only', '')
        
        return mutated_func
    
    @classmethod
    def add_mutation_safety_prompt(cls, constraints: MutationConstraints) -> str:
        """
        Generate prompt addition for LLM to ensure safe mutations.
        
        Returns:
            Additional prompt text
        """
        prompt = "\n=== MUTATION SAFETY CONSTRAINTS ===\n"
        prompt += "CRITICAL: You MUST preserve the following:\n\n"
        
        if constraints.preserve_signatures:
            prompt += "1. Function Signatures: Keep the EXACT same function name, return type, and parameters\n"
            prompt += "   - Change only the function body (code between { })\n"
            prompt += "   - Do NOT rename functions or change their parameters\n\n"
        
        if constraints.preserve_entry_points:
            prompt += "2. Entry Points: NEVER modify these functions:\n"
            prompt += f"   {', '.join(MutationStrategyImprover.ENTRY_POINTS)}\n\n"
        
        if constraints.preserve_system_includes:
            prompt += "3. System Includes: Keep all #include statements for system headers\n"
            prompt += "   - Especially: windows.h, stdio.h, stdlib.h, winsock2.h\n\n"
        
        if constraints.preserve_functions:
            prompt += "4. Critical Functions: Do NOT modify functions that are:\n"
            prompt += "   - Exported (marked with __declspec, WINAPI, CALLBACK)\n"
            prompt += "   - Referenced across multiple files\n"
            prompt += "   - Have critical prefixes (Dll*, Create*, Init*, etc.)\n\n"
        
        # ── NEW: API/function invention prohibition ──
        prompt += "5. FUNCTION & API USAGE RULES (LINKER SAFETY):\n"
        prompt += "   - You MAY create NEW helper functions for obfuscation or restructuring, but you MUST provide their COMPLETE definition in your output.\n"
        prompt += "   - NEVER call any function (custom or API) without either: (a) it being defined in the project code, (b) you defining it in your output, or (c) it being a real Windows/C standard library function.\n"
        prompt += "   - If the original code calls _memcpy, _memset, _xor, etc., keep calling those EXACT names. Do NOT replace them with memcpy, memset, or any other name.\n"
        prompt += "   - If the original code calls RegSetValueExW, keep that EXACT API name. Do NOT replace it with made-up names like SetRegistryValueW or WriteRegistryValue.\n"
        prompt += "   - ONLY use Windows API functions that actually exist in the Windows SDK (kernel32, user32, advapi32, ws2_32, etc.).\n"
        prompt += "   - When adding new helper functions for obfuscation, you MUST define them in your output. Never call a function without defining it.\n"
        prompt += "   - Do NOT rename calls to project-defined helper functions (e.g. _memcpy, _memset, _xor, base64_encode, base64_decode). These are custom implementations, NOT standard library functions.\n\n"
        
        prompt += "Your mutation should ONLY modify the internal implementation logic.\n"
        prompt += "The external interface (signature, includes, exports) MUST remain identical.\n"
        
        return prompt


def main():
    """Test mutation strategy improver"""
    print("Testing Mutation Strategy Improver")
    print("=" * 60)
    print("Note: This requires a real project to test properly")


if __name__ == "__main__":
    main()

