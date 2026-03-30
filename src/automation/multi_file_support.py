"""
Multi-File Compilation Support
==============================
Handles cross-file dependencies for multi-file C/C++ projects.

Features:
- Extracts missing symbols from MSVC/GCC errors
- Finds symbol definitions across project files
- Auto-injects forward declarations, externs, and includes
- Provides enhanced context for LLM fixer
"""
import os
import re
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class SymbolDefinition:
    """A symbol definition found in the project"""
    name: str
    kind: str  # 'function', 'type', 'global', 'typedef', 'struct', 'enum', 'macro'
    declaration: str  # The declaration text
    definition: Optional[str]  # Full definition if available
    file_path: str
    line_number: int
    is_static: bool = False  # static = file-local
    
    def get_forward_declaration(self) -> str:
        """Get forward declaration suitable for injection"""
        if self.kind == 'function':
            return self.declaration if self.declaration.endswith(';') else self.declaration + ';'
        elif self.kind in ('struct', 'class', 'union'):
            return f"{self.kind} {self.name};"
        elif self.kind == 'typedef':
            return self.declaration
        elif self.kind == 'global':
            # For globals, add extern
            return f"extern {self.declaration}" if not self.declaration.startswith('extern') else self.declaration
        elif self.kind == 'enum':
            # Enums can't be forward declared simply, need full definition
            return self.definition or f"enum {self.name};"
        return self.declaration
    
    def get_include_header(self) -> Optional[str]:
        """If defined in a header, return the include statement"""
        if self.file_path.endswith('.h') or self.file_path.endswith('.hpp'):
            basename = os.path.basename(self.file_path)
            return f'#include "{basename}"'
        return None


@dataclass
class ProjectSymbolIndex:
    """Index of all symbols in a project"""
    # symbol_name -> list of definitions (multiple files may define same name)
    functions: Dict[str, List[SymbolDefinition]] = field(default_factory=dict)
    types: Dict[str, List[SymbolDefinition]] = field(default_factory=dict)
    globals: Dict[str, List[SymbolDefinition]] = field(default_factory=dict)
    macros: Dict[str, List[SymbolDefinition]] = field(default_factory=dict)
    
    # namespace_name -> list of headers that define this namespace
    namespaces: Dict[str, List[str]] = field(default_factory=dict)
    
    # file_path -> symbols defined in that file
    file_symbols: Dict[str, Set[str]] = field(default_factory=dict)
    
    # file_path -> symbols used in that file
    file_uses: Dict[str, Set[str]] = field(default_factory=dict)
    
    # header_basename -> full path
    headers: Dict[str, str] = field(default_factory=dict)
    
    def lookup(self, symbol: str) -> Optional[SymbolDefinition]:
        """Look up a symbol, returning best definition"""
        # Check functions first
        if symbol in self.functions and self.functions[symbol]:
            # Prefer header declarations
            for defn in self.functions[symbol]:
                if defn.file_path.endswith('.h'):
                    return defn
            return self.functions[symbol][0]
        
        # Then types
        if symbol in self.types and self.types[symbol]:
            for defn in self.types[symbol]:
                if defn.file_path.endswith('.h'):
                    return defn
            return self.types[symbol][0]
        
        # Then globals
        if symbol in self.globals and self.globals[symbol]:
            for defn in self.globals[symbol]:
                # Prefer extern declarations
                if 'extern' in defn.declaration:
                    return defn
            return self.globals[symbol][0]
        
        # Then macros
        if symbol in self.macros and self.macros[symbol]:
            return self.macros[symbol][0]
        
        # Check namespaces (for C++ namespace::func style errors)
        if symbol in self.namespaces and self.namespaces[symbol]:
            # Prefer header files
            for file_path in self.namespaces[symbol]:
                if file_path.endswith('.h'):
                    return SymbolDefinition(
                        name=symbol,
                        kind='namespace',
                        declaration=f'namespace {symbol} {{ ... }}',
                        definition=f'namespace {symbol}',
                        file_path=file_path,
                        line_number=1
                    )
            # Return first file if no header found
            return SymbolDefinition(
                name=symbol,
                kind='namespace',
                declaration=f'namespace {symbol} {{ ... }}',
                definition=f'namespace {symbol}',
                file_path=self.namespaces[symbol][0],
                line_number=1
            )
        
        return None
    
    def get_all_symbols(self) -> Set[str]:
        """Get all known symbol names"""
        symbols = set()
        symbols.update(self.functions.keys())
        symbols.update(self.types.keys())
        symbols.update(self.globals.keys())
        symbols.update(self.macros.keys())
        symbols.update(self.namespaces.keys())  # Include namespaces
        return symbols
    
    def to_context_for_file(self, file_path: str, missing_symbols: Set[str], max_length: int = 10000) -> str:
        """Generate context string for fixing a specific file"""
        lines = ["=== PROJECT SYMBOLS CONTEXT ==="]
        
        # Find definitions for missing symbols
        resolved = []
        unresolved = []
        
        for sym in sorted(missing_symbols):
            defn = self.lookup(sym)
            if defn:
                resolved.append((sym, defn))
            else:
                unresolved.append(sym)
        
        if resolved:
            lines.append("\n--- AVAILABLE DEFINITIONS (from other project files) ---")
            for sym, defn in resolved:
                lines.append(f"\n// {sym} is defined in {os.path.basename(defn.file_path)}:")
                lines.append(defn.get_forward_declaration())
        
        if unresolved:
            lines.append("\n--- SYMBOLS NOT FOUND IN PROJECT ---")
            lines.append(f"// These may be from system headers: {', '.join(unresolved)}")
        
        # Add file's direct dependencies
        if file_path in self.file_uses:
            uses = self.file_uses[file_path] - set(self.file_symbols.get(file_path, set()))
            external_uses = [u for u in uses if self.lookup(u)]
            if external_uses:
                lines.append("\n--- EXTERNALLY DEFINED SYMBOLS USED IN THIS FILE ---")
                for sym in sorted(external_uses)[:30]:
                    defn = self.lookup(sym)
                    if defn:
                        lines.append(f"{defn.kind}: {sym} (from {os.path.basename(defn.file_path)})")
        
        result = "\n".join(lines)
        if len(result) > max_length:
            result = result[:max_length] + "\n... (truncated)"
        return result


class MultiFileCompilationSupport:
    """
    Provides multi-file compilation support:
    - Builds symbol index from project
    - Extracts missing symbols from errors
    - Auto-resolves cross-file dependencies
    - Injects necessary declarations
    """
    
    # MSVC error patterns for undefined symbols
    MSVC_UNDECLARED_PATTERNS = [
        # C2065: 'symbol' : undeclared identifier
        re.compile(r"error C2065:\s*['\"]?(\w+)['\"]?\s*:", re.IGNORECASE),
        # C3861: 'symbol': identifier not found
        re.compile(r"error C3861:\s*['\"]?(\w+)['\"]?\s*:", re.IGNORECASE),
        # C2061: syntax error : identifier 'symbol'
        re.compile(r"error C2061:.*identifier\s*['\"]?(\w+)['\"]?", re.IGNORECASE),
        # C2039: 'symbol' : is not a member
        re.compile(r"error C2039:\s*['\"]?(\w+)['\"]?\s*:", re.IGNORECASE),
        # C2146: syntax error : missing ';' before identifier 'symbol'
        re.compile(r"error C2146:.*identifier\s*['\"]?(\w+)['\"]?", re.IGNORECASE),
        # LNK2019: unresolved external symbol "symbol"
        re.compile(r"LNK2019:.*symbol\s*['\"]?(\w+)['\"]?", re.IGNORECASE),
        # LNK2001: unresolved external symbol "symbol"
        re.compile(r"LNK2001:.*symbol\s*['\"]?(\w+)['\"]?", re.IGNORECASE),
        # C2653: 'namespace': is not a class or namespace type
        re.compile(r"error C2653:\s*['\"]?(\w+)['\"]?\s*:", re.IGNORECASE),
    ]
    
    # GCC error patterns for undefined symbols
    GCC_UNDECLARED_PATTERNS = [
        # error: 'symbol' undeclared
        re.compile(r"error:\s*['\"]?(\w+)['\"]?\s*undeclared", re.IGNORECASE),
        # error: 'symbol' was not declared in this scope
        re.compile(r"error:\s*['\"]?(\w+)['\"]?\s*was not declared", re.IGNORECASE),
        # error: unknown type name 'symbol'
        re.compile(r"error:\s*unknown type name\s*['\"]?(\w+)['\"]?", re.IGNORECASE),
        # error: use of undeclared identifier 'symbol'
        re.compile(r"error:\s*use of undeclared identifier\s*['\"]?(\w+)['\"]?", re.IGNORECASE),
        # undefined reference to 'symbol'
        re.compile(r"undefined reference to\s*['\"`]?(\w+)['\"`]?", re.IGNORECASE),
        # error: implicit declaration of function 'symbol'
        re.compile(r"error:\s*implicit declaration of function\s*['\"]?(\w+)['\"]?", re.IGNORECASE),
    ]
    
    # Symbols to skip (C/C++ keywords, common FALSE positives)
    SKIP_SYMBOLS = {
        'void', 'int', 'char', 'short', 'long', 'float', 'double', 'unsigned', 'signed',
        'const', 'static', 'extern', 'volatile', 'register', 'auto', 'inline',
        'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'default', 'break', 'continue',
        'return', 'goto', 'sizeof', 'typedef', 'struct', 'union', 'enum', 'class',
        'public', 'private', 'protected', 'virtual', 'template', 'typename', 'namespace',
        'true', 'false', 'nullptr', 'NULL', 'TRUE', 'FALSE',
        'BOOL', 'BYTE', 'WORD', 'DWORD', 'QWORD', 'INT', 'UINT', 'LONG', 'ULONG',
        'LPSTR', 'LPCSTR', 'LPWSTR', 'LPCWSTR', 'LPTSTR', 'LPCTSTR',
        'PVOID', 'LPVOID', 'HANDLE', 'HWND', 'HINSTANCE', 'HMODULE',
        'SIZE_T', 'SSIZE_T', 'LRESULT', 'WPARAM', 'LPARAM',
    }
    
    # Patterns for extracting definitions from code
    FUNCTION_DEF_PATTERN = re.compile(
        r'^\s*(?:static\s+)?(?:STATIC\s+)?(?:inline\s+)?(?:extern\s+)?'
        r'([A-Za-z_][\w\s\*&]+?)\s+'
        r'(?:WINAPI\s+|CALLBACK\s+|__cdecl\s+|__stdcall\s+)?'
        r'([A-Za-z_]\w*)\s*'
        r'\(([^)]*)\)\s*[{;]',
        re.MULTILINE
    )
    
    STRUCT_DEF_PATTERN = re.compile(
        r'^\s*(typedef\s+)?(struct|union|enum)\s+(?:([A-Za-z_]\w*)\s*)?'
        r'\{([^}]*)\}\s*([A-Za-z_]\w*)?;',
        re.MULTILINE | re.DOTALL
    )
    
    SIMPLE_TYPEDEF_PATTERN = re.compile(
        r'^\s*typedef\s+(.+?)\s+([A-Za-z_]\w*)\s*;',
        re.MULTILINE
    )
    
    # Pattern for macro-based typedefs like: typedef TAILQ_HEAD(...) NAME, *PNAME;
    MACRO_TYPEDEF_PATTERN = re.compile(
        r'^\s*typedef\s+([A-Z_][A-Z0-9_]*)\s*\([^)]+\)\s*([A-Za-z_]\w*)\s*,?\s*\*?\s*([A-Za-z_]\w*)?\s*;',
        re.MULTILINE
    )
    
    # Global variable pattern - handles arrays like g_Name[100] and STATIC macro
    GLOBAL_VAR_PATTERN = re.compile(
        r'^\s*(extern\s+|STATIC\s+|static\s+)?([A-Za-z_][\w\s\*]+?)\s+([A-Za-z_]\w*)(\[\d*\])?\s*(?:=\s*[^;]+)?;',
        re.MULTILINE
    )
    
    MACRO_PATTERN = re.compile(
        r'^\s*#\s*define\s+([A-Za-z_]\w*)(?:\([^)]*\))?\s+.*',
        re.MULTILINE
    )
    
    def __init__(self):
        self.index: Optional[ProjectSymbolIndex] = None
    
    def build_index(self, project) -> ProjectSymbolIndex:
        """Build symbol index from project files"""
        logger.info("Building symbol index for multi-file compilation support...")
        
        self.index = ProjectSymbolIndex()
        
        # Index header files first (these provide declarations)
        for header_file in getattr(project, 'header_files', []):
            self._index_file(header_file, is_header=True)
        
        # Then source files (these provide definitions)
        for source_file in getattr(project, 'source_files', []):
            self._index_file(source_file, is_header=False)
        
        total_symbols = len(self.index.get_all_symbols())
        logger.info(f"  Indexed {total_symbols} symbols across {len(self.index.file_symbols)} files")
        logger.info(f"  Functions: {len(self.index.functions)}, Types: {len(self.index.types)}, Globals: {len(self.index.globals)}, Namespaces: {len(self.index.namespaces)}")
        
        return self.index
    
    def _index_file(self, file_path: str, is_header: bool = False):
        """Index a single file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            file_symbols = set()
            file_uses = set()
            
            # Track header basename for include resolution
            if is_header:
                basename = os.path.basename(file_path)
                self.index.headers[basename] = file_path
            
            # Extract namespace declarations (important for C++ projects)
            namespace_pattern = re.compile(r'\bnamespace\s+(\w+)\s*\{', re.MULTILINE)
            for match in namespace_pattern.finditer(content):
                ns_name = match.group(1)
                if ns_name not in self.index.namespaces:
                    self.index.namespaces[ns_name] = []
                # Track which file defines this namespace
                if file_path not in self.index.namespaces[ns_name]:
                    self.index.namespaces[ns_name].append(file_path)
                file_symbols.add(ns_name)
            
            # Extract function definitions/declarations
            for match in self.FUNCTION_DEF_PATTERN.finditer(content):
                return_type = match.group(1).strip()
                func_name = match.group(2).strip()
                params = match.group(3).strip()
                
                # Skip main entry points
                if func_name in ('main', 'WinMain', 'wWinMain', '_start', '_tmain', 'wmain'):
                    continue
                
                is_static = 'static' in return_type or match.group(0).strip().startswith('static')
                
                # Clean up return type (remove static/inline)
                return_type = re.sub(r'\b(static|inline|extern)\b', '', return_type).strip()
                
                declaration = f"{return_type} {func_name}({params})"
                
                defn = SymbolDefinition(
                    name=func_name,
                    kind='function',
                    declaration=declaration,
                    definition=match.group(0),
                    file_path=file_path,
                    line_number=content[:match.start()].count('\n') + 1,
                    is_static=is_static
                )
                
                if func_name not in self.index.functions:
                    self.index.functions[func_name] = []
                self.index.functions[func_name].append(defn)
                file_symbols.add(func_name)
            
            # Extract struct/union/enum definitions with typedef
            for match in self.STRUCT_DEF_PATTERN.finditer(content):
                has_typedef = match.group(1) is not None
                kind = match.group(2)  # struct, union, enum
                tag_name = match.group(3)  # name after struct/union/enum
                typedef_name = match.group(5)  # name after closing brace
                body = match.group(4)  # content inside braces
                
                names = []
                if tag_name:
                    names.append(tag_name)
                if typedef_name and typedef_name != tag_name:
                    names.append(typedef_name)
                
                for name in names:
                    defn = SymbolDefinition(
                        name=name,
                        kind=kind,
                        declaration=f"{kind} {name}",
                        definition=match.group(0),
                        file_path=file_path,
                        line_number=content[:match.start()].count('\n') + 1
                    )
                    
                    if name not in self.index.types:
                        self.index.types[name] = []
                    self.index.types[name].append(defn)
                    file_symbols.add(name)
            
            # Extract simple typedefs (typedef existing_type new_name;)
            for match in self.SIMPLE_TYPEDEF_PATTERN.finditer(content):
                base_type = match.group(1).strip()
                typedef_name = match.group(2).strip()
                
                # Skip if it's a function pointer or struct typedef we already handled
                if '(' in base_type or typedef_name in self.index.types:
                    continue
                
                defn = SymbolDefinition(
                    name=typedef_name,
                    kind='typedef',
                    declaration=match.group(0).strip(),
                    definition=match.group(0),
                    file_path=file_path,
                    line_number=content[:match.start()].count('\n') + 1
                )
                
                if typedef_name not in self.index.types:
                    self.index.types[typedef_name] = []
                self.index.types[typedef_name].append(defn)
                file_symbols.add(typedef_name)
            
            # Extract macro-based typedefs (typedef TAILQ_HEAD(...) NAME, *PNAME;)
            for match in self.MACRO_TYPEDEF_PATTERN.finditer(content):
                macro_name = match.group(1)  # e.g., TAILQ_HEAD
                type_name = match.group(2)   # e.g., SUBNET_LIST
                ptr_name = match.group(3)    # e.g., PSUBNET_LIST (optional)
                
                # Add base type name
                if type_name and type_name not in self.index.types:
                    defn = SymbolDefinition(
                        name=type_name,
                        kind='typedef',
                        declaration=f"typedef struct {type_name.lower()}_ {type_name};",
                        definition=match.group(0),
                        file_path=file_path,
                        line_number=content[:match.start()].count('\n') + 1
                    )
                    self.index.types[type_name] = [defn]
                    file_symbols.add(type_name)
                
                # Add pointer type name if present
                if ptr_name and ptr_name not in self.index.types:
                    defn = SymbolDefinition(
                        name=ptr_name,
                        kind='typedef',
                        declaration=f"typedef {type_name}* {ptr_name};",
                        definition=match.group(0),
                        file_path=file_path,
                        line_number=content[:match.start()].count('\n') + 1
                    )
                    self.index.types[ptr_name] = [defn]
                    file_symbols.add(ptr_name)
            
            # Extract global variables
            for match in self.GLOBAL_VAR_PATTERN.finditer(content):
                # Skip if inside a function (rough heuristic: check if after a '{')
                preceding = content[:match.start()]
                open_braces = preceding.count('{')
                close_braces = preceding.count('}')
                if open_braces > close_braces:
                    continue  # Likely inside a function
                
                prefix = match.group(1) or ''
                is_extern = 'extern' in prefix.lower()
                is_static = 'static' in prefix.lower() or 'STATIC' in prefix
                var_type = match.group(2).strip()
                var_name = match.group(3).strip()
                
                # Skip if it looks like a function declaration
                if '(' in var_type:
                    continue
                
                # Clean up type (remove STATIC/static/extern)
                var_type = re.sub(r'\b(static|STATIC|extern)\b', '', var_type).strip()
                
                # Skip built-in types as standalone (they're likely local vars)
                if var_type.lower() in ('int', 'char', 'void', 'short', 'long', 'float', 'double'):
                    continue
                
                declaration = f"extern {var_type} {var_name};"
                
                defn = SymbolDefinition(
                    name=var_name,
                    kind='global',
                    declaration=declaration,
                    definition=match.group(0),
                    file_path=file_path,
                    line_number=content[:match.start()].count('\n') + 1,
                    is_static=is_static
                )
                
                if var_name not in self.index.globals:
                    self.index.globals[var_name] = []
                self.index.globals[var_name].append(defn)
                file_symbols.add(var_name)
            
            # Extract macro definitions
            for match in self.MACRO_PATTERN.finditer(content):
                macro_name = match.group(1)
                
                defn = SymbolDefinition(
                    name=macro_name,
                    kind='macro',
                    declaration=match.group(0).strip(),
                    definition=match.group(0),
                    file_path=file_path,
                    line_number=content[:match.start()].count('\n') + 1
                )
                
                if macro_name not in self.index.macros:
                    self.index.macros[macro_name] = []
                self.index.macros[macro_name].append(defn)
                file_symbols.add(macro_name)
            
            # Extract uses (identifiers used in the file)
            # This is a rough extraction - looks for identifier patterns
            identifier_pattern = re.compile(r'\b([A-Za-z_]\w*)\b')
            for match in identifier_pattern.finditer(content):
                ident = match.group(1)
                if ident not in self.SKIP_SYMBOLS and len(ident) > 1:
                    file_uses.add(ident)
            
            self.index.file_symbols[file_path] = file_symbols
            self.index.file_uses[file_path] = file_uses
            
        except Exception as e:
            logger.warning(f"Failed to index {file_path}: {e}")
    
    def extract_missing_symbols_from_errors(self, errors: List[str]) -> Set[str]:
        """Extract undefined symbol names from compiler errors"""
        missing = set()
        
        for error in errors:
            # Try MSVC patterns
            for pattern in self.MSVC_UNDECLARED_PATTERNS:
                match = pattern.search(error)
                if match:
                    symbol = match.group(1)
                    if symbol not in self.SKIP_SYMBOLS and len(symbol) > 1:
                        missing.add(symbol)
            
            # Try GCC patterns
            for pattern in self.GCC_UNDECLARED_PATTERNS:
                match = pattern.search(error)
                if match:
                    symbol = match.group(1)
                    if symbol not in self.SKIP_SYMBOLS and len(symbol) > 1:
                        missing.add(symbol)
        
        return missing
    
    def resolve_missing_symbols(self, missing_symbols: Set[str]) -> Dict[str, SymbolDefinition]:
        """Find non-static definitions for missing symbols in the project index"""
        if not self.index:
            logger.warning("No index built - call build_index first")
            return {}
        
        resolved = {}
        for symbol in missing_symbols:
            defn = self.index.lookup(symbol)
            if defn and not defn.is_static:  # Can't use static symbols from other files
                resolved[symbol] = defn
        
        return resolved

    def resolve_missing_symbols_with_statics(
        self, missing_symbols: Set[str]
    ) -> Tuple[Dict[str, SymbolDefinition], Dict[str, SymbolDefinition]]:
        """Resolve missing symbols, returning both usable and static-only definitions.

        Returns:
            (resolved, static_only) where:
              - resolved: symbols that can be used directly (non-static)
              - static_only: symbols found but marked static (contextual hints only)
        """
        if not self.index:
            logger.warning("No index built - call build_index first")
            return {}, {}

        resolved = {}
        static_only = {}

        for symbol in missing_symbols:
            defn = self.index.lookup(symbol)
            if not defn:
                continue

            if defn.is_static:
                static_only[symbol] = defn
            else:
                resolved[symbol] = defn

        return resolved, static_only
    
    def generate_forward_declarations(
        self,
        missing_symbols: Set[str],
        target_file: str,
        include_static_hints: bool = True
    ) -> str:
        """
        Generate forward declarations block for missing symbols.
        
        Returns:
            String with forward declarations to inject
        """
        if not self.index:
            return ""
        
        resolved, static_only = self.resolve_missing_symbols_with_statics(missing_symbols)
        
        if not resolved and not static_only:
            return ""
        
        lines = ["\n/* === Auto-injected cross-file declarations === */\n"]
        
        # Group by type for better organization
        includes_needed = set()
        type_decls = []
        func_decls = []
        global_decls = []
        
        for symbol, defn in sorted(resolved.items()):
            # Prefer including header if symbol is defined in one
            header_include = defn.get_include_header()
            if header_include and defn.file_path != target_file:
                includes_needed.add(header_include)
            # For namespaces, always use include (cannot forward declare namespaces)
            elif defn.kind == 'namespace':
                basename = os.path.basename(defn.file_path)
                includes_needed.add(f'#include "{basename}"')
            else:
                # Need forward declaration
                fwd = defn.get_forward_declaration()
                if defn.kind in ('struct', 'union', 'enum', 'typedef', 'class'):
                    type_decls.append(f"/* From {os.path.basename(defn.file_path)} */ {fwd}")
                elif defn.kind == 'function':
                    func_decls.append(f"/* From {os.path.basename(defn.file_path)} */ {fwd}")
                elif defn.kind == 'global':
                    global_decls.append(f"/* From {os.path.basename(defn.file_path)} */ {fwd}")
        
        # Add includes first
        for inc in sorted(includes_needed):
            lines.append(inc)
        
        if includes_needed:
            lines.append("")
        
        # Add type declarations
        if type_decls:
            lines.append("/* Forward type declarations */")
            lines.extend(type_decls)
            lines.append("")
        
        # Add function declarations
        if func_decls:
            lines.append("/* External function declarations */")
            lines.extend(func_decls)
            lines.append("")
        
        # Add global extern declarations
        if global_decls:
            lines.append("/* External global variables */")
            lines.extend(global_decls)
            lines.append("")

        if include_static_hints and static_only:
            lines.append("/* Static-only definitions found in other files */")
            lines.append("/* To use these, move them to a header or copy the implementation here and remove 'static'. */")
            for symbol, defn in sorted(static_only.items()):
                preview = defn.definition or defn.declaration
                if preview and len(preview) > 200:
                    preview = preview[:200].strip() + " ..."
                location = f"{os.path.basename(defn.file_path)}:{defn.line_number}"
                hint = preview or defn.declaration or "<definition unavailable>"
                lines.append(f"// {symbol} (static in {location}) -> {hint}")
            lines.append("")
        
        lines.append("/* === End auto-injected declarations === */\n")
        
        return "\n".join(lines)
    
    def inject_declarations_into_file(
        self,
        file_path: str,
        missing_symbols: Set[str],
        dry_run: bool = False
    ) -> Tuple[bool, str]:
        """
        Inject necessary declarations into a file.
        
        Args:
            file_path: Path to file
            missing_symbols: Set of undefined symbols
            dry_run: If True, return modified content without writing
            
        Returns:
            (success, modified_content or error_message)
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            declarations = self.generate_forward_declarations(missing_symbols, file_path)
            
            if not declarations.strip() or declarations.strip() == "/* === Auto-injected cross-file declarations === */\n/* === End auto-injected declarations === */":
                return True, content  # Nothing to inject
            
            # Find insertion point (after last #include or pragma once)
            insert_pos = self._find_insertion_point(content)
            
            new_content = content[:insert_pos] + declarations + content[insert_pos:]
            
            if dry_run:
                return True, new_content
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            logger.info(f"✓ Injected {len(missing_symbols)} forward declarations into {os.path.basename(file_path)}")
            return True, new_content
        
        except Exception as e:
            logger.error(f"Failed to inject declarations into {file_path}: {e}")
            return False, str(e)
    
    def _find_insertion_point(self, content: str) -> int:
        """Find best insertion point for declarations (after includes)"""
        # Find last #include or #pragma once
        patterns = [
            re.compile(r'#\s*include\s+[<"][^>"]+[>"]'),
            re.compile(r'#\s*pragma\s+once'),
        ]
        
        last_pos = 0
        for pattern in patterns:
            for match in pattern.finditer(content):
                end_pos = content.find('\n', match.end()) + 1
                if end_pos > last_pos:
                    last_pos = end_pos
        
        # If no includes found, insert at the beginning (after any initial comment)
        if last_pos == 0:
            # Skip initial block comment
            if content.startswith('/*'):
                end_comment = content.find('*/')
                if end_comment != -1:
                    last_pos = content.find('\n', end_comment) + 1
        
        return last_pos
    
    def get_context_for_file(
        self,
        file_path: str,
        errors: List[str],
        max_length: int = 10000
    ) -> str:
        """
        Get enhanced context for fixing a specific file.
        
        Args:
            file_path: Path to source file with errors
            errors: List of compilation errors
            max_length: Maximum context string length
            
        Returns:
            Context string for LLM
        """
        if not self.index:
            return ""
        
        # Extract missing symbols from errors
        missing = self.extract_missing_symbols_from_errors(errors)

        # Include static-only symbols for hinting
        _, static_only = self.resolve_missing_symbols_with_statics(missing)
        static_hints = []
        for sym, defn in sorted(static_only.items()):
            location = f"{os.path.basename(defn.file_path)}:{defn.line_number}"
            static_hints.append(f"{sym} (static in {location})")
        
        base_context = self.index.to_context_for_file(file_path, missing, max_length)

        if static_hints:
            hint_block = "\n--- STATIC-ONLY DEFINITIONS (need moving or copying) ---\n" + "\n".join(
                f"// {hint}" for hint in static_hints
            )
            combined = base_context + "\n" + hint_block
            if len(combined) > max_length:
                combined = combined[:max_length] + "\n... (truncated)"
            return combined

        return base_context
    
    def auto_fix_cross_file_dependencies(
        self,
        project,
        errors: List[str],
        affected_file: str
    ) -> Tuple[int, List[str]]:
        """
        Automatically fix cross-file dependency errors.
        
        Args:
            project: MalwareProject
            errors: Compilation errors
            affected_file: File to fix
            
        Returns:
            (number_of_fixes, remaining_errors)
        """
        if not self.index:
            self.build_index(project)
        
        # Extract missing symbols
        missing = self.extract_missing_symbols_from_errors(errors)
        
        if not missing:
            return 0, errors
        
        # Resolve symbols
        resolved = self.resolve_missing_symbols(missing)
        
        if not resolved:
            return 0, errors
        
        # Inject declarations
        success, _ = self.inject_declarations_into_file(affected_file, set(resolved.keys()))
        
        if success:
            # Filter out resolved errors
            remaining = []
            resolved_names = set(resolved.keys())
            
            for error in errors:
                error_mentions_resolved = False
                for name in resolved_names:
                    if name in error:
                        error_mentions_resolved = True
                        break
                
                if not error_mentions_resolved:
                    remaining.append(error)
            
            return len(resolved), remaining
        
        return 0, errors


# Singleton instance for easy access
_support_instance: Optional[MultiFileCompilationSupport] = None


def get_multi_file_support() -> MultiFileCompilationSupport:
    """Get the singleton MultiFileCompilationSupport instance"""
    global _support_instance
    if _support_instance is None:
        _support_instance = MultiFileCompilationSupport()
    return _support_instance


def main():
    """Test multi-file support"""
    print("Multi-File Compilation Support")
    print("=" * 60)
    
    # Test error parsing
    support = MultiFileCompilationSupport()
    
    test_errors = [
        "error C2065: 'g_PrivateKey': undeclared identifier",
        "error C3861: 'ChangeFileName': identifier not found",
        "error C2061: syntax error : identifier 'LPFILE_INFO'",
        "error: 'MyStruct' was not declared in this scope",
        "undefined reference to `helper_function'",
    ]
    
    missing = support.extract_missing_symbols_from_errors(test_errors)
    print(f"Extracted missing symbols: {missing}")


if __name__ == "__main__":
    main()
