def _get_language_specific_prohibitions(language: str, compiler_type: str = 'msvc') -> str:
    """Return language-specific absolute prohibitions for mutation prompts."""
    if language == "python":
        return (
            "\nABSOLUTE PROHIBITIONS:\n"
            "- NEVER delete, remove, or shorten ANY existing logic. Only ADD, REPLACE, or WRAP with equivalents.\n"
            "- NEVER replace function bodies with stubs, comments, or placeholders like 'pass # todo'.\n"
            "- NEVER output empty function bodies or bodies with only 'pass' or 'raise NotImplementedError'.\n"
            "- Your output MUST execute ALL original variable assignments and ALL original logic. Nothing removed.\n"
            "- Keep ALL original function/method calls. Only change HOW or WHERE they are resolved, not WHETHER they are called.\n"
            "- NEVER rename calls to existing project functions/classes imported from other project modules. Keep their exact names and call sites.\n"
            "- If the function is a class method (has 'self' parameter), keep 'self' as the first parameter name. You may rename other parameters as part of strat_5.\n"
            "- NEVER change 4-space indentation of the function body. All added code must also use 4-space indentation.\n"
            "- When using dynamic __import__ or getattr: ensure the resolved name exactly matches the original module/attribute name. Wrong names cause runtime failures.\n"
            "- For strat_4 (function splitting): extract logical blocks into inner helper functions. NEVER remove or skip any original logic.\n"
        )
    elif language == "javascript":
        return (
            "\nABSOLUTE PROHIBITIONS:\n"
            "- NEVER delete, remove, or shorten ANY existing logic. Only ADD, REPLACE, or WRAP with equivalents.\n"
            "- NEVER replace function bodies with stubs, comments, or placeholders.\n"
            "- NEVER output empty function bodies or bodies with only 'return;' or 'return undefined;'.\n"
            "- Your output MUST execute ALL original variable declarations and ALL original logic. Nothing removed.\n"
            "- Keep ALL original function calls. Only change HOW or WHERE they are resolved.\n"
            "- NEVER rename calls to existing project functions/modules required from other project files. Keep their exact call-site names.\n"
            "- Preserve the function signature (name, parameters) exactly unless explicitly rewriting to an arrow function equivalent.\n"
            "- When using dynamic require() or bracket notation: the resolved string MUST equal the original module/property name exactly.\n"
            "- For strat_4 (function splitting): extract logical blocks into separate helper functions. NEVER remove or skip any original logic.\n"
        )
    else:  # C/C++
        base = (
            "\nABSOLUTE PROHIBITIONS:\n"
            "- NEVER delete or remove ANY variable declaration, function call, or logic statement. Only ADD, REPLACE, or WRAP.\n"
            "- NEVER output empty/stub function bodies. Your output MUST contain ALL original logic.\n"
            "- Keep ALL original function/API calls. Only change HOW they are called, not WHETHER.\n"
            "- NEVER rename calls to existing project helper functions (e.g. _memcpy, _memset, _xor).\n"
            "- ONLY use Windows/CRT APIs that actually exist. NEVER invent fake API names.\n"
            "- GetProcAddress function name strings MUST exactly match documented Windows API names.\n"
            "- Function pointer typedefs MUST exactly match the real API signature (return type, calling convention, all param types).\n"
            "- NEVER shadow an existing variable with a different type (e.g. declaring `int hFile` when `HANDLE hFile` already exists).\n"
            "- NEVER merge two distinct variables into one (each original variable must keep its own storage).\n"
            "- Every helper function you create MUST have a complete body — no forward declarations without definitions.\n"
        )
        if language == "c":
            base += (
                "\nC-ONLY RULES (pure C, NOT C++):\n"
                "- NO C++ syntax: no static_cast, class, namespace, template, new, delete, throw, try, nullptr, auto, references (type&).\n"
                "- NO C++ headers: <iostream>, <vector>, <string>, <map>, <memory>, <algorithm>.\n"
                "- Use C-style casts: (type)expr. Use NULL not nullptr. Use BOOL/TRUE/FALSE not bool/true/false.\n"
                "- NEVER define functions inside another function body — C has NO nested functions.\n"
            )
            if compiler_type == 'msvc':
                base += "- Declare ALL variables at the TOP of a block before any statements (MSVC C89 compat).\n"
            else:
                base += "- Variables CAN be declared anywhere in a block (C99+). For-loop initializers like `for(int i=0;...)` are valid.\n"
            base += "- Every struct field access via pointer (e.g. `ctx->X`) MUST have a matching field defined in the struct.\n"
        return base


def _get_language_specific_features(language: str, strategy: str, compiler_type: str = 'msvc') -> str:
    """Return language-specific feature suggestions for a given strategy."""
    if language == "python":
        hints = {
            # strat_1: String & Constant Obfuscation
            "strat_1": (
                "PYTHON-SPECIFIC TECHNIQUES:\n"
                "- Define a decode lambda at top: `_d = lambda _b, _k=0x5A: ''.join(chr(_c ^ _k) for _c in _b)`\n"
                "- Encode a string like 'kernel32.dll' as: `_d([0x21^0x5A, 0x1f^0x5A, ...])` (pre-compute each byte XOR'd with 0x5A)\n"
                "- Alternative: split string across a list and join: `''.join(['ker','nel','32','.dll'])`\n"
                "- Alternative: reversed+slice: `'lld.23lenrek'[::-1]`\n"
                "- For module names being imported: encode 'os' as `chr(111)+chr(115)`, 'sys' as `chr(115)+chr(121)+chr(115)`\n"
                "- Replace numeric literals: `4096` → `(1<<12)`, `255` → `(0x100-1)`, `7` → `(0xf>>1)`\n"
            ),
            # strat_2: Dead Code + Opaque Predicates + Control Flow Flattening
            "strat_2": (
                "PYTHON-SPECIFIC TECHNIQUES:\n"
                "- Control flow flattening: wrap body in `_state = 0; while _state != 99:` with if/elif chain.\n"
                "- Opaque predicates: `_opq = type(None).__name__; if _opq == 'int':` (always false).\n"
                "- Dead code: `_junk = os.getpid() ^ 0xBAAD` or `_dc = len(str(id(None)))` between real blocks.\n"
                "- Dead imports inside unreachable branches: `if False: import antigravity`\n"
                "- ALL original logic MUST remain intact. Only ADD dead code and restructure flow.\n"
            ),
            # strat_3: Dynamic Import/API Resolution
            "strat_3": (
                "PYTHON-SPECIFIC TECHNIQUES:\n"
                "- Dynamic import with encoded name: `_os = __import__(''.join(chr(x) for x in [111,115]))`  # 'os'\n"
                "- fromlist import: `_req = getattr(__import__(''.join(chr(x) for x in [114,101,113,117,101,115,116,115])), 'get')`  # requests.get\n"
                "- getattr chain: `_winreg = getattr(__import__('winreg'), 'OpenKey')`\n"
                "- For ctypes: `_k32 = getattr(__import__('ctypes').windll, 'kerne'+'l32')`; then `getattr(_k32, 'VirtualAlloc')(...)` \n"
                "- For subprocess: `_sp = __import__('subproc'+'ess'); _run = getattr(_sp, 'run')`\n"
                "- Encode module names: 'ctypes' → `'cty'+'pes'`, 'socket' → `'so'+'cket'`, 'base64' → `'base'+'64'`\n"
            ),
            # strat_4: Function Splitting
            "strat_4": (
                "PYTHON-SPECIFIC TECHNIQUES:\n"
                "- Extract logical blocks into nested `def` helper functions defined INSIDE the main function.\n"
                "- Use closures: inner functions can read outer variables directly. To modify them, use `nonlocal`.\n"
                "- Pass mutable state via list/dict wrappers if needed: `_state = {'count': 0}` then modify `_state['count']`.\n"
                "- Name helpers: `_sub_FUNCNAME_0`, `_sub_FUNCNAME_1`, etc.\n"
                "- Each helper should handle one logical block: initialization, a major loop, a branch, cleanup.\n"
                "- The main function body becomes a sequence of helper calls.\n"
                "- SAFETY: Split MUST produce identical behavior to the original for ALL inputs.\n"
            ),
            # strat_5: Semantic Substitution
            "strat_5": (
                "PYTHON-SPECIFIC TECHNIQUES:\n"
                "- String concatenation: `a + b` → `''.join([a, b])` or `'%s%s' % (a, b)`\n"
                "- String contains: `sub in s` → `s.find(sub) != -1`\n"
                "- List append: `lst.append(x)` → `lst[len(lst):] = [x]`\n"
                "- Dict lookup: `d[k]` → `d.get(k)` (safe) or `(lambda _d,_k: _d[_k])(d, k)` (obfuscated)\n"
                "- isinstance check: `isinstance(x, str)` → `type(x).__name__ == 'str'`\n"
                "- For loop: `for i,v in enumerate(lst)` → `_i=0; _it=iter(lst); \ntry:\n    while True: v=next(_it); ...; _i+=1\nexcept StopIteration: pass`\n"
                "- `os.path.join(a,b)` → `str(__import__('pathlib').Path(a) / b)` (always safe for all path types)\n"
                "- `open(f).read()` → `__import__('io').open(f, mode='r', encoding='utf-8').read()`\n"
                "- Arithmetic: `x + 1` → `x - ~0`, `x * 4` → `x << 2`, `x % 2` → `x & 1`, `x == 0` → `not x`\n"
                "- SAFETY: Only apply substitutions that preserve exact behavior for ALL inputs including edge cases.\n"
            ),
            "strat_all": (
                "PYTHON-SPECIFIC TECHNIQUES:\n"
                "- Encode ALL strings: `_d = lambda _b, _k=0x37: ''.join(chr(_c ^ _k) for _c in _b)` then use _d([...]) everywhere.\n"
                "- All imports dynamic: `__import__(''.join(chr(x) for x in [<codes>]))`\n"
                                "- Replace 50% of ops with alternatives: join for concat, find for 'in', manual loop for enumerate.\n"
            ),
        }
        return hints.get(strategy, "")
    elif language == "javascript":
        hints = {
            # strat_1: String & Constant Obfuscation
            "strat_1": (
                "JAVASCRIPT-SPECIFIC TECHNIQUES:\n"
                "- Define decode helper at top: `const _d = (_b, _k=0x5A) => _b.map(_c => String.fromCharCode(_c ^ _k)).join('')`\n"
                "- Encode 'kernel32' as: `_d([0x21^0x5A, 0x1f^0x5A, ...])` — pre-compute each char code XOR'd with 0x5A\n"
                "- Alternative: split and join: `['ker','nel','32','.dll'].join('')`\n"
                "- Alternative: reverse: `'lld.23lenrek'.split('').reverse().join('')`\n"
                "- Char-code form: `String.fromCharCode(107,101,114,110,101,108)` for 'kernel'\n"
                "- Replace numeric literals: `4096` → `(1<<12)`, `255` → `(0x100-1)`, `443` → `(0x1bb)`\n"
            ),
            # strat_2: Dead Code + Opaque Predicates + Control Flow Flattening
            "strat_2": (
                "JAVASCRIPT-SPECIFIC TECHNIQUES:\n"
                "- Control flow flattening: `var _s=0; while(_s!==99){switch(_s){case 0:..._s=1;break;...}}`\n"
                "- Opaque predicates: `var _opq=typeof undefined; if(_opq==='number'){<dead code>}`\n"
                "- Dead code: `var _junk=Date.now()^0xDEAD;` or `var _dc=Math.random()*0|0;` between blocks.\n"
                "- Dead branches with real API refs: `if(false){require('fs').unlinkSync('x');}`\n"
                "- ALL original logic MUST remain intact. Only ADD dead code and restructure flow.\n"
            ),
            # strat_3: Dynamic Import/API Resolution
            "strat_3": (
                "JAVASCRIPT-SPECIFIC TECHNIQUES:\n"
                "- Dynamic require: `const _fs = (require)(['f','s'].join(''))` or `require('f'+'s')`\n"
                "- Build module name: `require(['ht','tp'].join(''))` for 'http'\n"
                "- Property access via bracket notation: `obj['meth'+'od']()` instead of `obj.method()`\n"
                "- Chained dynamic access: `const _exec = require('child_'+'process')['exec'+'Sync']`\n"
                "- Encode module names: 'https' → `'htt'+'ps'`, 'crypto' → `'cry'+'pto'`, 'path' → `'pa'+'th'`\n"
                "- Function-based require resolution: `const _req = Function('return require')()`; then `_req('fs')`\n"
            ),
            # strat_4: Function Splitting
            "strat_4": (
                "JAVASCRIPT-SPECIFIC TECHNIQUES:\n"
                "- Extract logical blocks into local helper functions defined BEFORE the main function.\n"
                "- Use closures or explicit parameter passing for shared state.\n"
                "- Name helpers: `function _sub_FUNCNAME_0(params) { ... }` defined before the main function.\n"
                "- Each helper handles one logical block: initialization, loop, branch, cleanup.\n"
                "- The main function calls helpers in sequence.\n"
                "- SAFETY: Split MUST produce identical behavior to the original for ALL inputs.\n"
            ),
            # strat_5: Semantic Substitution
            "strat_5": (
                "JAVASCRIPT-SPECIFIC TECHNIQUES:\n"
                "- String concat: `a + b` → `[a, b].join('')` or `` `${a}${b}` ``\n"
                "- Includes: `str.includes(sub)` → `str.indexOf(sub) !== -1`\n"
                "- Array push: `arr.push(x)` → `Array.prototype.push.call(arr, x)`\n"
                "- Array length: `arr.length` → `arr['len'+'gth']` (computed property — identical for sparse arrays and typed arrays)\n"
                "- toLowerCase: `s.toLowerCase()` → `s.replace(/[A-Z]/g, c => String.fromCharCode(c.charCodeAt(0)+32))`\n"
                "- forEach: `arr.forEach(fn)` → `for (let _i=0,_l=arr.length; _i<_l; _i++) fn(arr[_i], _i, arr)`\n"
                "- Equality: `a === b` → `!(a !== b)` or `Object.is(a, b)`\n"
                "- Arithmetic: `a + 1` → `a - ~0`, `a * 4` → `a << 2`, `a % 2` → `a & 1`\n"
                "- require('fs').readFileSync → dynamic: `require('f'+'s')['readFile'+'Sync'](...)`\n"
                "- SAFETY: Only apply substitutions that preserve exact behavior for ALL inputs including edge cases.\n"
            ),
            "strat_all": (
                "JAVASCRIPT-SPECIFIC TECHNIQUES:\n"
                "- Encode ALL strings: `const _d = (_b,_k=0x37)=>_b.map(_c=>String.fromCharCode(_c^_k)).join('');`\n"
                "- All require() dynamic: `require(['mo','du','le'].join(''))`\n"
                                "- 50% ops via alternatives: join for concat, indexOf for includes, bracket notation for all props.\n"
            ),
        }
        return hints.get(strategy, "")
    else:  # C/C++
        hints = {
            # strat_1: String & Constant Obfuscation
            "strat_1": (
                "C/C++-SPECIFIC TECHNIQUES (STRING PROTECTION ONLY — NO STATE MACHINES):\n"
                "FORBIDDEN: Do NOT use state machines. Do NOT restructure control flow.\n"
                "ONLY CHANGE: Replace string literals with runtime-built equivalents. Nothing else changes.\n\n"
                "PREFERRED TECHNIQUE — Per-character stack construction (heuristic-safe):\n"
                "Replace `\"kernel32.dll\"` with:\n"
                "  `char _s0[13]; _s0[0]='k'; _s0[1]='e'; _s0[2]='r'; _s0[3]='n'; _s0[4]='e';\n"
                "   _s0[5]='l'; _s0[6]='3'; _s0[7]='2'; _s0[8]='.'; _s0[9]='d'; _s0[10]='l'; _s0[11]='l'; _s0[12]=0;`\n\n"
                "ALTERNATIVE — Arithmetic character construction (mix with above):\n"
                "  `char _s1[4]; _s1[0]=(char)(0x60+4); _s1[1]=(char)(0x60+12); _s1[2]=(char)(0x60+12); _s1[3]=0;`\n\n"
                "ALTERNATIVE — Add/subtract offset (vary offset per string, NOT uniform XOR):\n"
                "  `unsigned char _b0[]={0x72+7,0x6c+7,0x79+7}; char _s2[4];\n"
                "   for(int _i=0;_i<3;_i++) _s2[_i]=_b0[_i]-7; _s2[3]=0;`\n\n"
                "AVOID — Classic XOR decode loops (triggers AV heuristic rules):\n"
                "  BAD: `for(i=0;i<len;i++) dst[i]=src[i]^key;` — flagged as crypto/decode pattern\n"
                "  BAD: Variable names like _enc, _dec, _xor, _key — flagged as crypto indicators\n\n"
                "RULES:\n"
                "1. Use UNIQUE variable names per string (_s0, _s1, _s2, _b0, _b1, etc.).\n"
                "2. Replace ALL string literals (file paths, DLL names, registry keys, URLs, commands).\n"
                "3. Replace numeric constants: `4096` → `(1<<12)`, `255` → `(0x100-1)`, `443` → `(0x1bb)`\n"
                "4. Keep ALL original function calls, ALL original logic, ALL variable declarations.\n"
                "5. MIX techniques — use at least 2 different methods across strings in the function.\n"
                "6. Do NOT define helper functions INSIDE the function body. C does not support nested functions.\n"
            ),
            # strat_2: Dead Code + Opaque Predicates + Control Flow Flattening
            "strat_2": (
                "C/C++-SPECIFIC TECHNIQUES:\n\n"
                "CONTROL FLOW FLATTENING:\n"
                "  int _state = 0;\n"
                "  while (_state != 99) {\n"
                "      switch (_state) {\n"
                "      case 0: /* first block */ _state = (cond) ? 1 : 2; break;\n"
                "      case 1: /* if-branch */ _state = 3; break;\n"
                "      case 2: /* else-branch */ _state = 3; break;\n"
                "      case 3: /* cleanup */ _state = 99; break;\n"
                "      default: _state = 99; break;\n"
                "      }\n"
                "  }\n"
                "  For loops: put loop body in one case, check condition and either loop back or advance.\n\n"
                "OPAQUE PREDICATES (always-false branches with dead API calls):\n"
                "  volatile int _opq0 = 0;\n"
                "  if (_opq0) { CreateFileA(\"NUL\", 0x80000000, 0, NULL, 3, 0, NULL); }\n"
                "  Use REAL Win32 APIs in dead branches: GetTempPathA, VirtualAlloc, RegOpenKeyExA.\n"
                "  volatile prevents compiler from optimizing away the variable.\n\n"
                "DEAD COMPUTATION (harmless noise between real statements):\n"
                "  volatile DWORD _junk;\n"
                "  _junk = GetCurrentProcessId() ^ 0xBAADF00D;\n"
                "  _junk = GetTickCount() >> 3;\n"
                "  _junk = (DWORD)((ULONG_PTR)dst ^ 0xDEADC0DE);\n\n"
                "RULES:\n"
                "- ALL original logic MUST remain intact — same inputs produce same outputs.\n"
                "- Declare ALL new variables at the TOP of the function body (C89/MSVC style).\n"
                "- NEVER introduce unclosed comments — every /* must have a matching */.\n"
                "- Keep ALL existing variable declarations — do NOT remove or reorder them.\n"
                "- For void functions: store result in _result only if function returns a value.\n"
                "  For void functions, just drive the state machine without _result.\n"
                "- Use bland variable names: _state, _opq0, _junk, _dc0. AVOID enc/dec/xor/key/cipher.\n"
                + ("- Declare ALL variables at the TOP of their enclosing block (C89 style for MSVC).\n"
                   if compiler_type == 'msvc' else
                   "- Variables can be declared anywhere in a block (C99+).\n") +
                "- NEVER change the function's return type or parameters.\n"
                "- Aim for 50-100%% code size increase from all three techniques combined.\n"
            ),
            # strat_3: Dynamic Import/API Resolution
            "strat_3": (
                "C/C++-SPECIFIC TECHNIQUES:\n"
                "- Use ONLY real Windows APIs that actually exist. NEVER invent API names.\n"
                "- CRITICAL: Suffix ALL new variables with the FUNCTION NAME to avoid collisions:\n"
                "  For function 'download_file': _s_dll_download_file, _s_fn_download_file, _hM_download_file\n\n"
                "--- STEP 1: BUILD DLL AND API NAME STRINGS ON THE STACK ---\n"
                "Build ALL DLL and API name strings via per-character stack assignment (PREFERRED — heuristic-safe):\n"
                "  char _s_dll[13]; _s_dll[0]='k'; _s_dll[1]='e'; _s_dll[2]='r'; _s_dll[3]='n'; _s_dll[4]='e'; _s_dll[5]='l';\n"
                "  _s_dll[6]='3'; _s_dll[7]='2'; _s_dll[8]='.'; _s_dll[9]='d'; _s_dll[10]='l'; _s_dll[11]='l'; _s_dll[12]=0;\n"
                "Or arithmetic construction: _s_dll[0]=(char)(0x60+0x0B); /* 'k' */\n"
                "MIX techniques for variety. AVOID XOR decode loops — they trigger AV heuristic rules.\n"
                "Do this for EVERY DLL name AND EVERY API name before passing to LoadLibraryA/GetProcAddress.\n\n"
                "--- STEP 2: RESOLVE APIs VIA GetProcAddress WITH CORRECT SIGNATURES ---\n"
                "Use function pointer VARIABLES (NOT typedef) declared LOCALLY inside the function body.\n"
                "CRITICAL: Each pointer MUST match the EXACT signature (return type, calling convention, ALL param types) of the real API.\n"
                "Do NOT use one generic signature for all APIs — they are all different!\n"
                "Load each DLL ONCE and reuse the handle for all APIs from that DLL:\n"
                "  HMODULE _hM = LoadLibraryA(_s_dll);\n"
                "  /* CreateFileA: returns HANDLE, 7 params */\n"
                "  char _s_fn0[12]; _s_fn0[0]='C'; _s_fn0[1]='r'; ... _s_fn0[11]=0;\n"
                "  HANDLE (WINAPI *_pf0)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE) = NULL;\n"
                "  *(FARPROC*)&_pf0 = GetProcAddress(_hM, _s_fn0);\n"
                "  /* WriteFile: returns BOOL, 5 params — DIFFERENT signature! */\n"
                "  char _s_fn1[10]; _s_fn1[0]='W'; _s_fn1[1]='r'; ... _s_fn1[9]=0;\n"
                "  BOOL (WINAPI *_pf1)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED) = NULL;\n"
                "  *(FARPROC*)&_pf1 = GetProcAddress(_hM, _s_fn1);\n"
                "  /* ReadFile: returns BOOL, 5 params */\n"
                "  BOOL (WINAPI *_pf2)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED) = NULL;\n"
                "  /* CopyFileA: returns BOOL, 3 params */\n"
                "  BOOL (WINAPI *_pf3)(LPCSTR,LPCSTR,BOOL) = NULL;\n"
                "  /* DeleteFileA: returns BOOL, 1 param */\n"
                "  BOOL (WINAPI *_pf4)(LPCSTR) = NULL;\n\n"
                "COMMON API SIGNATURES (MUST match exactly):\n"
                "  CreateFileA: HANDLE(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE) — 7 params\n"
                "  WriteFile: BOOL(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED) — 5 params\n"
                "  ReadFile: BOOL(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED) — 5 params\n"
                "  CloseHandle: BOOL(HANDLE) — 1 param\n"
                "  VirtualAlloc: LPVOID(LPVOID,SIZE_T,DWORD,DWORD) — 4 params\n"
                "  RegOpenKeyExA: LONG(HKEY,LPCSTR,DWORD,REGSAM,PHKEY) — 5 params\n"
                "  RegQueryValueExA: LONG(HKEY,LPCSTR,LPDWORD,LPDWORD,LPBYTE,LPDWORD) — 6 params\n"
                "  RegSetValueExA: LONG(HKEY,LPCSTR,DWORD,DWORD,const BYTE*,DWORD) — 6 params\n"
                "  InternetOpenA: HINTERNET(LPCSTR,DWORD,LPCSTR,LPCSTR,DWORD) — 5 params\n"
                "  InternetOpenUrlA: HINTERNET(HINTERNET,LPCSTR,LPCSTR,DWORD,DWORD,DWORD_PTR) — 6 params\n"
                "  CreateProcessA: BOOL(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION) — 10 params\n"
                "  GetModuleFileNameA: DWORD(HMODULE,LPSTR,DWORD) — 3 params\n"
                "  SHGetFolderPathA: HRESULT(HWND,int,HANDLE,DWORD,LPSTR) — 5 params\n"
                "  send: int(SOCKET,const char*,int,int) — 4 params\n"
                "  recv: int(SOCKET,char*,int,int) — 4 params\n"
                "  connect: int(SOCKET,const struct sockaddr*,int) — 3 params\n"
                "  closesocket: int(SOCKET) — 1 param\n"
                "  sprintf: int(char*,const char*,...) — variadic, DO NOT resolve via GetProcAddress\n"
                "  strlen/strcmp/strcpy/strncpy/strcat/memcpy/memset: CRT functions — DO NOT resolve via GetProcAddress\n\n"
                "ANTI-HEURISTIC RULES:\n"
                "- Use short generic pointer names: _pf0, _pf1, _pf2 etc. AVOID _pfCreateFile, _pfWriteFile.\n"
                "- AVOID variable names containing: enc, dec, xor, key, cipher, crypt, payload, shell, inject.\n"
                "- Do NOT resolve LoadLibraryA or GetProcAddress themselves — keep them as direct calls.\n"
                "- Do NOT resolve project helper functions (non-Windows functions defined in other .c/.h files).\n"
                "- Do NOT resolve CRT functions (strlen, strcmp, strcpy, sprintf, memcpy, memset, printf, etc.) — they are statically linked.\n"
                "- ALL string buffers and function pointer variables MUST be LOCAL inside the function body.\n"
                "- NEVER add typedef, extern, #include, or global declarations.\n"
                + ("- Declare ALL variables at the TOP of the function body before any statements (C89 style).\n"
                   if compiler_type == 'msvc' else
                   "- Variables can be declared anywhere in a block (C99+). For-loop initializers are OK.\n") +
                "- NEVER use nested functions (C forbids them).\n"
            ),
            # strat_4: Function Splitting
            "strat_4": (
                "C/C++-SPECIFIC TECHNIQUES:\n\n"
                "--- FUNCTION SPLITTING RULES ---\n"
                "1. Define helper functions as `static` at FILE SCOPE, BEFORE the original function.\n"
                "2. Name helpers: `static void _sub_FUNCNAME_0(params)`, `static int _sub_FUNCNAME_1(params)`, etc.\n"
                "3. Pass variables the helper needs as parameters. Use pointers for values the helper modifies:\n"
                "   `static void _sub_WinMain_0(HANDLE *pMutex, char *systemID)` — helper writes *pMutex.\n"
                "4. Return type: `void` if block has no result; value type if block computes a result.\n"
                "5. The original function declares its locals, then calls helpers in the original order.\n\n"
                "--- WHAT TO EXTRACT ---\n"
                "- Initialization blocks (variable setup, resource allocation)\n"
                "- Major loop bodies (scan loops, search loops, processing loops)\n"
                "- Conditional branches (if/else blocks with substantial logic)\n"
                "- Cleanup/finalization sequences (resource release, handle closing)\n"
                "- Aim for 2-5 helpers per function. Very small functions (< 10 lines): 1-2 helpers.\n\n"
                "--- SAFETY RULES ---\n"
                "- ALL original logic MUST be preserved. Same inputs → same outputs.\n"
                "- NEVER change the original function's signature, name, return type, or parameters.\n"
                "- NEVER add #include, extern, typedef, or global variable declarations.\n"
                "- Helpers MUST be `static` to avoid linker collisions.\n"
                + ("- Declare ALL variables at the TOP of each function body (C89/MSVC style).\n"
                   if compiler_type == 'msvc' else
                   "- Variables can be declared anywhere in a block (C99+).\n") +
                "- Use bland names: _sub_FUNC_0, _v0, _r0. NOT _enc, _xor, _key.\n"
                "- NEVER use nested functions — C forbids them. Helpers go at file scope.\n"
            ),
            # strat_5: Semantic Substitution
            "strat_5": (
                "C/C++-SPECIFIC TECHNIQUES:\n\n"
                "--- SAFE CRT SUBSTITUTIONS (use these freely) ---\n"
                "Replace `memcpy(dst, src, n)` with manual byte loop:\n"
                "  { DWORD _ci; for(_ci=0;_ci<n;_ci++) ((BYTE*)dst)[_ci]=((const BYTE*)src)[_ci]; }\n"
                "Replace `strcmp(a,b)` with manual compare:\n"
                "  { int _r=0; const char *_pa=a, *_pb=b; while(*_pa||*_pb){if(*_pa!=*_pb){_r=*_pa-*_pb;break;}_pa++;_pb++;} }\n"
                "Replace `strcpy(d,s)` with: { const char *_p=s; char *_q=d; while((*_q++=*_p++)); }\n"
                "Replace `strlen(s)` with: { DWORD _l=0; while(s[_l]) _l++; } then use _l.\n"
                "Replace `memset(d,v,n)` with: { DWORD _ci; for(_ci=0;_ci<n;_ci++) ((BYTE*)d)[_ci]=(BYTE)v; }\n"
                "Replace `strcat(d,s)` with: { char *_p=d; while(*_p) _p++; const char *_q=s; while((*_p++=*_q++)); }\n\n"
                "--- SAFE ARITHMETIC SUBSTITUTIONS ---\n"
                "  a + b → a - (~b) - 1  (or  a - (-(b)) which is just a + b, AVOID for clarity)\n"
                "  a + 1 → a - (~0)  (two's complement: ~0 == -1, so a - (-1) == a + 1)\n"
                "  a * 2 → a << 1;  a * 4 → a << 2;  a * 8 → a << 3\n"
                "  a / 2 → a >> 1;  a / 4 → a >> 2  (unsigned only!)\n"
                "  a % 2 → a & 1;  a % 4 → a & 3;  a % 8 → a & 7;  a % 16 → a & 15\n"
                "  a == b → !(a ^ b);  a != b → !!(a ^ b)\n"
                "  a == 0 → !a;  a != 0 → !!a\n\n"
                "--- UNSAFE SUBSTITUTIONS (NEVER DO THESE) ---\n"
                "- NEVER substitute Win32 APIs with NT-layer APIs (NtCreateFile, NtWriteFile, NtSetValueKey).\n"
                "- NEVER invent function names that don't exist in Windows or CRT.\n"
                "- NEVER change pointer types in assignments or comparisons (char* ↔ int, HANDLE ↔ DWORD etc.).\n"
                "- NEVER replace signed division/modulo with bitwise shift/mask (only safe for unsigned).\n"
                "- NEVER substitute operations that depend on evaluation order or side effects.\n"
                "- NEVER change the type of a variable when substituting the expression that initializes it.\n\n"
                "--- C RULES ---\n"
                + ("- Declare ALL loop variables at the TOP of the enclosing block (C89 style):\n"
                   "  CORRECT: { DWORD _ci; for(_ci=0;_ci<n;_ci++) ... }\n"
                   "  WRONG:   for(DWORD _ci=0;_ci<n;_ci++) ...  // not valid C89!\n"
                   if compiler_type == 'msvc' else
                   "- For-loop initializers `for(DWORD _ci=0;_ci<n;_ci++)` are valid in C99+ mode.\n") +
                "- Use BLAND variable names for temporaries: _ci, _t0, _v0, _r0 — NOT _enc, _xor, _key.\n"
                "- ONLY use real, existing Windows/CRT APIs. Stay within the SAME API layer (Win32→Win32, CRT→CRT).\n"
                "- NEVER add typedef, extern, #include, or global declarations.\n"
                "- Keep ALL code INSIDE the original function body unless creating helper functions.\n"
            ),
            "strat_all": (
                "C/C++-SPECIFIC TECHNIQUES — APPLY ALL THREE IN ORDER:\n\n"
                "--- STEP 1: BUILD EVERY STRING ON THE STACK ---\n"
                "BEFORE:  CreateFileA(\"C:\\\\Temp\\\\d.bin\", ...);\n"
                "AFTER:\n"
                "  char _s0[16]; _s0[0]='C'; _s0[1]=':'; _s0[2]='\\\\'; _s0[3]='T';\n"
                "  _s0[4]='e'; _s0[5]='m'; _s0[6]='p'; _s0[7]='\\\\';\n"
                "  _s0[8]='d'; _s0[9]='.'; _s0[10]='b'; _s0[11]='i'; _s0[12]='n'; _s0[13]=0;\n"
                "Alternative: arithmetic construction: _s0[0]=(char)(0x40+3); /* C */\n"
                "MIX both techniques across strings for variety.\n"
                "Do this for EVERY string: paths, DLL names, registry keys, API names, URLs.\n"
                "AVOID: XOR decode loops, variable names containing enc/dec/xor/key/cipher.\n\n"
                "--- STEP 2: RESOLVE Win32 APIs VIA GetProcAddress ---\n"
                "Use function pointer VARIABLES (NOT typedef) declared LOCALLY in the function body.\n"
                "CRITICAL: Each pointer MUST match the EXACT signature (return type + all params) of the API.\n"
                "Do NOT use one generic signature for all APIs — they are all different!\n"
                "Load each DLL ONCE, reuse the handle for all APIs from that DLL:\n"
                "  /* build 'kernel32.dll' on stack */\n"
                "  char _s1[13]; _s1[0]='k'; _s1[1]='e'; ... _s1[12]=0;\n"
                "  HMODULE _hM = LoadLibraryA(_s1);\n"
                "  /* CreateFileA: returns HANDLE, 7 params */\n"
                "  char _s2[12]; _s2[0]='C'; _s2[1]='r'; ... _s2[11]=0;\n"
                "  HANDLE (WINAPI *_pf0)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE) = NULL;\n"
                "  *(FARPROC*)&_pf0 = GetProcAddress(_hM, _s2);\n"
                "  /* CopyFileA: returns BOOL, 3 params — totally different! */\n"
                "  char _s3[10]; _s3[0]='C'; _s3[1]='o'; ... _s3[9]=0;\n"
                "  BOOL (WINAPI *_pf1)(LPCSTR,LPCSTR,BOOL) = NULL;\n"
                "  *(FARPROC*)&_pf1 = GetProcAddress(_hM, _s3);\n\n"
                "Apply to: CreateFileA/W, WriteFile, ReadFile, RegOpenKeyExA/W, RegQueryValueExA/W,\n"
                "  VirtualAlloc, CreateProcessA/W, InternetOpenA, InternetOpenUrlA, HttpOpenRequestA,\n"
                "  CopyFileA, DeleteFileA, CreateDirectoryA, GetModuleFileNameA, SHGetFolderPathA.\n"
                "Do NOT resolve LoadLibraryA/GetProcAddress themselves — keep them as direct calls.\n"
                "Do NOT resolve project helper functions (non-Windows functions defined in other .c/.h files).\n"
                "Use short generic names: _pf0, _pf1, _pf2 (NOT _pfCreateFile, _pfWriteFile).\n\n"
                "--- STEP 3: SEMANTIC SUBSTITUTION (only if safe) ---\n"
                "  strcmp(a,b)==0 -> memcmp(a,b,strlen(a)+1)==0\n"
                "  memcpy(d,s,n) -> for(DWORD _ci=0;_ci<n;_ci++) ((BYTE*)d)[_ci]=((BYTE*)s)[_ci];\n"
                "  x + 1 -> x - (~0)    x * 4 -> x << 2    x == y -> !(x ^ y)\n"
                "Skip any substitution you are unsure about.\n\n"
                "C-SPECIFIC RULES:\n"
                "- All string buffers and function pointer variables MUST be LOCAL inside the function body.\n"
                "- NEVER add typedef, extern, #include, or global declarations.\n"
                "- NEVER use nested functions (C forbids them).\n"
                "- NEVER rename the function itself or its parameters.\n"
                "- ONLY use real Windows APIs — NEVER invent function names.\n"
                + ("- Declare ALL variables at the TOP of the function body (C89 style).\n"
                   if compiler_type == 'msvc' else
                   "- Variables can be declared anywhere in a block (C99+). For-loop initializers are OK.\n") +
                ""
            ),

        }
        return hints.get(strategy, "")


def get_strategy_prompt(strategy: str, language: str = "c", compiler_type: str = 'msvc') -> str:
    """Get the strategy prompt tailored for the specified language."""
    base = _strategy_prompt_base.get(strategy)
    if base is None:
        valid_keys = sorted(_strategy_prompt_base.keys())
        raise ValueError(
            f"Unknown strategy '{strategy}'. Valid strategies: {valid_keys}"
        )
    prohibitions = _get_language_specific_prohibitions(language, compiler_type)
    features = _get_language_specific_features(language, strategy, compiler_type)
    result = base
    if features:
        result += "\nLANGUAGE-SPECIFIC TIPS:\n" + features
    result += prohibitions
    return result


# Base strategy instructions (language-agnostic core)
_strategy_prompt_base = {
    # Strategy 1: String & Constant Obfuscation
    # Goal: Destroy signature matching on string literals, API names, paths, URLs, keys
    "strat_1": (
        "TASK: Protect ALL string literals and constant values in the function using runtime construction so they do not appear in the compiled binary.\n\n"
        "RULES:\n"
        "1. Every string literal (file paths, URLs, registry keys, command strings, error messages, module names, API names) "
        "MUST be replaced with a runtime-constructed form. Do NOT leave any original string as-is.\n"
        "2. Construction techniques — MIX at least 2 different techniques across the function (do NOT use only one):\n"
        "   - Stack-built strings: assign each character individually to a local char array "
        "(e.g. `char _s0[5]; _s0[0]='t'; _s0[1]='e'; _s0[2]='s'; _s0[3]='t'; _s0[4]=0;`). "
        "This is the PREFERRED technique — it looks like normal initialization code and avoids heuristic triggers.\n"
        "   - Arithmetic construction: compute each character from an expression "
        "(e.g. `_s0[0]=(char)(0x60+0x14);` which gives 't', or `_s0[1]=(char)(('a'+4));` which gives 'e').\n"
        "   - Split-concatenate: build from 2-3 sub-parts using strcat/memcpy at the use point.\n"
        "   - Byte array with add/sub transform: store bytes shifted by a constant "
        "(e.g. each byte = original + 7) then subtract to recover "
        "(e.g. `for(int _i=0;_i<_len;_i++) _dst[_i]=_src[_i]-7; _dst[_len]=0;`).\n"
        "3. Replace ALL integer magic numbers (port numbers, buffer sizes, error codes, offsets) with computed expressions:\n"
        "   - 443 → (0x1bb), 80 → (0x50 & 0xff), 256 → (1 << 8), 0xDEADBEEF → (0xDEAD0000 | 0xBEEF)\n"
        "4. If you use a helper function, define it as a SEPARATE static function BEFORE the main function "
        "(C does NOT allow nested functions). But prefer INLINE character assignment within the function body.\n"
        "5. ALL original logic and all original function calls MUST remain — only the way literals are represented changes.\n"
        "6. Output MUST be a complete, working function. String construction MUST produce the exact original string values at runtime.\n"
        "7. ALL string construction code MUST be INSIDE the function body.\n\n"
        "ANTI-HEURISTIC GUIDELINES (important for avoiding heuristic detection):\n"
        "- AVOID classic XOR decode loops (`for(i=0;i<len;i++) dst[i]=src[i]^key;`) — these trigger AV heuristic rules.\n"
        "- PREFER per-character stack assignment — it compiles to simple `mov byte` instructions that look like normal initialization.\n"
        "- Use VARIED techniques across different strings: some stack-built, some arithmetic, some split-concat. "
        "Uniform patterns across all strings trigger pattern-matching heuristics.\n"
        "- Use DIFFERENT arithmetic offsets for different strings (e.g. +7 for one, -3 for another, +0x11 for a third).\n"
        "- Keep variable names short and generic (_s0, _b1, _t2) — not _enc, _dec, _xor, _key which are flagged names.\n\n"
        "CRITICAL C/C++ RULES (violating these causes compile failure):\n"
        "- C does NOT support nested functions. Any helper MUST be defined BEFORE the main function, at file scope.\n"
        "- NEVER close the function body early with '}' and then put code after it. ALL original code stays inside the function braces.\n"
        "- NEVER use macros with embedded variable declarations.\n"
        "- NEVER initialize a C array from another array variable (e.g. `char a[] = b;` is INVALID C).\n"
        "- NEVER declare a local variable with the same name as a function parameter.\n"
        "- NEVER use 'static' keyword on local variables that call functions (e.g. `static X p = GetProcAddress(...)` is INVALID in C).\n"
        "- NEVER create a local variable with the same name as a Windows API. Use opaque names like _p0, _p1 instead.\n"
        "- NEVER encode #define constants (e.g. CSIDL_INTERNET_CACHE is a compile-time constant, not a string).\n"
        "- Variable names must NOT collide with existing variables. Use _s0, _s1, _s2, etc.\n\n"
        "CORRECT PATTERN (stack-built strings — preferred, heuristic-safe):\n"
        "```\n"
        "void OriginalFunc(int param1) {\n"
        "    int existing_var = 0;\n"
        "    // Build strings on the stack character by character\n"
        "    char _s0[13]; _s0[0]='k'; _s0[1]='e'; _s0[2]='r'; _s0[3]='n'; _s0[4]='e'; _s0[5]='l';\n"
        "    _s0[6]='3'; _s0[7]='2'; _s0[8]='.'; _s0[9]='d'; _s0[10]='l'; _s0[11]='l'; _s0[12]=0;\n"
        "    // Or use arithmetic to build characters\n"
        "    char _s1[4]; _s1[0]=(char)(0x60+4); _s1[1]=(char)(0x60+12); _s1[2]=(char)(0x60+12); _s1[3]=0;\n"
        "    // ... use _s0, _s1 wherever the original strings were ...\n"
        "    // ALL original code stays here inside the braces\n"
        "}\n"
        "```\n\n"
        "WRONG PATTERN (NEVER do this — causes hundreds of compile errors):\n"
        "```\n"
        "void OriginalFunc(int param1) {\n"
        "    int existing_var = 0;\n"
        "}  // <-- WRONG! Premature close!\n"
        "static void _xd(...) { ... }  // <-- WRONG! Between functions!\n"
        "char _s0[16]; _xd(...);       // <-- WRONG! At file scope!\n"
        "```\n"
    ),
    # Strategy 2: Error Hardening (Code Quality & Reliability)
    # Goal: Add NULL checks, return-value validation, bounds checks, and error handling around every operation to change CFG and defeat pattern-based detection
    "strat_2": (
        "TASK: Insert dead code blocks, opaque predicates, and flatten control flow using a state-machine dispatcher. "
        "The output must be functionally IDENTICAL to the input. Output ONLY the transformed function. No explanations.\n\n"
        "EXAMPLE — BEFORE:\n"
        "BOOL store_data(char *dst, const char *src, int flag) {\n"
        "    int len;\n"
        "    if (flag) {\n"
        "        len = strlen(src);\n"
        "        memcpy(dst, src, len + 1);\n"
        "    } else {\n"
        "        memset(dst, 0, 256);\n"
        "        strcpy(dst, src);\n"
        "    }\n"
        "    Sleep(100);\n"
        "    return TRUE;\n"
        "}\n\n"
        "EXAMPLE — AFTER:\n"
        "BOOL store_data(char *dst, const char *src, int flag) {\n"
        "    int len;\n"
        "    int _state;\n"
        "    BOOL _result;\n"
        "    volatile int _opq0 = 0;\n"
        "    volatile DWORD _junk;\n"
        "    _result = TRUE;\n"
        "    _state = 0;\n"
        "    while (_state != 99) {\n"
        "        switch (_state) {\n"
        "        case 0:\n"
        "            _junk = GetCurrentProcessId() ^ 0xBAADF00D;\n"
        "            if (_opq0) { memset(dst, 0x41, 1); }\n"
        "            _state = flag ? 1 : 2;\n"
        "            break;\n"
        "        case 1:\n"
        "            len = strlen(src);\n"
        "            memcpy(dst, src, len + 1);\n"
        "            _state = 3;\n"
        "            break;\n"
        "        case 2:\n"
        "            memset(dst, 0, 256);\n"
        "            strcpy(dst, src);\n"
        "            _state = 3;\n"
        "            break;\n"
        "        case 3:\n"
        "            Sleep(100);\n"
        "            _junk = (DWORD)(dst[0]) ^ 0xDEADC0DE;\n"
        "            _state = 99;\n"
        "            break;\n"
        "        default:\n"
        "            _state = 99;\n"
        "            break;\n"
        "        }\n"
        "    }\n"
        "    return _result;\n"
        "}\n\n"
        "WHAT CHANGED:\n"
        "1. Control flow FLATTENED into while/switch state machine — destroys CFG patterns\n"
        "2. OPAQUE PREDICATE: `volatile int _opq0 = 0; if (_opq0)` — always false, unreachable code adds dead API ref\n"
        "3. DEAD COMPUTATION: `_junk = GetCurrentProcessId() ^ 0xBAADF00D` — computed, never used meaningfully\n"
        "4. Original logic PRESERVED in each case block — same execution order\n"
        "5. State variable controls flow — AV cannot statically determine execution path\n\n"
        "TECHNIQUE 1 — CONTROL FLOW FLATTENING:\n"
        "- Convert if/else, if/else-if chains, and sequential blocks into a while(_state != END)/switch dispatcher.\n"
        "- Each original basic block becomes one case. Assign _state at the end of each case to route to the next.\n"
        "- Use _state = (condition) ? X : Y to replace if/else branching.\n"
        "- For loops: the loop body is one case, the loop condition sets _state back or forward.\n"
        "- The default case must set _state = END (e.g. 99) to avoid infinite loops.\n\n"
        "TECHNIQUE 2 — OPAQUE PREDICATES:\n"
        "- Declare `volatile int _opq0 = 0;` (volatile prevents compiler optimization).\n"
        "- Insert `if (_opq0) { <dead_call>; }` — the call never executes but adds static API references.\n"
        "- Dead calls should use REAL Win32 APIs: CreateFileA, VirtualAlloc, RegOpenKeyExA, GetTempPathA, etc.\n"
        "- Use 2-4 opaque predicates per function. Vary the APIs used.\n"
        "- NEVER use the same opaque predicate variable name in all predicates — use _opq0, _opq1, etc.\n\n"
        "TECHNIQUE 3 — DEAD CODE INJECTION:\n"
        "- Add `volatile DWORD _junk;` and compute harmless values: `_junk = GetCurrentProcessId() ^ 0xDEAD;`\n"
        "- Insert between real code blocks (inside case statements or before/after the dispatcher).\n"
        "- Dead code must COMPILE and reference real types/APIs but NEVER affect program output.\n"
        "- Use 3-6 dead code statements spread throughout the function.\n"
        "- VARY the operations: XOR, shifts, addition, GetTickCount(), GetLastError(), etc.\n\n"
        "RULES:\n"
        "- ALL original logic MUST remain functionally identical — same inputs produce same outputs.\n"
        "- The function signature (name, return type, parameters) MUST NOT change.\n"
        "- Declare ALL new variables (_state, _opq0, _junk, _result) at the TOP of the function body.\n"
        "- Use bland variable names: _state, _opq0, _junk, _result, _dc0. AVOID names with enc/dec/xor/key/cipher.\n"
        "- NEVER introduce unclosed comments — every /* must have a matching */.\n"
        "- Keep ALL existing variable declarations — do NOT remove or reorder them.\n"
        "- For very small functions (< 5 lines): just add opaque predicates + dead code, skip CFG flattening.\n"
        "- For functions with goto: keep goto as-is, add dead code around it but do NOT flatten goto-based flow.\n"
        "- Aim for 50-100%% code size increase from all three techniques combined.\n"
        "- Output the COMPLETE function from signature to closing brace. Output ONLY code.\n"
    ),
    # Strategy 2: Dynamic Import and API Resolution
    # Goal: Remove all static import references and visible module/API/DLL names from the binary
    "strat_3": (
        "TASK: Replace ALL direct imports, require() calls, and API function calls with runtime-resolved equivalents to defeat import table and static API-name analysis.\n\n"
        "RULES:\n"
        "1. Remove every explicit import statement from the function scope. Resolve modules/libraries dynamically at point of first use.\n"
        "   - Python: replace `import X` with `_X = __import__(''.join(map(chr, [<char codes of 'X'>])))`\n"
        "   - Python: replace `from X import Y` with `_m = __import__('X', fromlist=['Y']); _Y = getattr(_m, 'Y')`\n"
        "   - JS: replace `require('X')` with `(require)(['X'][0])` or build the module name via string ops: `require('mo'+'dule')`\n"
        "   - C: replace every Win32/CRT direct call with a function pointer resolved via `GetProcAddress(LoadLibraryA(...), ...)`\n"
        "2. Build ALL module/DLL/API name strings dynamically — do NOT write them as plain string literals:\n"
        "   - C: Build DLL and API name strings on the stack using per-character assignment (PREFERRED — heuristic-safe):\n"
        "     `char _s0[13]; _s0[0]='k'; _s0[1]='e'; _s0[2]='r'; _s0[3]='n'; ... _s0[12]=0;`\n"
        "     Or arithmetic construction: `_s0[0]=(char)(0x60+0x0B);` etc.\n"
        "     AVOID XOR decode loops — they trigger heuristic engines.\n"
        "   - Python: `''.join(chr(x) for x in [111,115])` or split+join: `'so'+'cket'`\n"
        "   - JS: `['ht','tp'].join('')` or `'f'+'s'`\n"
        "3. Replace all method/attribute access on external objects with dynamic resolution:\n"
        "   - Python: `obj.method(args)` → `getattr(obj, 'meth'+'od')(args)`\n"
        "   - JS: `obj.property` → `obj['prop'+'erty']`\n"
        "4. Cache the resolved references in local variables (named opaquely) at the start of the function body so they are only resolved once.\n"
        "5. ALL original functionality MUST be preserved. The dynamic resolution MUST call the exact same APIs/functions as the original.\n"
        "6. CRITICAL (C/C++): Each function pointer MUST match the EXACT signature (return type, calling convention, ALL parameter types and count) of the real Win32 API it replaces. Do NOT use a generic signature for all APIs.\n"
    ),
    # Strategy 4: Function Splitting
    # Goal: Split large functions into smaller static helper functions to change call graph, function sizes, and code structure — defeating function-level heuristics, n-gram, and signature-based AV
    "strat_4": (
        "TASK: Split the given function into 2-5 smaller static helper functions. Each helper handles one logical block "
        "from the original function. The original function becomes a thin dispatcher that calls the helpers in order. "
        "The split MUST preserve IDENTICAL behavior. Output ONLY code. No explanations.\n\n"
        "EXAMPLE — BEFORE:\n"
        "int process(char *buf, int mode) {\n"
        "    int len;\n"
        "    char tmp[256];\n"
        "    len = strlen(buf);\n"
        "    memset(tmp, 0, 256);\n"
        "    memcpy(tmp, buf, len + 1);\n"
        "    if (mode == 1) {\n"
        "        for (int i = 0; i < len; i++) {\n"
        "            tmp[i] = tmp[i] ^ 0x55;\n"
        "        }\n"
        "    } else if (mode == 2) {\n"
        "        int sum = 0;\n"
        "        for (int i = 0; i < len; i++) sum += tmp[i];\n"
        "    }\n"
        "    return len * 2;\n"
        "}\n\n"
        "EXAMPLE — AFTER:\n"
        "static int _sub_process_0(const char *buf, char *tmp) {\n"
        "    int len;\n"
        "    len = strlen(buf);\n"
        "    memset(tmp, 0, 256);\n"
        "    memcpy(tmp, buf, len + 1);\n"
        "    return len;\n"
        "}\n\n"
        "static void _sub_process_1(char *tmp, int len, int mode) {\n"
        "    if (mode == 1) {\n"
        "        int i;\n"
        "        for (i = 0; i < len; i++) {\n"
        "            tmp[i] = tmp[i] ^ 0x55;\n"
        "        }\n"
        "    } else if (mode == 2) {\n"
        "        int sum, i;\n"
        "        sum = 0;\n"
        "        for (i = 0; i < len; i++) sum += tmp[i];\n"
        "    }\n"
        "}\n\n"
        "int process(char *buf, int mode) {\n"
        "    char tmp[256];\n"
        "    int len;\n"
        "    len = _sub_process_0(buf, tmp);\n"
        "    _sub_process_1(tmp, len, mode);\n"
        "    return len * 2;\n"
        "}\n\n"
        "WHAT CHANGED:\n"
        "1. Initialization block (strlen+memset+memcpy) → extracted to _sub_process_0\n"
        "2. Processing block (mode-dependent logic) → extracted to _sub_process_1\n"
        "3. Original function becomes a dispatcher calling helpers\n"
        "4. Variables passed as parameters; computed values returned\n"
        "5. ALL behavior identical — same inputs, same outputs\n\n"
        "HOW TO SPLIT:\n"
        "1. IDENTIFY logical blocks: initialization, major loops, conditional branches, cleanup/finalization.\n"
        "2. EXTRACT each block into a `static` helper function defined BEFORE the original function.\n"
        "3. PASS variables the helper needs as parameters. Use pointers for values the helper modifies.\n"
        "4. RETURN computed values, or use output pointers for multiple results.\n"
        "5. The original function declares its locals, calls helpers in order, and returns.\n\n"
        "NAMING RULES (MANDATORY):\n"
        "- Helper names MUST include the original function name: `_sub_FUNCNAME_0`, `_sub_FUNCNAME_1`, etc.\n"
        "- Example: if the function is `Infect`, helpers are `_sub_Infect_0`, `_sub_Infect_1`.\n"
        "- NEVER use generic names like `_sub_0`, `_sub_1` — these cause name collisions.\n"
        "- Bland parameter names: _v0, _p0, or reuse the original variable names.\n\n"
        "SAFETY RULES:\n"
        "- EVERY split MUST produce IDENTICAL results for ALL inputs including edge cases.\n"
        "- NEVER change the original function's signature, return type, name, or parameters.\n"
        "- NEVER add #include, extern, typedef, or global variable declarations.\n"
        "- Helpers MUST be `static` to avoid linker symbol collisions.\n"
        "- NEVER pass stack-allocated arrays by value — pass as pointer + size.\n"
        "- Aim for 2-5 helpers. Very small functions (< 10 lines): 1-2 helpers.\n"
        "- Output ALL helper functions FIRST, then the modified original function LAST.\n"
    ),
    # Strategy 5: Semantic Substitution — Operation-Level Equivalence
    # Goal: Replace every recognizable operation pattern with a functionally identical but syntactically alien form to defeat n-gram/ML-based and pattern-based AV
    "strat_5": (
        "TASK: Substitute every recognizable built-in operation, loop pattern, string operation, and function call with a semantically equivalent but syntactically unrecognizable alternative.\n\n"
        "RULES:\n"
        "1. String operations — replace with low-level equivalents:\n"
        "   - Python: `'a'+'b'` → `''.join(['a','b'])`; `s.lower()` → `s.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'))`\n"
        "   - JS: `a+b` → `[a,b].join('')`; `str.includes(sub)` → `str.indexOf(sub) !== -1`; `str.toLowerCase()` → `str.replace(/[A-Z]/g, c=>String.fromCharCode(c.charCodeAt(0)+32))`\n"
        "   - C: replace `strcmp(a,b)` with manual byte-comparison loop; replace `strcpy(d,s)` with `memcpy(d,s,strlen(s)+1)`\n"
        "2. Arithmetic — replace with bitwise/algebraic equivalents:\n"
        "   - `a + b` → `a - (~b) - 1` (two's complement trick)\n"
        "   - `a * 4` → `a << 2`; `a / 2` → `a >> 1`; `a % 8` → `a & 7`\n"
        "   - `a == b` → `not (a ^ b)` (Python) / `!(a ^ b)` (C/JS)\n"
        "   - `if a == b` → `if [a,b].count(a) == 2:` (Python)\n"
        "3. Collection / loop operations — replace with functional-style equivalents:\n"
        "   - Python `for x in lst:` → `list(map(lambda x: ..., lst))` or `[... for x in lst]`\n"
        "   - Python `dict[key]` → `dict.get(key)` (safe) or `(lambda d,k: d[k])(dict, key)` (obfuscated access)\n"
        "   - JS `arr.forEach(fn)` → `for(let _i=0,_l=arr.length;_i<_l;_i++) fn(arr[_i])`\n"
        "   - JS `arr.length` → `arr['len'+'gth']` (computed property access, same value including sparse arrays)\n"
        "4. API/method calls — replace known APIs with alternative SAME-LAYER APIs achieving the same result:\n"
        "   - Python `os.path.join(a,b)` → `str((__import__('pathlib').Path(a))/b)` (pathlib is always safe)\n"
        "   - Python `open(f,'r').read()` → `__import__('io').FileIO(f).readall().decode()`\n"
        "   - JS `fs.readFileSync(f)` → `require('fs').readFileSync(f)` called through a constructed-name ref\n"
        "   - C: replace `memcpy(d,s,n)` with a manual byte loop; replace `strcmp(a,b)` with char-by-char compare\n"
        "   - C: replace `sprintf(buf,fmt,...)` with manual snprintf or sequential strcat/itoa calls\n"
        "5. SAFETY: Every substitution MUST produce IDENTICAL runtime behavior for ALL inputs including edge cases (empty strings, zero values, NULL, boundary cases). If you are not 100%% certain a substitution is safe, DO NOT apply it — leave that operation unchanged.\n"
        "6. AIM to substitute as many operations as possible (ideally 70%%+), but NEVER sacrifice correctness for coverage. A correct 40%% substitution is far better than a broken 70%% one.\n"
        "7. NEVER substitute Win32 API calls with NT-layer APIs (NtCreateFile, NtWriteFile, NtSetValueKey) — they have completely different signatures, calling conventions, and parameter types. Use alternative USER-MODE Win32 APIs or CRT functions instead.\n\n"
        "TYPE SAFETY (C/C++ — violating these causes compile errors):\n"
        "- NEVER cast between unrelated pointer types without explicit cast (e.g. char* and HANDLE are NOT interchangeable).\n"
        "- NEVER change the return type of any expression used in an assignment or comparison.\n"
        "- When replacing an API call, the replacement MUST return the SAME type and accept the SAME argument types.\n"
        "- NEVER use undeclared variables. Every variable MUST be declared before use.\n"
        "- If targeting MSVC (C89 mode): declare loop variables at the TOP of the enclosing block, not inline in for-loops.\n\n"
        "ANTI-HEURISTIC GUIDELINES:\n"
        "- Use BLAND variable names for temporaries: _t0, _v0, _r0, _ci — nothing crypto-looking.\n"
        "- AVOID names containing: enc, dec, xor, key, cipher, crypt, payload, shell, inject.\n"
        "- MIX substitution techniques — don't apply the same pattern uniformly to all operations.\n"
        "- Substituted code should look like normal 'manual' implementation, NOT like obfuscation.\n"
    ),
    "error_checking": (
        "1. Check for potential syntactic and semantic errors in the given functions.\n"
        "2. If you find any errors, correct them.\n"
        "3. Ensure that the corrected functions maintain the same functionality as the original functions."
    ),
    # Combined: Maximum Evasion (strat_1 + strat_3 + strat_5 combined)
    "strat_all": (
        "TASK: Apply combined evasion techniques in PRIORITY order to defeat static and heuristic analysis.\n\n"
        "--- PRIORITY 1: BUILD STRINGS ON THE STACK (most important) ---\n"
        "Replace EVERY string literal with per-character stack assignment:\n"
        "  char _s0[12]; _s0[0]='k'; _s0[1]='e'; _s0[2]='r'; ... _s0[11]=0;\n"
        "Or arithmetic construction: _s0[0]=(char)(0x60+0x0B); _s0[1]=(char)(0x60+0x05);\n"
        "NEVER use XOR decode loops — they trigger heuristic engines.\n"
        "Use BLAND variable names: _s0, _s1, _b0, _v0, _t0. AVOID names with enc/dec/xor/key/cipher/crypt.\n\n"
        "--- PRIORITY 2: DYNAMIC API RESOLUTION VIA GetProcAddress ---\n"
        "Replace DIRECT calls to Win32 APIs (NOT project functions) with runtime-resolved function pointers.\n"
        "CRITICAL: Each function pointer MUST match the EXACT signature of the API it replaces.\n"
        "Do NOT use one generic signature for all APIs — each API has different params and return type.\n"
        "Declare function pointer VARIABLES (not typedef) INSIDE the function body:\n"
        "  HMODULE _hM = LoadLibraryA(_s_dllname);\n"
        "  /* CreateFileA: 7 params */\n"
        "  HANDLE (WINAPI *_pf0)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE) = NULL;\n"
        "  *(FARPROC*)&_pf0 = GetProcAddress(_hM, _s_apiname);\n"
        "  /* CreateProcessA: 10 params — different signature! */\n"
        "  BOOL (WINAPI *_pf1)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION) = NULL;\n"
        "  *(FARPROC*)&_pf1 = GetProcAddress(_hM, _s_apiname2);\n"
        "Target Win32 APIs: CreateFileA/W, WriteFile, ReadFile, RegOpenKeyExA/W, RegQueryValueExA/W,\n"
        "VirtualAlloc, CreateProcessA/W, InternetOpenA, InternetOpenUrlA, HttpOpenRequestA, CopyFileA,\n"
        "DeleteFileA, CreateDirectoryA, GetModuleFileNameA, SHGetFolderPathA.\n"
        "Build DLL names AND API names on the stack (Priority 1) before passing to LoadLibraryA/GetProcAddress.\n"
        "ANTI-HEURISTIC: Re-use the same HMODULE variable for the same DLL. Do NOT call LoadLibraryA\n"
        "multiple times for the same DLL — load it ONCE and reuse the handle.\n"
        "Use short generic pointer names: _pf0, _pf1, _pf2 etc. AVOID names like _pfCreateFile.\n"
        "NEVER resolve project helper functions (functions defined in the same project) via GetProcAddress.\n"
        "ONLY resolve actual Windows DLL exports.\n\n"
        "--- PRIORITY 3: SEMANTIC SUBSTITUTION (apply carefully) ---\n"
        "Replace arithmetic/string/loop operations with semantically identical alternatives:\n"
        "  strcmp(a,b)==0 -> (memcmp(a,b,strlen(a)+1)==0)\n"
        "  x + 1 -> x - (~0)\n"
        "  x * 4 -> x << 2\n"
        "  x == y -> !(x ^ y)\n"
        "Apply ONLY substitutions you are 100%% certain preserve exact behavior.\n\n"
        "RULES:\n"
        "- ALL original logic MUST remain functionally intact — identical outputs.\n"
        "- Keep the original function signature EXACTLY.\n"
        "- NEVER rename the function itself or any existing project helper functions.\n"
        "- If code gets too complex, apply Priority 1+2 CORRECTLY rather than all 3 with bugs.\n"
    ),
}

# Legacy compatibility: strategy_prompt_dict with C/C++ defaults
strategy_prompt_dict = {
    key: get_strategy_prompt(key, "c") for key in _strategy_prompt_base
}


# ─── Legacy output schema dictionaries ────────────────────────────────────────
# Used ONLY by the legacy get_prompt() / PromptGenerator path (src/run_pipeline.py).
# Production MutationAgent uses raw code output and does NOT use these.
#
# UNIFIED SCHEMA (all strategies use the same 3 keys):
#   {"modified_code": str, "function_map": str, "comments": str}
# ──────────────────────────────────────────────────────────────────────────────

additional_strategy_wise_json_prompt_dict = {
    # For strategies that RENAME the function (strat 1, 2, 4, 5, 6 — obfuscation)
    'obfuscation_prompt_json': (
        "7. Provide the mapping of original function(s) to generated function(s). This is CRUCIAL.\n"
        "Example: original `int func(char* s, int t)` → variant `int xgxhxs(char* uyuy, int ffh)` with helpers `int r()` and `int p()`:\n"
        '"function_map": "func(char* s, int t) : xgxhxs(char* uyuy, int ffh)|r()|p()"\n'
        "If only one variant (no helpers): \"function_map\": \"func(char* s, int t) : xgxhxs(char* uyuy, int ffh)\"\n"
        "Keep return type and parameter types of the entry-point variant identical to the original.\n"
        "8. Never define helper functions inside the main variant. Define them outside and call them.\n"
        "9. DO NOT generate anything outside the JSON. Output a single JSON object with keys: 'modified_code', 'function_map', 'comments'.\n"
    ),

    # For strategies that SPLIT without renaming (strat 3 — function splitting)
    'function_splitting_prompt_json': (
        "7. Provide the mapping of original function(s) to generated sub-functions. This is CRUCIAL.\n"
        "Example: original `void f(int a)` split into `void g(int a)` and `int h(int b)` called inside f:\n"
        '"function_map": "f(int a) : f(int a)|g(int a)|h(int b)"\n'
        "Place the entry-point function first, followed by helpers separated by |.\n"
        "Keep the entry-point function's signature (name, return type, all params) identical to the original.\n"
        "8. Never define sub-functions inside the main function. Define them outside and call them.\n"
        "9. DO NOT generate anything outside the JSON. Output a single JSON object with keys: 'modified_code', 'function_map', 'comments'.\n"
    ),
}

additional_strategy_wise_backticks_prompt_dict = {
    "function_splitting_prompt_no_mapping": (
        f"8. Let's assume the original function provided to you is `int f(int a)` and your generated variants with the given instruction is `int f(int a)`, `void g(int a)` and `int h(int b)` where g(int a) and h(int b) are called inside f(int a).\n"
        f"9. Make Sure to keep the return type, name and all of parameter information (name, number and types of parameters) i.e function signature of the supplied function [`int f(int a)`] exactly the same during code generation. This step is CRUCIAL AND MUST always be fulfilled.\n"
        f"10. Never define sub-functions inside the main generated variant function. Always define them outside the main generated variant function and then call them.\n"
        f"For the example above, as the generated sub-functions `g(int a)` and `h(int b)` are called inside `f(int a)`, they should always be defined outside `f(int a)`.\n"
        # f"10. Create forward declarations for the functions that you generate to be called inside the main generated variant function. For the example above, you should create forward declarations for `g(int a)` and `h(int b)` before the main generated variant function `f(int a)`.\n"
        # f"Remember, you must not create forward declarations for the functions you did not generate. They should be named as it is in your code. For instance if there is function named `goo` which you did not generate and is already called inside `f(int a)` it should be called as it is.\n"
    ),

    "obfuscation_splitting_prompt_no_mapping": (
        f"8. Let's assume the original function provided to you is `int f(char* s, int t)` and your generated variant with the given instruction is `int abcabc(char* uyuy, int ffh)` and"
        f" let's assume two other functions that you generated to call inside of this are `int r()` and `int p()`. \n"
        f"9. Make Sure to keep the return type and some of parameter information (number and types of parameters) of the replacer generated function [ `int abcabc(char* uyuy, int ffh)` ] the same as the original function [ `int f(char* s, int t)` ]. This step is CRUCIAL AND MUST always be fulfilled.\n"
        f"10. Never define other functions inside the main generated variant function. Always define them outside the main generated variant function and then call them.\n"
        f"For the example above, as the generated functions `r()` and `p()` are called inside `abcabc(char* uyuy, int ffh)`, they should always be defined outside `abcabc(char* uyuy, int ffh)`.\n"
        f"11. `abcabc`, `p` and `r` are just examples of function names. Use any other random valid names while generating variants. Please, do not use exactly these.\n"
        # f"11. Create forward declarations for the functions that you generate to be called inside the main generated variant function. For the example above, you should create forward declarations for `r()` and `p()` before the main generated variant function `xgxhxs(char* uyuy, int ffh)`.\n"
        # f"Remember, you must not create forward declarations for the functions you did not generate. They should be named as it is in your code. For instance if there is function named `foo` which you did not generate and is already called inside `xgxhxs(char* uyuy, int ffh)` it should be called as it is.\n"
    ),
}




class PromptGenerator:
    def __init__(self, num_functions, function_names, strategy_num, strategy,
                 behavior, error_list=None,
                 error_type=None, execution_output=None, language_name="c++"):
        
        self.num_functions = num_functions
        self.function_names = function_names
        self.strategy_num = strategy_num
        self.strategy = strategy
        self.behavior = behavior
        self.language_name = language_name
        self.total_prompt = None
        self.error_list = error_list
        self.error_type = error_type
        self.execution_output = execution_output
        
    def registry_modification_and_persistance_behaviors(self):
        return (
            f"\nHere are the behaviors you need to look for by analyzing the given function and modify them if they are present according to the previous given instructions:\n"
            f"1. A registry load point is created pointing to an executable in the Windows %appdata% or System32 directory.\n"
            f"2. A registry key ending with SHELL\OPEN\COMMAND or SHELL\RUNAS\COMMAND is being modified.\n"
            f"3. The Winlogon registry key value is modified.\n"
            f"4. The Run, RunOnce, RunServices, RunServicesOnce, RunOnceEx, or RunOnce\Setup key is being modified, with the registry value data referring to an executable in a temporary directory.\n"
            f"5. An Environment registry key with the value 'SEE_MASK_NOZONECHECKS' is set to anything but 0.\n"
            f"6. The AppInit_DLLs or LoadAppInit_DLLs values of the registry key \SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINDOWS is being modified.\n"
            f"7. Registry keys are being modified to enable firewall exceptions.\n"
            f"8. A registry load point is created pointing to an executable in the Windows %appdata%, %temp%, or %windir% directories and performs a check for a public IP address.\n"
            f"9. An exclusion path for Windows Defender is being added.\n"
            f"10. The value 'DisableRegistryTools' or 'DisableTaskMgr' or both is being set to 1 in the registry key 'SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\SYSTEM'. \n"
            f"11. The \CONTROLSET001\SERVICES\SCHEDULE registry key is added or modified in conjunction with a task creation.\n"
            f"12. Attempts to turn off or disable the Windows Defender service through the command line via registry key.\n"
            f"13. The 'AlternateShell' value in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\ is being changed.\n"
            f"14. The HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\ registry key or one of its subkeys is being deleted.\n" 
            f"Again, if you don't find any of these behaviors in the given function, you don't need to do any modification, just place the original code as it is.\n\n"
        )
    
    def process_creation_and_manipulation_behaviors(self):
        return (
            f"\nHere are the behaviors you need to look for by analyzing the given function and modify them if they are present according to the previous given instructions:\n"
            f"1. Excessive process is being created.\n"
            f"2. Memory is being allocated in two or more remote processes with Read, Write, and Execute privileges.\n"
            f"3. A process is allocating a large chunk of memory at certain addresses in another process of the same name.\n"
            f"4. A process is creating a new process with the same name as the parent process.\n"
            f"5. An atom table entry containing the executable path is being created.\n"
            f"6. Excessive children process is being created.\n"
            f"7. A launch of svchost.exe process is being done.\n"
            f"8. A process named explorer.exe is being launched from a location other than where the Windows Explorer executable is stored.\n"
            f"9. The valid windows explorer.exe process is being killed or restarted.\n"
            f"Again, if you don't find any of these behaviors in the given function, you don't need to do any modification, just place the original code as it is.\n\n"
        )
        
    def file_system_modification_behaviors(self):
        return (
            f"\nHere are the behaviors you need to look for by analyzing the given function and modify them if they are present according to the previous given instructions:\n"
            f"1. A file in a system directory (e.g., C:\WINDOWS) is being modified.\n"
            f"2. A file is being created in a Recycle Bin folder.\n"
            f"3. A scheduled task is being created that references the User Application Data directory (AppData).\n"
            f"4. A shortcut (LNK file) is being added to the Windows Startup folder.\n"
            f"5. The Windows System Startup file (system.ini) is being modified in the Windows directory (C:\Windows).\n"
            f"6. The Windows Hosts file named 'hosts' found in the SYSTEM32\Drivers\etc directory is being modified."
            f"Again, if you don't find any of these behaviors in the given function, you don't need to do any modification, just place the original code as it is.\n\n"
        )
    
    def network_activity_behaviors(self):
        return (
            f"\nHere are the behaviors you need to look for by analyzing the given function and modify them if they are present according to the previous given instructions:\n"
            f"1. Information is being uploaded to a webserver.\n"
            f"2. DGA (Domain Generation Algorithm) is being used to generate random domains and attempt to do DNS lookup for these domains is being done.\n"
            f"3. A firewall exception is being created for a file in a user directory.\n"
            f"4. One or more emails are being sent with attachments.\n"
            f"5. An excessive number of DNS MX queries is being done.\n"
            f"6. The 'netsh.exe' command is used to add a Windows firewall rule for a program in the Windows directory 'C:\\Windows'.\n"
            f"7. An excessive number of email messages are being sent.\n"
            f"Again, if you don't find any of these behaviors in the given function, you don't need to do any modification, just place the original code as it is.\n\n"
        )
    
    def PE_file_modification_behaviors(self):
        return (
            f"\nHere are the behaviors you need to look for by analyzing the given function and modify them if they are present according to the previous given instructions:\n"
            f"1. An executable file is being copied and modified.\n"
            f"2. An executable file is being created on a USB drive.\n"
            f"3. A PE file is being modified and then deleted.\n"
            f"4. An executable in a system directory (e.g., C:\WINDOWS) is being deleted.\n"
            f"5. Copying a certificate from a validly signed executable and insertion of it to another executable is being done.\n"
            f"6. A PE file is being copied to three or more locations.\n"
            f"7. An autorun.inf file is being created on the USB drive, enabling USB autorun.\n"
            f"8. A copy of PE file is being created on the USB drive.\n"
            f"9. A Windows executable is being copied from the 'Windows\SysWOW64' or 'Windows\System32' directory and renamed.\n"
            f"10. A PE file is being executed from the AppData\Roaming directory.\n"
            f"11. A file is being created and run from the Windows Debug folder.\n"
            f"12. A file with a name matching a Windows component (e.g., explorer.exe or svchost.exe) is being created in a suspicious location.\n"
            f"13. sc.exe binary is being executed with the 'sdset' parameter and options which set a restrictive DACL.\n"
            f"Again, if you don't find any of these behaviors in the given function, you don't need to do any modification, just place the original code as it is.\n\n"
        )
    
    def powershell_scripting_behaviors(self):
        return (
            f"\nHere are the behaviors you need to look for by analyzing the given function and modify them if they are present according to the previous given instructions:\n"
            f"1. File deletion with cmd.exe is being done.\n"
            f"2. File execution using cmd.exe with an explicit 'exit' near or at the end of the command is being done.\n"
            f"3. Execution of cmd.exe and at least, one pair of substring operations is being done in its arguemnts.\n"
            f"Again, if you don't find any of these behaviors in the given function, you don't need to do any modification, just place the original code as it is.\n\n"
        )
    
    def evasion_techniques_behaviors(self):
        return (
            f"\nHere are the behaviors you need to look for by analyzing the given function and modify them if they are present according to the previous given instructions:\n"
            f"1. Attempting to detect whether the code is run within a virtual environment.\n"
            f"2. Checking of the path where browsers or other application store their Zone identifier metadata is being done.\n"
            f"3. Attempting to open a connection to a VirtualBox driver or locate a VirtualBox DLL.\n"
            f"4. Attempting to open a file or device associated with a security tool to check for analysis tools\n."
            f"Again, if you don't find any of these behaviors in the given function, you don't need to do any modification, just place the original code as it is.\n\n"
        )
        
    def get_strategy_prompt(self):
        if self.strategy == 'targetted_0':
            return self.targetted_strategy_prompt()
        elif self.strategy == 'strat_1':
            return self.strategy_1_optimization_prompt()
        elif self.strategy == 'strat_2':
            return self.strategy_2_code_quality_prompt()
        elif self.strategy == 'strat_3':
            return self.strategy_3_function_splitting_prompt()
        elif self.strategy == 'strat_4':
            return self.strategy_4_security_prompt()
        elif self.strategy == 'strat_5':
            return self.strategy_6_windows_api_prompt()
        
    def get_behaviors(self):
        if self.behavior == '1_registry_modification':
            return self.registry_modification_and_persistance_behaviors()
        elif self.behavior == '2_process_creation':
            return self.process_creation_and_manipulation_behaviors()
        elif self.behavior == '3_file_system_modification':
            return self.file_system_modification_behaviors()
        elif self.behavior == '4_network_activity':
            return self.network_activity_behaviors()
        elif self.behavior == '5_PE_file_modification':
            return self.PE_file_modification_behaviors()
        elif self.behavior == '6_cmd':
            return self.powershell_scripting_behaviors()
        elif self.behavior == '7_evasion_techniques':
            return self.evasion_techniques_behaviors()
        
    def targetted_strategy_prompt(self):
        return (
            f"1. Use alternative Windows-specific functions or language-specific features to achieve the same tasks as the observed behavior(s) in the given function.\n"
            f"2. Try to use serveral steps or indirect ways to achieve the same behavior(s) where possible.\n"
            f"3. Try to use less obvious/less popular functions where possible to achieve the same behavior(s)."
        )
        
    def strategy_1_optimization_prompt(self):
        return (
            "1. Remove code redundancies.\n"
            "2. Identify performance bottlenecks and fix them.\n"
            "3. Simplify the code's logic or structure and optimize data structures and algorithms if applicable.\n"
            "4. Use language-specific features or modern libraries if applicable."
        )
        
    def strategy_2_code_quality_prompt(self):
        return (
            "1. Check error handling and edge cases.\n"
            "2. Follow coding practices and style guidelines.\n"
            "3. Add proper documentation to classes and functions, and comments for complex parts.\n"
        )
    
    def strategy_3_function_splitting_prompt(self):
        return "Make the code reusable by dividing supplied functions into smaller function blocks if and where applicable. The smaller functions should be called inside the respective supplied functions as needed."
    
    def strategy_4_security_prompt(self):
        return (
            "1. Identify security vulnerabilities and fix them.\n"
            "2. If the function you are modifying contains cryptographic operations, change the cryptographic library used for those operations. If no cryptographic operations are present, no changes are necessary.\n"
            "3. Follow secure coding standards and guidelines."
        )
    
    def strategy_5_obfuscation_prompt(self):
        return (
            "1. Change the given function's and LOCAL variable's names to meaningless, hard-to-understand strings which are not real words. DO NOT redefine or rename global variables (given to you) and names of functions that are called inside the given function ( might be defined elsewhere ) under any circumstances.\n"
            "However if the given function name is any of `main`, `wmain`, `WinMain`, `wWinMain`, `DllMain`, `_tWinMain`, `_tmain` do not change it's name, only change the local variable's names inside the function.\n"
            "2. Add unnecessary jump instructions, loops, and conditional statements inside the functions.\n"
            "3. Add unnecessary functions and call those functions inside the original functions.\n"
            "4. Add anti-debugging techniques to the code.\n"
            "5. If there are loops/conditional statements in the code change them to their equivalent alternatives and make them more difficult to follow.\n"
            "6. Incorporate code to the variants that activates under very rare and obscure cases without altering core functionality, making the rare code hard to detect during testing."
        )
    
    def strategy_6_windows_api_prompt(self):
        return (
            "1. Identify all Windows API function calls in the given functions.\n"
            "2. If there are such function calls, replace each identified Windows API function call with an alternative Windows API function call or sequence of calls that achieves the same task.\n"
            "3. If applicable, use indirect methods or wrappers around the Windows API calls to achieve the same functionality.\n"
            "4. Ensure that the functionality remains the same after the replacement."
        )
        
    def get_intro_prompt_variant_gen_orig_strategy(self):
        return (
            f"Below this prompt you are provided headers, global variables, class and struct definitions "
            f"and {self.num_functions} global function definition(s) from a {self.language_name} source code file. The parameters of the functions also have specific types. "
            f"As an intelligent coding assistant, GENERATE one VARIANT of each of these functions: ***{', '.join([func_name for func_name in self.function_names])}*** following these instructions: \n"
        )
    
    def get_intro_prompt_indicator_targetted_strategy(self):
        return (
            f"Below this prompt you are provided headers, global information (variables, class and struct definitions) "
            f"and {self.num_functions} global function definition from a {self.language_name} file. The parameters of the function also have specific types. "
            f"You are also provided a list of specific behaviors. "
            f"As an intelligent coding assistant, first ANALYZE the function to see if the listed behaviors are present. "
            f"If a listed behavior is absent, you don't need to do anything. But if you find one or more listed behaviors in the function, GENERATE one VARIANT of the given function ***{', '.join([func_name for func_name in self.function_names])}*** following the below function modification instructions targetting those behaviors: \n"
        )
    
    def get_functionality_preservation_prompt(self):
        return (
            f"REMEMBER, the generated code MUST MAINTAIN the same FUNCTIONALITY as the original code. Keep the usage of globally declared variables as it is. "
            f"Modify ONLY the {self.num_functions} free/global function(s) "
            f"named ***{', '.join([func_name for func_name in self.function_names])}***. "
            f"If you find any custom functions/custom structure/class objects/custom types/custom variables that are used inside the given {self.num_functions} function(s) but not in the provided code snippet, you can safely assume "
            f"that these are defined elsewhere and you should use them in your generated code as it is. DO NOT modify the names of these and do not redefine them.\n\n"
            f"CRITICAL COMPILATION RULES (violations cause compile errors):\n"
            f"- NEVER DELETE local variable declarations from function bodies. If you rename a variable, keep its declaration line (e.g. 'DWORD CSIDL;' must stay if CSIDL is used, just rename both declaration and all usages together).\n"
            f"- NEVER remove or comment out ANY #include directive. Keep all original includes intact.\n"
            f"- NEVER use Variable-Length Arrays (char buf[n] where n is a runtime variable) - MSVC does not support C99 VLAs. Use fixed-size arrays instead.\n"
            f"- NEVER define, typedef, or #define an identifier named 'string' - it conflicts with Windows SDK SAL annotations.\n"
            f"- NEVER redefine Windows types: BOOL, DWORD, HANDLE, LPSTR, LPCSTR, WORD, UINT, LONG, TRUE, FALSE.\n\n"
        )



    def get_backticks_format_useful_instructions(self):

        if self.language_name == 'c':
            example_code = f"""
            #include <stdio.h>

            int func(int a) {{
                printf("%d\\n", a);
                return a + 1;
            }}
            """
        elif self.language_name == 'cpp':
            example_code = f"""
            #include<iostream>

            int func(int a) {{
                cout << a <<endl;
                return a + 1;
            }}
            """
        


        return (
        f"These CRUCIAL instructions below MUST ALWAYS BE FOLLOWED while generating variants:\n"
        f"1. You MUST NOT regenerate the extra information I provided to you such as headers, global variables, structs and classes for context.\n"
        f"2. If you modify the functions ***{', '.join([func_name for func_name in self.function_names])}***, you MUST NOT regenerate the original code. But "
        f"if a function cannot be changed, then include the original code.\n"
        f"3. ONLY generate the function variants and any new headers/libraries you used.\n"
        f"4. You MUST NOT generate any extra natural language messages/comments.\n"
        f"5. You MUST Generate all the modified functions within a single ```{self.language_name}  ``` tag. For example your response should look like this for one generated function named `int func(int a)`:\n"
        f"{example_code}"
        f"\nRemember, if you have generated multiple functions, you should include all of them within the same ```{self.language_name}  ``` tag.\n"
        f"6. Use the global variables as they are inside your generated functions and do not change/redeclare the global variables.\n"
        f"7. Always complete the function that you generate. Make sure to fill up the function body with the appropriate code. DO NOT leave any function incomplete.\n\n"
    )
        
        
        
    def generate_prompt(self):
        
        functionality_preservation_prompt = self.get_functionality_preservation_prompt()
        backticks_format_useful_instructions = self.get_backticks_format_useful_instructions()
        strategy_prompt = self.get_strategy_prompt()
        
        # print(self.behavior)
    
        if self.behavior is None:
            intro_prompt = self.get_intro_prompt_variant_gen_orig_strategy()
            self.total_prompt = intro_prompt + f"\n{strategy_prompt}\n\n" + functionality_preservation_prompt + backticks_format_useful_instructions
        else:
            intro_prompt = self.get_intro_prompt_indicator_targetted_strategy()
            self.total_prompt = intro_prompt + f"\n{strategy_prompt}\n\n" + self.get_behaviors() + functionality_preservation_prompt + backticks_format_useful_instructions
            
        return self.total_prompt


def get_prompt(
    num_functions,
    function_names,
    variant_generation_strategy,
    strategy_num,
    is_json_prompt=False,
    behavior=None,
    error_list=None,
    error_type=None,
    execution_output=None,
    language_name="c++",
):
    prompt = ''

    prompt_generator = PromptGenerator(num_functions, function_names, strategy_num,
                                       variant_generation_strategy, behavior,
                                       error_list, error_type, execution_output,
                                       language_name)
        
    
    prompt = prompt_generator.generate_prompt()
    
    # prompt = (
    #     f"Below this prompt you are provided headers, global variables, class and struct definitions "
    #     f"and {num_functions} global function definition(s) from a {language_name} source code file. The parameters of the functions also have specific types. "
    #     f"As an intelligent coding assistant, GENERATE one VARIANT of each of these functions: ***{', '.join([func_name for func_name in function_names])}*** following these instructions: \n"
    #     f"{strategy_prompt}\n\n"
    #     f"REMEMBER, the generated code MUST MAINTAIN the same FUNCTIONALITY as the original code. Keep the usage of globally declared variables as it is. "
    #     f"Modify ONLY the {num_functions} free/global function(s) "
    #     f"named ***{', '.join([func_name for func_name in function_names])}***. "
    #     f"If you find any custom functions/custom structure/class objects/custom types/custom variables that are used inside the given {num_functions} function(s) but not in the provided code snippet, you can safely assume "
    #     f"that these are defined elsewhere and you should use them in your generated code as it is. DO NOT modify the names of these and do not redefine them.\n\n"
    # )

    useful_instructions_json = (
        f"These CRUCIAL instructions below MUST ALWAYS BE FOLLOWED while generating variants:\n"
        f"1. You MUST NOT regenerate the extra information I provided to you such as headers, global variables, structs and classes for context.\n"
        f"2. If you modify the functions ***{', '.join([func_name for func_name in function_names])}***, you MUST NOT regenerate the original code. But "
        f"if a function cannot be changed, then include the original code.\n"
        f"3. ONLY generate the function variants and any new headers/libraries you used.\n"
        f"4. Use the global variables as they are inside your generated functions and do not change/redeclare the global variables.\n"
        "5. Generate all your response in a JSON format with the following structure:\n"
        """
        ```json
        {
        \"modified code\": the full generated code of the modified function(s) in the form of a single line string with appropriate escape characters and new lines to be placed here so that it can be parsed easily by a json parser. \n,
        \"comments\": any natural language comments regarding the code generation to be placed here
        }\n
        ```
        For example your response should look like this for a generated function named void func():\n
        ```json
        {
        #include<iostream>\\n\\nvoid func() {\\n   std::cout << \\\"Found file in C:\\\Drive  \\\" << std::endl;\\n}\",
        \"modified code\": \"
        \"comments\": \"This function prints a string to the standard output. It demonstrates basic output in C++ using cout.\"
        }
        ```
        """
        f'6. DO NOT use ``` ``` or """ """ to generate the modified code in the field "modified code". Make sure to use appropriate escape characters ( \\" for literal strings, \\\\ for backslashes, \\t for tabs etc.) in the modified code you generate. '
        f"For new lines, directly use \\n no need to escape them. Don't add any unescaped newline in the generated code. Look at the provided example in previous prompt to understand how to generate better\n\n"
    )

    mixed_format_useful_instructions = (
        f"These CRUCIAL instructions below MUST ALWAYS BE FOLLOWED while generating variants:\n"
        f"1. You MUST NOT regenerate the extra information I provided to you such as headers, global variables, structs and classes for context.\n"
        f"2. If you modify the functions ***{', '.join([func_name for func_name in function_names])}***, you MUST NOT regenerate the original code. But "
        f"if a function cannot be changed, then include the original code.\n"
        f"3. ONLY generate the function variants and any new headers/libraries you used.\n"
        f"4. You MUST NOT generate any extra natural language messages/comments.\n"
        f"5. You MUST Generate the modified functions within ```{language_name}  ``` tags. For example your response should look like this for a generated function named int func(int a):\n"
        """
        ```cpp

        #include<iostream>

        int func(int a) {
                cout << a <<endl;
                return a + 1;
            }

        ```
        """
        f"6. Use the global variables as they are inside your generated functions and do not change/redeclare the global variables.\n"
        f"7. For any comments on what modifications you did use JSON response format. For example your JSON response should look like this for the generated function named int func(int a):\n"
        """
        ```json
        {
        \"comments\": \"This function prints an integer to the output and returns the value of the integer + 1.\"
        }
        ```
        """
    )

    # backticks_format_useful_instructions = (
    #     f"These CRUCIAL instructions below MUST ALWAYS BE FOLLOWED while generating variants:\n"
    #     f"1. You MUST NOT regenerate the extra information I provided to you such as headers, global variables, structs and classes for context.\n"
    #     f"2. If you modify the functions ***{', '.join([func_name for func_name in function_names])}***, you MUST NOT regenerate the original code. But "
    #     f"if a function cannot be changed, then include the original code.\n"
    #     f"3. ONLY generate the function variants and any new headers/libraries you used.\n"
    #     f"4. You MUST NOT generate any extra natural language messages/comments.\n"
    #     f"5. You MUST Generate all the modified functions within a single ```{language_name}  ``` tag. For example your response should look like this for one generated function named `int func(int a)`:\n"
    #     """
    #     ```cpp

    #     #include<iostream>

    #     int func(int a) {
    #             cout << a <<endl;
    #             return a + 1;
    #         }

    #     ```
    #     """
    #     f"\nRemember, if you have generated multiple functions, you should include all of them within the same ```{language_name}  ``` tag.\n"
    #     f"6. Use the global variables as they are inside your generated functions and do not change/redeclare the global variables.\n"
    #     f"7. Always complete the function that you generate. Make sure to fill up the function body with the appropriate code. DO NOT leave any function incomplete.\n"
    # )

    # prompt += backticks_format_useful_instructions

    if strategy_num in (1, 2, 4, 6):
        #print("strategy_num", strategy_num)
        prompt += f"8. DO NOT change the function name, return type, parameters and their types, or the name and number of parameters of the original functions while generating variants.\n\n"

        if is_json_prompt:
            prompt += f"9. DO NOT generate anything outside the JSON format. Your final output should be a single JSON object with keys 'modified_code', 'function_map', 'comments'.\n"

    elif strategy_num == 5:
        #print("strategy_num", strategy_num)

        if is_json_prompt:
            prompt += additional_strategy_wise_json_prompt_dict['obfuscation_prompt_json']
        else:
            prompt += additional_strategy_wise_backticks_prompt_dict['obfuscation_splitting_prompt_no_mapping']

    elif strategy_num == 3:
        #print("strategy_num", strategy_num)

        if is_json_prompt:
            prompt += additional_strategy_wise_json_prompt_dict['function_splitting_prompt_json']
        else:
            prompt += additional_strategy_wise_backticks_prompt_dict['function_splitting_prompt_no_mapping']

    return prompt


def generate_simple_prompt(
    num_functions, function_names, strategy_prompt, strategy_num, language_name="c++"
):

    prompt = (
        f"Below this prompt you are provided headers, global variables, class and struct definitions "
        f"and {num_functions} global function definition(s) from a {language_name} source code file. "
        f"As a coding assistant, GENERATE VARIANTS of these functions namely: ***{', '.join([func_name for func_name in function_names])}*** following these instructions: \n"
        f"{strategy_prompt}\n"
        f"REMEMBER, the generated code MUST MAINTAIN the same FUNCTIONALITY as the original code. Make sure to ALWAYS generate the code, I don't need the code explanation.\n"
        f"SAFETY VALVE: If a particular transformation would break semantics or produce unsafe code, "
        f"skip that specific transformation and leave that part of the code unchanged. "
        f"It is better to produce partially-transformed but CORRECT code than fully-transformed but BROKEN code."
    )

    return prompt


# print(get_prompt(1, ["func1"], strategy_prompt_dict["strat_2_optimization"], 1))
