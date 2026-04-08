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
            "- If the function is a class method (has 'self' parameter), keep 'self' as the first parameter name. You may rename other parameters only as part of strat_5.\n"
            "- NEVER change 4-space indentation of the function body. All added code must also use 4-space indentation.\n"
            "- When using dynamic __import__ or getattr: ensure the resolved name exactly matches the original module/attribute name. Wrong names cause runtime failures.\n"
            "- For strat_4/strat_2 (fragmentation/state machine): define ALL helper functions at MODULE level (outside the class if in a class), not nested inside the main function.\n"
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
            "- For strat_4/strat_2 (fragmentation/state machine): define ALL helper functions at the FILE/MODULE level, not nested inside the main function.\n"
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
            # strat_2: Control Flow Flattening
            "strat_2": (
                "PYTHON-SPECIFIC TECHNIQUES:\n"
                "- State machine pattern:\n"
                "  ```\n"
                "  def _s0(ctx): ctx['v'] = prepare(ctx['input']); return 1\n"
                "  def _s1(ctx): ctx['v'] = process(ctx['v']); return 2 if ctx['v'] else 99\n"
                "  def _s99(ctx): return None  # dead state with plausible code\n"
                "  _dispatch = {0: _s0, 1: _s1, 2: _s2, 99: _s99}\n"
                "  _ctx = {'input': arg, 'v': None}; _st = 0\n"
                "  while _st is not None: _st = _dispatch[_st](_ctx)\n"
                "  return _ctx['result']\n"
                "  ```\n"
                "- Opaque predicate example: `if (len(str(id(self))) | 1) > 0:` (always True, looks like a guard)\n"
                "- Opaque predicate example: `if not (False and __import__('os').getpid() < 0):` (always True)\n"
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
            # strat_4: Function Fragmentation
            "strat_4": (
                "PYTHON-SPECIFIC TECHNIQUES:\n"
                "- Use closures to share state without globals:\n"
                "  ```\n"
                "  def _make_pipeline(raw):\n"
                "      _state = {'data': raw}\n"
                "      def _normalize(_s): _s['data'] = _s['data'].strip(); return _s\n"
                "      def _encode(_s): _s['data'] = _s['data'].encode(); return _s\n"
                "      return _state\n"
                "  ```\n"
                "- Or use a pipeline list: `_ops = [_normalize_input, _build_payload, _encode_data, _dispatch_result]`\n"
                "  then: `_ctx = {'v': arg}; [op(_ctx) for op in _ops]; return _ctx['v']`\n"
                "- Name helpers generically: `_normalize_input`, `_build_request_data`, `_handle_response`, `_finalize`\n"
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
            # strat_2: Control Flow Flattening
            "strat_2": (
                "JAVASCRIPT-SPECIFIC TECHNIQUES:\n"
                "- State machine pattern:\n"
                "  ```js\n"
                "  const _s0 = ctx => { ctx.v = prepare(ctx.input); return 1; };\n"
                "  const _s1 = ctx => { ctx.v = process(ctx.v); return ctx.v ? 2 : 99; };\n"
                "  const _s99 = ctx => null;  // dead state\n"
                "  const _disp = {0:_s0, 1:_s1, 2:_s2, 99:_s99};\n"
                "  const _ctx = {input: arg, v: null}; let _st = 0;\n"
                "  while (_st !== null) _st = _disp[_st](_ctx);\n"
                "  return _ctx.result;\n"
                "  ```\n"
                "- Opaque predicate: `if ((Object.keys(_ctx).length | 1) !== 0)` (always True)\n"
                "- Opaque predicate: `if (typeof undefined !== 'number')` (always True)\n"
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
            # strat_4: Function Fragmentation
            "strat_4": (
                "JAVASCRIPT-SPECIFIC TECHNIQUES:\n"
                "- Use closures for shared state:\n"
                "  ```js\n"
                "  function _makeCtx(raw) { return { data: raw }; }\n"
                "  function _normalizeData(ctx) { ctx.data = ctx.data.trim(); return ctx; }\n"
                "  function _encodePayload(ctx) { ctx.data = Buffer.from(ctx.data); return ctx; }\n"
                "  ```\n"
                "  Then in main: `const _ctx = _makeCtx(arg); [_normalizeData, _encodePayload, _dispatch].forEach(f => f(_ctx)); return _ctx.result;`\n"
                "- Name helpers generically: `_normalizeInput`, `_buildRequestData`, `_handleResponse`, `_finalizeOutput`\n"
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
            # strat_2: Control Flow Flattening
            "strat_2": (
                "C/C++-SPECIFIC TECHNIQUES:\n"
                "- Opaque predicate example: `if ((uintptr_t)ctx | 1)` (always true)\n\n"
                "CORRECT PATTERN (follow this EXACTLY — deviations cause compile errors):\n"
                "```\n"
                "// 1. UNIQUE struct name per function: _Ctx_<FuncName>\n"
                "// 2. ONE field per original variable — PRESERVE THE EXACT TYPE\n"
                "//    char* stays char* (NOT char[260]) — pointer params are POINTERS\n"
                "//    SOCKET stays SOCKET, struct sockaddr_in stays struct sockaddr_in\n"
                "// 3. Only include fields you actually USE — do NOT add padding/dummy fields\n"
                "typedef struct {\n"
                "    char *host;              // was: char *host parameter\n"
                "    char *file;              // was: char *file parameter\n"
                "    unsigned int addr;       // was: local variable\n"
                "    struct sockaddr_in sa;   // was: local struct\n"
                "    SOCKET sock;             // was: local SOCKET\n"
                "    char buf[4096];          // was: local char buf[4096]\n"
                "    int result;              // return value\n"
                "} _Ctx_OriginalFunc;\n\n"
                "// State functions defined OUTSIDE (C has NO nested functions)\n"
                "static int _of_s0(void *_p) {\n"
                "    _Ctx_OriginalFunc *ctx = (_Ctx_OriginalFunc*)_p;\n"
                "    ctx->addr = Resolve(ctx->host);  // use ctx->host (pointer), NOT strcpy\n"
                "    return (ctx->addr == 0) ? -1 : 1;\n"
                "}\n"
                "static int _of_s1(void *_p) {\n"
                "    _Ctx_OriginalFunc *ctx = (_Ctx_OriginalFunc*)_p;\n"
                "    ctx->sa.sin_family = AF_INET;\n"
                "    ctx->sa.sin_addr.s_addr = ctx->addr;\n"
                "    return 2;\n"
                "}\n"
                "static int _of_s2(void *_p) {\n"
                "    _Ctx_OriginalFunc *ctx = (_Ctx_OriginalFunc*)_p;\n"
                "    closesocket(ctx->sock);  // void-returning → call as STATEMENT, NO assignment\n"
                "    return -1;\n"
                "}\n"
                "static int _of_s99(void *_p) { return -1; } // dead state\n"
                "typedef int (*_STATE_FN_OriginalFunc)(void*);\n"
                "static _STATE_FN_OriginalFunc _dispatch_OriginalFunc[] = {_of_s0, _of_s1, _of_s99};\n\n"
                "// Entry: assign pointer params directly (they are already pointers)\n"
                "int OriginalFunc(char *host, char *file) {\n"
                "    _Ctx_OriginalFunc _c; memset(&_c, 0, sizeof(_c));\n"
                "    _c.host = host;  // pointer assignment — correct\n"
                "    _c.file = file;  // pointer assignment — correct\n"
                "    int _st = 0;\n"
                "    while (_st >= 0) _st = _dispatch_OriginalFunc[_st](&_c);\n"
                "    return _c.result;\n"
                "}\n"
                "```\n\n"
                "CRITICAL RULES:\n"
                "- Pointer params (char*, BYTE*, void*) → store as POINTER in struct, assign with `=`\n"
                "- Array locals (char buf[N]) → store as array in struct, copy with strcpy/memcpy\n"
                "- NEVER convert char* param to char[260] — causes C3863 (array not assignable)\n"
                "- NEVER add unused/padding fields — only fields that map to real variables\n"
                "- Keep ORIGINAL variable names as field names when possible (readable + fewer mistakes)\n\n"
                "VOID FUNCTION HANDLING:\n"
                "- If the original function returns void → entry function returns void, NO 'result' field.\n"
                "- If a CALLED function returns void (e.g. free(), memset(), sendReport(), closesocket()):\n"
                "  CORRECT: sendReport(ctx->buf); return 3;\n"
                "  WRONG:   ctx->result = sendReport(ctx->buf);  // C2186 void cannot be assigned!\n"
                "- If unsure whether a function returns void, call it as a STATEMENT (never assign).\n\n"
                "COMMON MISTAKES (each causes compile errors):\n"
                "- Assigning void function result to a field → C2186 (see VOID HANDLING above)\n"
                "- Defining struct/state functions INSIDE the main function → C has NO nested functions\n"
                "- Reusing `_Ctx` name for multiple functions → use _Ctx_FuncA, _Ctx_FuncB (avoids C2371)\n"
                "- Naming function pointers after Win32 APIs (e.g. `int (*GetUserNameA)(...)`) → causes C2365\n"
                "- Missing struct fields → every `ctx->X` access needs a matching field (C2039)\n"
                "- Converting pointer params to fixed arrays → causes C3863\n"
                "- Using `_st` variable inside state functions (it's only in the entry function) → causes C2065\n"
                "- Using array subscript [] on non-array/non-pointer field → C2109\n"
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
            # strat_4: Function Fragmentation
            "strat_4": (
                "C/C++-SPECIFIC TECHNIQUES:\n\n"
                "--- HEADER FILE RULES (prevents C2084 'already has a body') ---\n"
                "CRITICAL: If this file is a .h file:\n"
                "  1) Add `#pragma once` as the VERY FIRST LINE of the file.\n"
                "  2) Mark ALL new helpers and structs `static`.\n"
                "  3) Keep every existing function in EXACTLY the same order — do NOT reorder.\n"
                "  4) Do NOT add any #include lines not already in the original file.\n"
                "  5) Insert new helpers IMMEDIATELY ABOVE the function you are decomposing.\n\n"
                "--- NAMING CONVENTION (MANDATORY — violation = compilation failure) ---\n"
                "Every struct, typedef, and helper MUST end with the ORIGINAL FUNCTION NAME.\n"
                "If the function is 'combineArrs':  _Ctx_combineArrs, _step0_combineArrs, _step1_combineArrs\n"
                "If the function is 'sendReport':   _Ctx_sendReport, _step0_sendReport, _step1_sendReport\n"
                "If the function is 'initGlobals':   _Ctx_initGlobals, _step0_initGlobals\n"
                "FORBIDDEN: _Ctx, _OP_CTX, _init, _proc, _step0 — these WILL cause C2011/C2084 redefinition errors.\n\n"
                "--- CONTEXT STRUCT ---\n"
                "  `static struct _Ctx_<funcname> { <fields> };`\n"
                "  a) For EVERY local variable, add a matching field (PRESERVE EXACT TYPE).\n"
                "     - `char buf[260]` → field `char buf[260]` (array stays array)\n"
                "     - `char* ptr` → field `char* ptr` (pointer stays pointer)\n"
                "     - `int i, count` → TWO fields: `int i; int count;`\n"
                "  b) For EVERY function parameter, add a matching field.\n"
                "  c) Add a 'result' field matching the return type (skip if void).\n"
                "  d) VERIFY: for every `ctx->X`, confirm `X` exists in struct.\n\n"
                "--- HELPER FUNCTIONS ---\n"
                "  `static int _step0_<funcname>(struct _Ctx_<funcname>* ctx) { ... return 0; }`\n"
                "  `static int _step1_<funcname>(struct _Ctx_<funcname>* ctx) { ... return 0; }`\n\n"
                "--- VOID FUNCTION HANDLING ---\n"
                "- If original returns void: NO 'result' field.\n"
                "- void calls (free, memset, closesocket): call as STATEMENT, not assignment.\n"
                "  CORRECT: free(ctx->buf); return 0;\n"
                "  WRONG:   ctx->result = free(ctx->buf);  // C2186!\n\n"
                "--- WIN32 API COLLISION PREVENTION (C2373 errors) ---\n"
                "NEVER redeclare or create variables/function-pointers named after Win32 APIs.\n"
                "WRONG: `BOOL (WINAPI *Process32First)(...) = NULL;`  // redefines Win32 API → C2373!\n"
                "WRONG: `HANDLE OpenProcessToken = ...;`  // redefines Win32 API → C2373!\n"
                "CORRECT: Just CALL the APIs directly: `Process32First(hSnap, &pe);`\n"
                "The context struct should only hold DATA (variables, buffers, handles) — never function pointers for APIs that are already available via #include.\n\n"
                "--- C RULES ---\n"
                + ("- Declare ALL variables at the TOP of a block (C89 style).\n"
                   if compiler_type == 'msvc' else
                   "- Variables can be declared anywhere in a block (C99+). For-loop initializers are OK.\n") +
                "- NEVER define functions inside another function body.\n"
                "- Pointer params (char*) → store as pointer. Array locals (char buf[N]) → store as array.\n"
                "- Use C-style casts. Use NULL not nullptr.\n"
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
    # Strategy 1: Control Flow Flattening via State Machine
    # Goal: Destroy recognizable sequential/conditional code structure
    "strat_2": (
        "TASK: Transform the function's control flow into a state-machine dispatch loop.\n\n"
        "RULES:\n"
        "1. Identify every major logical block (initialization, each branch of if/elif/else, loop bodies, cleanup/return). Assign each a numeric state ID starting from 0.\n"
        "2. Extract each block into a separate helper function defined OUTSIDE the main function. Name them blandly: _s0_<FuncName>, _s1_<FuncName>, etc.\n"
        "3. Replace the original code body with a dispatch loop:\n"
        "   - Build a dispatch table mapping state ID → helper function.\n"
        "   - Run a while-loop that calls dispatch[current_state](context) and receives the next state.\n"
        "   - Use a shared mutable context struct to pass data between states.\n"
        "   - C ONLY — CONTEXT STRUCT CHECKLIST (follow step-by-step to avoid C2039 errors):\n"
        "     a) Read the ENTIRE original function from first line to last line.\n"
        "     b) For EVERY local variable declaration, add a matching field to the context struct (PRESERVE THE EXACT TYPE).\n"
        "     c) For EVERY function parameter, add a matching field.\n"
        "     d) Add a 'result' field matching the function's return type (skip if void).\n"
        "     e) VERIFY: for every `ctx->X` access in state functions, confirm `X` exists in your struct. If not, ADD IT.\n"
        "4. Add 1-2 bogus dead states containing plausible-looking but harmless code (e.g. zeroing a buffer, incrementing a counter).\n"
        "5. Insert opaque predicates (conditions that always evaluate the same way) as guards in 1-2 state transitions.\n"
        "6. Keep the original function's signature (name, parameters, return type) EXACTLY the same.\n"
        "7. Call ALL existing API functions DIRECTLY — do NOT add dynamic API resolution. Do NOT create variables or fields named after Win32 APIs.\n\n"
        "VOID FUNCTION HANDLING (CRITICAL):\n"
        "- If the original function returns void, the entry function must also return void — no result field needed.\n"
        "- If a called function returns void (e.g. sendReport(), free(), memset()), call it as a STATEMENT, NOT an assignment:\n"
        "  CORRECT: sendReport(ctx->buf); return 3;\n"
        "  WRONG: ctx->result = sendReport(ctx->buf);  // C2186: void cannot be assigned!\n"
        "- If a called function returns a value you DON'T use, still call it as a statement.\n\n"
        "ANTI-HEURISTIC GUIDELINES:\n"
        "- Use BLAND generic names: _s0, _s1, _ctx, _st, _disp — nothing crypto-looking.\n"
        "- AVOID names containing: _enc, _dec, _xor, _key, _cipher, _crypt, _payload, _shell, _inject.\n"
        "- Dead states should look like normal utility code, NOT decoy malware logic.\n"
        "- Opaque predicates should use arithmetic/pointer tricks, NOT string comparisons or API calls.\n"
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
    # Strategy 3: Function Fragmentation with Indirect Call Chain
    # Goal: Split the monolithic function into 4-6 small fragments so no single piece carries enough context to trigger detection
    "strat_4": (
        "TASK: Fragment the function into a chain of small, single-responsibility helper functions and replace the original body with an orchestration call chain.\n\n"
        "*** MANDATORY NAMING RULE (violation = compilation failure) ***\n"
        "Every new struct, typedef, and helper function you create MUST include the ORIGINAL FUNCTION NAME as a suffix.\n"
        "Example: if the function is called 'sendReport', your names must be:\n"
        "  struct: _Ctx_sendReport  (NOT _Ctx, NOT _OpCtx)\n"
        "  helpers: _step0_sendReport, _step1_sendReport, _step2_sendReport  (NOT _step0, NOT _init)\n"
        "Example: if the function is called 'combineArrs', your names must be:\n"
        "  struct: _Ctx_combineArrs\n"
        "  helpers: _step0_combineArrs, _step1_combineArrs\n"
        "NEVER use a name without the function suffix. _Ctx, _init, _proc, _step0 alone WILL collide with other files.\n\n"
        "RULES:\n"
        "1. Extract every distinct logical unit into its own named helper function OUTSIDE the main function.\n"
        "2. Aim for 3-5 helper functions. Each helper should be 5-15 lines and have a single clear responsibility.\n"
        "3. AVOID names containing: enc, dec, xor, key, cipher, crypt, payload, shell, inject, hook, exploit.\n"
        "4. Pass shared state between helpers using a context struct (C) or a dict/object (Python/JS):\n"
        "   - The context struct MUST contain a field for EVERY local variable AND EVERY parameter of the original function.\n"
        "   - If a helper accesses `ctx->X`, field `X` MUST exist in the struct.\n"
        "5. Keep the original function's signature (name, parameters, return value) EXACTLY the same.\n"
        "6. ALL original operations MUST appear somewhere across the fragments — nothing may be dropped.\n\n"
        "HEADER FILE SAFETY (C/C++ — prevents C2084 'already has a body' errors):\n"
        "- If the file is a .h header file, add `#pragma once` as the VERY FIRST LINE.\n"
        "- Mark ALL new helper functions and structs as `static`.\n"
        "- Do NOT reorder or move existing functions that you are NOT decomposing.\n"
        "- Do NOT add any #include directives that are not already present.\n"
        "- Output the COMPLETE file — every original function must still appear exactly once.\n\n"
        "WIN32 API COLLISION PREVENTION (C/C++ — prevents C2373 redefinition errors):\n"
        "- NEVER create variables, struct fields, or function pointers named after Win32 API functions.\n"
        "  WRONG: `BOOL (WINAPI *Process32First)(...);` — redefines the Win32 API name → C2373!\n"
        "  WRONG: `HANDLE OpenProcessToken;` — shadows the Win32 API → C2373!\n"
        "- Just CALL Win32 APIs directly in your helper functions. They are already available via headers.\n"
        "- The context struct holds only DATA (variables, buffers, handles, counters) — never API function pointers.\n\n"
        "ANTI-HEURISTIC GUIDELINES:\n"
        "- Each fragment should look like a normal utility function — not suspicious in isolation.\n"
        "- Fragment boundaries should NOT align with 'suspicious' operations. Mix benign and sensitive code in each fragment.\n"
        "- The orchestration in the main function should look like normal sequential calls, not an obfuscated dispatch.\n"
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
