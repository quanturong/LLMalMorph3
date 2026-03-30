import sys, os
sys.path.insert(0, 'E:/LLMalMorph2')
os.chdir('E:/LLMalMorph2')

from src.project_compiler import ProjectCompiler
import logging
logging.basicConfig(level=logging.DEBUG)

print("=== Testing compiler detection ===")
try:
    compiler = ProjectCompiler(compiler='auto')
    print(f"compiler_type: {compiler.compiler_type}")
    print(f"compiler dict: {compiler.compiler}")
    print(f"msvc_env has INCLUDE: {'INCLUDE' in (compiler.msvc_env or {})}")
    if compiler.msvc_env:
        print(f"cl path: {compiler.compiler}")
except Exception as e:
    import traceback
    print(f"Exception: {e}")
    print(traceback.format_exc())
