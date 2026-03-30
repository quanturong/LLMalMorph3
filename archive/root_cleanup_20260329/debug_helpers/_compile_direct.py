import sys, os
sys.path.insert(0, 'E:/LLMalMorph2')
os.chdir('E:/LLMalMorph2')

from src.project_compiler import ProjectCompiler
from src.project_detector import ProjectDetector

build_dir = 'project_mutation_output/variant_build_4ded889f'

print(f"Testing compile of: {build_dir}")

detector = ProjectDetector(build_dir)
projects = detector.detect_projects(recursive=True)
print(f"Projects detected: {len(projects)}")

if projects:
    p = projects[0]
    print(f"Project: {p.name}")
    
    compiler = ProjectCompiler(compiler='auto')
    output_dir = 'project_mutation_output/test_build3'
    os.makedirs(output_dir, exist_ok=True)
    
    result = compiler.compile_project(
        project=p,
        output_dir=output_dir,
        output_name='test',
        max_fix_attempts=0,
        auto_fix=False
    )
    
    if result:
        print(f"\nSuccess: {result.success}")
        print(f"Return code: {getattr(result, 'return_code', 'N/A')}")
        if result.errors:
            errors = result.errors
            # Show first 3KB of errors
            print(f"\nErrors (first 3KB):\n{errors[:3000]}")
        else:
            print("No errors")
    else:
        print("Result is None!")
