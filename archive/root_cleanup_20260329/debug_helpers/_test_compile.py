import sys
sys.path.insert(0, '.')
from src.project_detector import ProjectDetector
from src.project_compiler import ProjectCompiler

build_dir = 'project_mutation_output/variant_build_4ded889f'
detector = ProjectDetector(build_dir)
projects = detector.detect_projects(recursive=True)
print('Projects:', len(projects))
p = projects[0]
print('Project name:', p.name)
# Print all public attributes
attrs = {k: getattr(p, k, 'N/A') for k in dir(p) if not k.startswith('_') and not callable(getattr(p, k, None))}
for k, v in attrs.items():
    print(f'  {k}: {str(v)[:100]}')

print('\n--- Trying compile ---')
compiler = ProjectCompiler(compiler='auto')
output_dir = 'project_mutation_output/test_build'
try:
    result = compiler.compile_project(project=p, output_dir=output_dir, output_name='test', max_fix_attempts=0, auto_fix=False)
    print('Result:', result)
    if result:
        print('  Success:', result.success)
        print('  Errors:', str(result.errors)[:500] if result.errors else 'None')
except Exception as e:
    print(f'Exception: {type(e).__name__}: {e}')
