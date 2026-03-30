import sys, os
sys.path.insert(0, 'E:/LLMalMorph2')
os.chdir('E:/LLMalMorph2')

output_lines = []

try:
    from src.project_detector import ProjectDetector
    from src.project_compiler import ProjectCompiler

    build_dir = 'project_mutation_output/variant_build_4ded889f'
    output_lines.append(f'Build dir: {build_dir}')
    output_lines.append(f'Build dir exists: {os.path.exists(build_dir)}')
    if os.path.exists(build_dir):
        output_lines.append(f'Files: {os.listdir(build_dir)[:10]}')

    detector = ProjectDetector(build_dir)
    projects = detector.detect_projects(recursive=True)
    output_lines.append(f'Projects: {len(projects)}')
    
    if projects:
        p = projects[0]
        output_lines.append(f'Project name: {p.name}')
        output_lines.append(f'Project dict: {str(p.__dict__)[:500]}')
        
        compiler = ProjectCompiler(compiler='auto')
        output_dir = 'project_mutation_output/test_build2'
        try:
            result = compiler.compile_project(
                project=p, 
                output_dir=output_dir, 
                output_name='test', 
                max_fix_attempts=0, 
                auto_fix=False
            )
            output_lines.append(f'Result type: {type(result).__name__}')
            if result:
                output_lines.append(f'Success: {result.success}')
                output_lines.append(f'Errors: {str(result.errors)[:1000] if result.errors else "None"}')
                output_lines.append(f'Command: {str(getattr(result, "command", ""))[:300]}')
                output_lines.append(f'Return code: {getattr(result, "return_code", "N/A")}')
            else:
                output_lines.append('Result is None!')
        except Exception as e:
            output_lines.append(f'Compile exception: {type(e).__name__}: {str(e)[:500]}')
            import traceback
            output_lines.append(traceback.format_exc()[:1000])
            
except Exception as e:
    output_lines.append(f'Setup exception: {type(e).__name__}: {str(e)[:500]}')
    import traceback
    output_lines.append(traceback.format_exc()[:1000])

with open('E:/LLMalMorph2/compile_test_result.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(output_lines))
print('Done')
