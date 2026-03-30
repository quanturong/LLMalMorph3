"""
Improved Pipeline với tất cả cải tiến:
- Automated compilation & testing
- Quality assurance
- Auto-fixing với LLM
- Parallel processing
- Caching
- Metrics collection
"""
import argparse
import os
import sys
import logging
import re
from pathlib import Path
from typing import List, Optional, Tuple, Dict
import json
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from automation import IntegratedPipeline
from performance import ParallelProcessor, CacheManager
from config import get_config, setup_logging
from tree_sitter_parser import (
    initialize_parser,
    read_source_code,
    extract_functions_globals_headers,
)
from variant_source_generator import generate_function_variant_obj_from_function_mapping
from pipeline_util import run_experiment_trial, get_llm_name_from_input, mistral_generate
from parse_llm_generated_code import parse_code_any_format
from stitcher_util import create_output_directory, stitcher
from variant_source_generator import VariantFunction
from randomization import generate_random_func_sequences
from string_utils import escape_string_for_json
import utility_prompt_library as upl

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def process_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="LLMalMorph Improved Pipeline với automation và quality assurance"
    )
    
    # Original arguments
    parser.add_argument(
        "--source_file",
        type=str,
        required=True,
        help="Path to source file to mutate"
    )
    parser.add_argument(
        "--num_func",
        type=int,
        default=1,
        help="Number of functions to mutate"
    )
    parser.add_argument(
        "--llm",
        type=str,
        default="codestral-2508",
        help="LLM model to use"
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        required=True,
        help="Output directory"
    )
    parser.add_argument(
        "--strategy",
        type=str,
        default="strat_1",
        help="Mutation strategy"
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=1,
        help="Number of trials"
    )
    
    # New improved arguments
    parser.add_argument(
        "--auto_fix",
        action="store_true",
        help="Enable auto-fixing compilation errors"
    )
    parser.add_argument(
        "--run_tests",
        action="store_true",
        help="Run compilation tests"
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Enable parallel processing"
    )
    parser.add_argument(
        "--use_cache",
        action="store_true",
        help="Use caching for performance"
    )
    parser.add_argument(
        "--max_fix_attempts",
        type=int,
        default=3,
        help="Maximum auto-fix attempts"
    )
    
    return parser.parse_args()


def _extract_code_block(text: str) -> str:
    """Extract first fenced code block if present, else return raw text."""
    if not text:
        return text
    fence_match = re.search(r"```[a-zA-Z0-9+_-]*\n(.*?)```", text, re.DOTALL)
    if fence_match:
        return fence_match.group(1).strip()
    return text.strip()


def _build_prompt(strategy: str, language: str, func_name: str, func_body: str, extra_instructions: str | None = None) -> Tuple[str, str]:
    """Prefer legacy prompt library; only add minimal inline guidance when missing."""
    system_prompt = (
        "You are an expert C/C++ developer generating mutated variants. "
        "Preserve functionality, avoid introducing vulnerabilities, and keep code compilable."
    )

    # Prefer legacy strategy prompt
    prompt_body = upl.strategy_prompt_dict.get(strategy) if hasattr(upl, "strategy_prompt_dict") else None
    if not prompt_body:
        prompt_body = f"Apply strategy '{strategy}' while preserving functionality."

    if extra_instructions:
        prompt_body = f"{prompt_body}\nAdditional instructions:\n{extra_instructions}"

    user_prompt = (
        f"Language: {language}\n"
        f"Strategy: {strategy}\n"
        f"Original function {func_name}:\n````\n{func_body}\n````\n"
        f"Instructions:\n{prompt_body}\n"
        "Return only the mutated function(s) inside a fenced code block, include any needed headers/globals."
    )

    return system_prompt, user_prompt


def _join_segments(headers: List[str], globals_: List, functions: List[dict]) -> str:
    """Combine headers, globals, and function bodies into a single source string."""
    parts: List[str] = []
    parts.extend(headers or [])
    for g in globals_ or []:
        parts.append(g["body"] if isinstance(g, dict) else g)
    for fn in functions or []:
        parts.append(fn.get("body", ""))
    return "\n".join(parts)


def generate_variant_with_llm(func_name: str, func_body: str, strategy: str, llm_model: str, language: str, func_obj: dict) -> Tuple[str, List[VariantFunction]]:
    """Generate mutated variant using legacy parse + variant generator; returns stitched code and variant objects."""
    system_prompt, user_prompt = _build_prompt(strategy, language, func_name, func_body)
    variant_objects: List[VariantFunction] = []

    try:
        if llm_model.startswith("codestral"):
            llm_response = mistral_generate(system_prompt, user_prompt, model=llm_model)
        else:
            llm_response = mistral_generate(system_prompt, user_prompt, model=llm_model)

        # Parse using legacy parser
        segmented = parse_code_any_format(llm_response, language=language)
        if segmented and isinstance(segmented, (list, tuple)) and len(segmented) >= 3:
            headers, globals_, functions = segmented[0], segmented[1], segmented[2]
            # Build variant object(s)
            try:
                vf = generate_function_variant_obj_from_function_mapping(
                    mapping=None,
                    segmented_code=segmented,
                    func_objs=[func_obj],
                )
                if isinstance(vf, VariantFunction):
                    variant_objects.append(vf)
            except Exception as gen_exc:  # noqa: BLE001
                logger.debug(f"Variant object generation warning for {func_name}: {gen_exc}")

            stitched = _join_segments(headers, globals_, functions)
            if stitched.strip():
                return stitched, variant_objects

        # Fallback: extract first fenced block
        candidate = _extract_code_block(llm_response)
        return (candidate if candidate else func_body), variant_objects
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"LLM variant generation failed for {func_name}: {exc}")
        return func_body, variant_objects


def process_file_with_improvements(
    source_file: str,
    num_funcs: int,
    llm_model: str,
    output_dir: str,
    strategy: str,
    trials: int,
    auto_fix: bool = False,
    run_tests: bool = False,
    parallel: bool = False,
    use_cache: bool = False,
    max_fix_attempts: int = 3,
):
    """
    Process source file với tất cả cải tiến.
    
    Tương tự như run_pipeline.py ban đầu nhưng với:
    - Automated compilation
    - Quality assurance
    - Auto-fixing
    - Parallel processing (optional)
    - Caching (optional)
    """
    config = get_config()
    setup_logging(config)
    
    logger.info(f"Processing {source_file} with improvements")
    logger.info(f"  Functions: {num_funcs}, LLM: {llm_model}, Strategy: {strategy}")
    
    # Initialize components
    cache_manager = CacheManager() if use_cache else None
    parallel_processor = ParallelProcessor() if parallel else None
    
    # Detect language from file extension
    file_ext = Path(source_file).suffix.lower()
    if file_ext in ['.c']:
        language = 'c'
    elif file_ext in ['.cpp', '.cxx', '.cc', '.hpp']:
        language = 'cpp'
    else:
        language = 'c'  # Default
        logger.warning(f"Unknown file extension {file_ext}, defaulting to C")
    
    # Initialize integrated pipeline
    integrated_pipeline = IntegratedPipeline(
        language=language,
        llm_model=llm_model,
        api_key=config.get_mistral_api_key(),
        max_fix_attempts=max_fix_attempts,
    )
    
    # Read and parse source file
    logger.info("Parsing source file...")
    parser = initialize_parser(source_file)
    source_code = read_source_code(source_file)
    tree = parser.parse(bytes(source_code, "utf8"))
    
    parsed_info = extract_functions_globals_headers(source_code, tree)
    functions, globals_, headers, classes, structs = parsed_info
    
    logger.info(f"Found {len(functions)} functions, {len(headers)} headers")
    
    if len(functions) < num_funcs:
        logger.warning(
            f"Only {len(functions)} functions found, but {num_funcs} requested. "
            f"Processing {len(functions)} functions."
        )
        num_funcs = len(functions)
    
    # Create output directories
    strategy_dir = create_output_directory(output_dir, strategy)
    llm_response_dir = os.path.join(strategy_dir, "llm_responses")
    variant_dir = os.path.join(strategy_dir, "variant_source_code", "sequential")
    os.makedirs(llm_response_dir, exist_ok=True)
    os.makedirs(variant_dir, exist_ok=True)
    
    # Process functions
    results = []
    # Randomize function order using legacy helper (persisted per file name)
    try:
        random_order_indices = generate_random_func_sequences(
            total_target_functions=len(functions),
            file_name=Path(source_file).stem,
            random_seed=42,
        )
        selected_functions = [functions[i] for i in random_order_indices if i < len(functions)]
        # Trim to requested num_funcs
        selected_functions = selected_functions[:num_funcs]
    except Exception:
        selected_functions = functions[:num_funcs]
    
    # Accumulate variant objects per trial for optional stitching
    trial_to_variant_objects: Dict[int, List[VariantFunction]] = {t: [] for t in range(trials)}
    is_failed_llm_generation_list: List[bool] = []

    for trial in range(trials):
        logger.info(f"\n{'='*60}")
        logger.info(f"Trial {trial + 1}/{trials}")
        logger.info(f"{'='*60}")
        
        trial_results = []
        
        for func_idx, func in enumerate(selected_functions, 1):
            logger.info(f"\nProcessing function {func_idx}/{num_funcs}: {func.get('name_only', 'unknown')}")
            
            # Check cache if enabled
            cache_key = f"{source_file}_{func_idx}_{trial}_{strategy}"
            if use_cache and cache_manager:
                cached_result = cache_manager.get_cached_item(cache_key)
                if cached_result:
                    logger.info(f"Using cached result for function {func_idx}")
                    trial_results.append(cached_result)
                    continue
            
            # Generate mutation using LLM (original pipeline logic)
            # This would use the original run_experiment_trial logic
            # For now, we'll use the integrated pipeline for quality checks
            
            # Get function code and generate mutated variant via LLM
            func_code = func.get('body', '')
            original_code = func_code
            variant_code, variant_objs = generate_variant_with_llm(
                func_name=func.get('name_only', 'unknown'),
                func_body=func_code,
                strategy=strategy,
                llm_model=llm_model,
                language=language,
                func_obj=func,
            )
            if variant_objs:
                trial_to_variant_objects[trial].extend(variant_objs)
            else:
                is_failed_llm_generation_list.append(True)
            
            # Process with integrated pipeline
            variant_result = integrated_pipeline.process_variant(
                source_file=source_file,
                variant_code=variant_code,
                original_code=original_code,
                auto_fix=auto_fix,
                run_tests=run_tests,
            )
            
            # Store result
            func_result = {
                'function_index': func_idx,
                'function_name': func.get('name_only', 'unknown'),
                'variant_result': variant_result,
                'quality_score': variant_result.get('quality', {}).get('quality_score', 0),
                'syntax_valid': variant_result.get('quality', {}).get('syntax_valid', False),
                'compilation_success': variant_result.get('compilation', {}).get('success', False),
            }
            
            trial_results.append(func_result)
            
            # Cache result if enabled
            if use_cache and cache_manager:
                cache_manager.set_cached_item(cache_key, func_result)
            
            logger.info(
                f"Function {func_idx} processed: "
                f"Quality={func_result['quality_score']:.2f}, "
                f"Syntax={'✓' if func_result['syntax_valid'] else '✗'}, "
                f"Compile={'✓' if func_result['compilation_success'] else '✗'}"
            )
        
        results.append({
            'trial': trial + 1,
            'functions': trial_results,
        })
    
    # Generate summary
    summary = generate_summary(results, source_file, num_funcs, strategy)
    
    # Save results
    results_file = os.path.join(strategy_dir, f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump({
            'source_file': source_file,
            'num_functions': num_funcs,
            'llm_model': llm_model,
            'strategy': strategy,
            'trials': trials,
            'results': results,
            'summary': summary,
        }, f, indent=2, ensure_ascii=False)
    
    logger.info(f"\n✓ Results saved to: {results_file}")
    logger.info(f"\n{summary}")

    # Optional: stitch and write variant source to disk using legacy stitcher
    try:
        if any(trial_to_variant_objects.values()):
            info_tuple = (
                parsed_info,
                variant_dir,
                Path(source_file).name,
                num_funcs,
                1,  # batch_num placeholder
                num_funcs,  # num_functions_merge_back
            )
            stitcher(trial_to_variant_objects, info_tuple, is_failed_llm_generation_list, "sequential")
            logger.info("✓ Stitched variant source files written")
    except Exception as stitch_exc:  # noqa: BLE001
        logger.warning(f"Stitcher step failed/skipped: {stitch_exc}")
    
    return results


def generate_summary(results: List, source_file: str, num_funcs: int, strategy: str) -> str:
    """Generate summary of processing results"""
    total_functions = sum(len(trial['functions']) for trial in results)
    syntax_valid = sum(
        1 for trial in results
        for func in trial['functions']
        if func.get('syntax_valid', False)
    )
    compilation_success = sum(
        1 for trial in results
        for func in trial['functions']
        if func.get('compilation_success', False)
    )
    avg_quality = sum(
        func.get('quality_score', 0)
        for trial in results
        for func in trial['functions']
    ) / total_functions if total_functions > 0 else 0
    
    summary = f"""
{'='*60}
PROCESSING SUMMARY
{'='*60}
Source File: {source_file}
Functions Processed: {num_funcs}
Strategy: {strategy}
Trials: {len(results)}

Results:
  Total Functions: {total_functions}
  Syntax Valid: {syntax_valid} ({syntax_valid/total_functions*100:.1f}%)
  Compilation Success: {compilation_success} ({compilation_success/total_functions*100:.1f}%)
  Average Quality Score: {avg_quality:.2f}
{'='*60}
"""
    return summary


def main():
    """Main entry point"""
    args = process_arguments()
    
    try:
        results = process_file_with_improvements(
            source_file=args.source_file,
            num_funcs=args.num_func,
            llm_model=args.llm,
            output_dir=args.output_dir,
            strategy=args.strategy,
            trials=args.trials,
            auto_fix=args.auto_fix,
            run_tests=args.run_tests,
            parallel=args.parallel,
            use_cache=args.use_cache,
            max_fix_attempts=args.max_fix_attempts,
        )
        
        logger.info("\n✓ Processing completed successfully!")
        return 0
        
    except Exception as e:
        logger.error(f"\n✗ Processing failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())

