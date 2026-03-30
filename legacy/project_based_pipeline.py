"""
Project-Based Mutation Pipeline for LLMalMorph
==============================================
Complete pipeline for mutating and compiling entire malware projects.

Features:
- Multi-file project detection
- Complete project parsing
- LLM-powered mutation of selected functions
- Project-wide variant generation
- Full compilation with all dependencies
- PE executable generation

Usage:
    python project_based_pipeline.py [--config project_config.json] [--project PROJECT_NAME]
"""

import os
import sys
import json
import logging
import argparse
import shutil
import random
import time
import subprocess
from pathlib import Path
from datetime import datetime
from collections import Counter
import traceback


def _load_dotenv_file(env_path: str) -> None:
    """Lightweight .env loader (no external dependency)."""
    if not os.path.exists(env_path):
        return

    try:
        with open(env_path, 'r', encoding='utf-8') as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue

                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")

                if key and value and not os.environ.get(key):
                    os.environ[key] = value
    except Exception as e:
        print(f"WARNING: Failed to load .env file: {e}")

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import project-based modules
try:
    from project_detector import ProjectDetector, MalwareProject
    from project_parser import ProjectParser, ProjectParseResult
    from project_compiler import ProjectCompiler, CompilationResult
    
    # Import existing pipeline modules
    from pipeline_util import (
        run_experiment_trial,
        prepend_function_def_with_batching,
        get_llm_name_from_input,
        generate_code_from_llm_response,
    )
    from utility_prompt_library import get_prompt
    from parse_llm_generated_code import parse_code_any_format
    from variant_source_generator import (
        generate_function_variant_obj_from_function_mapping,
    )
    from stitcher_util import create_output_directory, stitcher
    
    # Import enhanced automation modules
    automation_path = os.path.join(os.path.dirname(__file__), 'src', 'automation')
    if automation_path not in sys.path:
        sys.path.insert(0, automation_path)
    
    from enhanced_error_categorizer import EnhancedErrorCategorizer
    from compilation_validator import CompilationValidator
    from project_context_collector import ProjectContextCollector
    from header_generator import HeaderGenerator
    from mutation_strategy_improver import MutationStrategyImprover
    
    ENHANCED_TOOLS_AVAILABLE = True
    
except ImportError as e:
    print(f"❌ Failed to import modules: {e}")
    print("   Make sure you're running from the project root directory")
    EnhancedErrorCategorizer = None
    CompilationValidator = None
    ProjectContextCollector = None
    HeaderGenerator = None
    MutationStrategyImprover = None
    ENHANCED_TOOLS_AVAILABLE = False
    traceback.print_exc()

# Import ClangAnalyzer (optional but highly recommended)
CLANG_ANALYZER_AVAILABLE = False
try:
    from clang_analyzer import ClangAnalyzer, AnalysisResult as ClangAnalysisResult
    CLANG_ANALYZER_AVAILABLE = True
except ImportError as e:
    ClangAnalyzer = None
    ClangAnalysisResult = None
    logger = logging.getLogger(__name__)
    # Silently skip - ClangAnalyzer is optional

# Import sandbox analyzer (optional – Stage 6)
try:
    from sandbox_analyzer import SandboxAnalyzer, SandboxReport, ComparisonResult
    SANDBOX_AVAILABLE = True
except ImportError:
    SandboxAnalyzer = None
    SandboxReport = None
    ComparisonResult = None
    SANDBOX_AVAILABLE = False


class ProjectBasedMutationPipeline:
    """Complete pipeline for project-based mutation"""
    
    def __init__(self, config_path='project_config.json'):
        """Initialize pipeline with config"""
        self.load_config(config_path)
        
        # Create unique run folder with timestamp
        self.run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.run_folder = os.path.join(
            self.config['environment']['output_dir'],
            f'run_{self.run_id}'
        )
        os.makedirs(self.run_folder, exist_ok=True)
        
        self.setup_logging()
        
        # Initialize components
        self.detector = None
        self.parser = None
        self.compiler = None
        
        # Shared HybridLLMProvider (singleton for entire pipeline run)
        self._hybrid_provider = None
        
        # Results
        self.detected_projects = []
        self.parse_results = {}
        self.mutation_results = {}
        self.compilation_results = {}
        self.sandbox_results = {}
    
    def _get_cloud_api_key(self):
        """Get the appropriate cloud API key based on cloud_provider_type."""
        env_config = self.config.get('environment', {})
        comp_config = self.config.get('compilation', {})
        cloud_type = comp_config.get('cloud_provider_type', 'auto')
        cloud_model = self.config.get('mutation', {}).get('llm_model', 'codestral-2508')
        
        # Auto-detect from model name
        if cloud_type == 'auto':
            cloud_type = 'deepseek' if cloud_model.startswith('deepseek-') else 'mistral'
        
        if cloud_type == 'deepseek':
            return os.environ.get('DEEPSEEK_API_KEY') or env_config.get('deepseek_api_key', '')
        else:
            return os.environ.get('MISTRAL_API_KEY') or env_config.get('api_key', '')
    
    def _get_hybrid_provider(self):
        """Get or create shared HybridLLMProvider (singleton per pipeline run)"""
        if self._hybrid_provider is not None:
            return self._hybrid_provider
        
        from src.llm_api import HybridLLMProvider
        mutation_config = self.config.get('mutation', {})
        comp_config = self.config.get('compilation', {})
        api_key = self._get_cloud_api_key()
        local_model = mutation_config.get('hybrid_local_model', 'qwen2.5-coder:7b-instruct-q4_K_M')
        cloud_model = mutation_config.get('llm_model', 'deepseek-chat')
        cloud_file_limit = mutation_config.get('hybrid_cloud_file_size_limit', 15000)
        cloud_provider_type = comp_config.get('cloud_provider_type', 'auto')
        mode = mutation_config.get('hybrid_mode', 'local_only')
        
        self._hybrid_provider = HybridLLMProvider(
            local_model=local_model,
            cloud_model=cloud_model,
            api_key=api_key,
            cloud_file_size_limit=cloud_file_limit,
            mode=mode,
            cloud_provider_type=cloud_provider_type,
        )
        self.logger.info(f"✅ Shared HybridLLMProvider created (mode={mode})")
        return self._hybrid_provider
        
    def load_config(self, config_path):
        """Load configuration from JSON file"""
        # Load local .env first so keys are available to all stages
        repo_root = os.path.dirname(os.path.abspath(__file__))
        _load_dotenv_file(os.path.join(repo_root, '.env'))

        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}")
        
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
        # Validate API key - try env var, then config
        api_key_env = self.config['environment']['api_key_env']
        api_key = os.environ.get(api_key_env) or self.config.get('environment', {}).get('api_key', '')
        if api_key:
            # Set it in environment so all submodules (compiler, etc.) can access it
            os.environ[api_key_env] = api_key
        else:
            print(f"WARNING: {api_key_env} not set in environment or config!")
            print(f"   Please set it: set {api_key_env}=your-api-key")
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_config = self.config['logging']
        log_level = getattr(logging, log_config['level'])
        
        handlers = []
        
        # Console handler
        if log_config['console']:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(
                logging.Formatter('%(message)s')
            )
            handlers.append(console_handler)
        
        # File handler
        if log_config['file']:
            file_handler = logging.FileHandler(
                os.path.join(
                    self.run_folder,
                    log_config['file']
                ),
                encoding='utf-8'
            )
            file_handler.setFormatter(
                logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            )
            handlers.append(file_handler)
        
        logging.basicConfig(
            level=log_level,
            handlers=handlers,
            force=True
        )
        self.logger = logging.getLogger(__name__)
    
    def stage1_detect_projects(self):
        """Stage 1: Detect malware projects"""
        self.logger.info("\n" + "="*70)
        self.logger.info("STAGE 1: PROJECT DETECTION")
        self.logger.info("="*70)
        
        base_dir = self.config['project_detection']['base_directory']
        min_files = self.config['project_detection'].get('min_files_for_project', 2)
        
        self.detector = ProjectDetector(base_dir, min_files=min_files)
        self.detected_projects = self.detector.detect_projects()
        
        if not self.detected_projects:
            self.logger.error("❌ No projects detected!")
            return False
        
        self.detector.list_projects()
        
        # Export detected projects
        output_file = os.path.join(
            self.run_folder,
            'detected_projects.json'
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'total_projects': len(self.detected_projects),
                'projects': [
                    {
                        'name': p.name,
                        'root_dir': p.root_dir,
                        'language': p.get_language(),
                        'source_files': p.source_files,
                        'header_files': p.header_files,
                    }
                    for p in self.detected_projects
                ]
            }, f, indent=2)
        
        self.logger.info(f"\n✅ Exported to: {output_file}")
        return True
    
    def stage2_parse_projects(self, project_names=None):
        """Stage 2: Parse selected projects"""
        self.logger.info("\n" + "="*70)
        self.logger.info("STAGE 2: PROJECT PARSING")
        self.logger.info("="*70)
        
        # Filter projects
        projects_to_parse = self.detected_projects
        
        if project_names:
            projects_to_parse = [
                p for p in self.detected_projects
                if p.name in project_names
            ]
        
        # Apply filters from config
        filters = self.config['project_detection']['filters']
        
        if filters.get('language'):
            lang = filters['language']
            projects_to_parse = [
                p for p in projects_to_parse
                if p.get_language() == lang
            ]
        
        if filters.get('min_files'):
            min_files = filters['min_files']
            projects_to_parse = [
                p for p in projects_to_parse
                if len(p.source_files) >= min_files
            ]
        
        if filters.get('max_files'):
            max_files = filters['max_files']
            projects_to_parse = [
                p for p in projects_to_parse
                if len(p.source_files) <= max_files
            ]
        
        self.logger.info(f"\n📋 Projects to parse: {len(projects_to_parse)}")
        
        # Parse each project
        self.parser = ProjectParser()
        
        for i, project in enumerate(projects_to_parse, 1):
            self.logger.info(f"\n[{i}/{len(projects_to_parse)}] Parsing: {project.name}")
            
            try:
                parse_result = self.parser.parse_project(project)
                self.parse_results[project.name] = {
                    'project': project,
                    'parse_result': parse_result,
                }
                
                # Export parse result
                output_file = os.path.join(
                    self.run_folder,
                    f'parsed_{project.name}.json'
                )
                self.parser.export_parse_result(parse_result, output_file)
                
            except Exception as e:
                self.logger.error(f"❌ Failed to parse {project.name}: {e}")
                traceback.print_exc()
        
        return len(self.parse_results) > 0
    
    def stage3_mutate_functions(self, project_names=None):
        """Stage 3: Mutate selected functions with LLM"""
        self.logger.info("\n" + "="*70)
        self.logger.info("STAGE 3: FUNCTION MUTATION")
        self.logger.info("="*70)
        
        mutation_config = self.config['mutation']
        supported_compile_languages = {'c', 'cpp', 'python'}
        
        # Legacy feature: seed tracking
        initial_seed = mutation_config.get('initial_seed', 42)
        self._current_seed = initial_seed
        random.seed(initial_seed)
        
        # Legacy feature: multi-trial
        experiment_trial_no = mutation_config.get('trials', 1)
        
        # Legacy feature: skip-over
        skip_over = mutation_config.get('skip_over', 0)
        
        # Legacy feature: batch size
        func_batch_size = mutation_config.get('func_batch_size', 1)
        
        # Legacy feature: retry attempts
        retry_attempts = mutation_config.get('retry_generation_attempts', 5)
        
        # Legacy feature: source code response format
        source_code_response_format = mutation_config.get('source_code_response_format', 'backticks')
        
        # Legacy feature: strategy chaining order
        strat_all_order = mutation_config.get('strat_all_order', ['strat_1', 'strat_5', 'strat_6'])
        
        # Filter projects
        projects_to_mutate = self.parse_results
        if project_names:
            projects_to_mutate = {
                k: v for k, v in self.parse_results.items()
                if k in project_names
            }

        supported_mutation_languages = {'c', 'cpp', 'python'}
        skipped_unsupported = 0
        
        for project_name, project_data in projects_to_mutate.items():
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Mutating project: {project_name}")
            self.logger.info(f"{'='*60}")
            self.logger.info(f"   Trials: {experiment_trial_no} | Strategy: {mutation_config['strategy']}")
            self.logger.info(f"   Seed: {initial_seed} | Skip: {skip_over} | Batch: {func_batch_size}")
            
            project = project_data['project']
            parse_result = project_data['parse_result']
            project_language = project.get_language()

            if project_language not in supported_mutation_languages:
                skipped_unsupported += 1
                self.logger.warning(
                    f"⚠️  Skipping mutation for {project_name}: unsupported language '{project_language}'. "
                    f"Supported: {sorted(supported_mutation_languages)}"
                )
                continue
            
            # Collect project context if enhanced tools available
            project_context = None
            mutation_constraints = None
            clang_analysis = None
            
            if ENHANCED_TOOLS_AVAILABLE:
                self.logger.info(f"\n📚 Analyzing project for safe mutations...")
                
                # Collect project context
                project_context = ProjectContextCollector.collect_project_context(
                    project, parse_result
                )
                
                # Determine mutation constraints
                mutation_constraints = MutationStrategyImprover.analyze_project_for_mutation(
                    project, project_context, parse_result
                )
            
            # ── Clang AST Analysis (if available) ──
            if CLANG_ANALYZER_AVAILABLE:
                self.logger.info(f"\n🔬 Running Clang AST analysis...")
                try:
                    analyzer = ClangAnalyzer()
                    source_files = project.source_files if hasattr(project, 'source_files') else []
                    header_files = project.header_files if hasattr(project, 'header_files') else []
                    if source_files:
                        clang_analysis = analyzer.analyze_files(
                            source_files, header_files,
                            include_paths=[os.path.dirname(f) for f in source_files]
                        )
                        self.logger.info(
                            f"   Clang: {len(clang_analysis.symbols)} symbols, "
                            f"{len(clang_analysis.call_graph)} call graph entries, "
                            f"{len(clang_analysis.get_leaf_functions())} leaf functions"
                        )
                except Exception as e:
                    self.logger.warning(f"   ⚠️  Clang analysis failed: {e}")
                    clang_analysis = None
            
            # Select functions for mutation
            num_functions = mutation_config['num_functions_per_project']
            selection_strategy = mutation_config['function_selection_strategy']
            
            selected_functions = self.parser.select_functions_for_mutation(
                parse_result,
                num_functions=num_functions,
                selection_strategy=selection_strategy
            )
            
            # Filter out unsafe mutation candidates if enabled
            if ENHANCED_TOOLS_AVAILABLE and mutation_config.get('filter_unsafe_candidates', True):
                if mutation_constraints:
                    selected_functions = MutationStrategyImprover.filter_mutation_candidates(
                        selected_functions,
                        mutation_constraints,
                        verbose=True
                    )
                    
                    # If too few functions after filtering, log warning
                    if len(selected_functions) < num_functions:
                        self.logger.warning(
                            f"⚠️  Only {len(selected_functions)}/{num_functions} functions "
                            f"safe to mutate after filtering"
                        )
            
            # ── Clang-based candidate ranking ──
            if clang_analysis and selected_functions:
                try:
                    func_names = [f.get('name_only', '') for f in selected_functions]
                    ranked = ClangAnalyzer().rank_mutation_candidates(clang_analysis, func_names)
                    
                    self.logger.info(f"\n🎯 Clang Mutation Safety Ranking:")
                    for name, score, reason in ranked:
                        indicator = "🟢" if score >= 0.7 else ("🟡" if score >= 0.4 else "🔴")
                        self.logger.info(f"   {indicator} {name}: {score:.2f} ({reason})")
                    
                    # Re-order selected_functions by safety score (safest first)
                    name_to_score = {name: score for name, score, _ in ranked}
                    selected_functions.sort(
                        key=lambda f: name_to_score.get(f.get('name_only', ''), 0.5),
                        reverse=True
                    )
                except Exception as e:
                    self.logger.warning(f"   ⚠️  Clang ranking failed: {e}")
            
            # Legacy feature: skip-over
            if skip_over > 0 and skip_over < len(selected_functions):
                self.logger.info(f"   ⏭️  Skipping first {skip_over} functions")
                selected_functions = selected_functions[skip_over:]
            
            if not selected_functions:
                # No mutations requested (e.g., num_functions_per_project = 0)
                self.logger.warning(f"⚠️  No functions selected for {project_name}")
                # Still record a mutation result so later stages (variant generation/compilation)
                # can proceed using the original code.
                self.mutation_results[project_name] = {
                    'project': project,
                    'parse_result': parse_result,
                    'selected_functions': [],
                    'mutated_functions': [],
                    'project_context': project_context,
                    'mutation_constraints': mutation_constraints,
                    'clang_analysis': clang_analysis,
                    'trial_to_mutated_functions': {},
                    'best_trial': 0,
                    'seeds_per_func_per_trial': [],
                    'is_failed_llm_generation_list': [],
                    'llm_response_time_per_func': [],
                    'experiment_trial_no': experiment_trial_no,
                    'initial_seed': initial_seed,
                }

                mutation_output_file = os.path.join(
                    self.run_folder,
                    f'mutated_{project_name}.json'
                )
                self._export_mutation_results(project_name, mutation_output_file)
                self.logger.info(f"   ✅ No mutations applied; using original code. Exported to: {mutation_output_file}")
                continue
            
            # Legacy feature: tracking structures (per-trial)
            trial_to_mutated_functions = {}  # trial_no -> list of mutated function results
            seeds_per_func_per_trial = []
            is_failed_llm_generation_list = []
            llm_response_time_per_func = []
            
            for trial_no in range(experiment_trial_no):
                trial_to_mutated_functions[trial_no] = []
                seeds_per_func_per_trial.append([])
                is_failed_llm_generation_list.append([])
                llm_response_time_per_func.append([])
            
            # Legacy feature: batch processing
            if func_batch_size > 1 or func_batch_size == -1:
                effective_batch_size = len(selected_functions) if func_batch_size == -1 else func_batch_size
                function_batches = []
                for i in range(0, len(selected_functions), effective_batch_size):
                    function_batches.append(selected_functions[i:i + effective_batch_size])
                self.logger.info(f"   📦 Batched into {len(function_batches)} batch(es) of up to {effective_batch_size} functions")
            else:
                # Default: one function per batch
                function_batches = [[func] for func in selected_functions]
            
            # Process each batch
            func_index = 0
            for batch_num, func_batch in enumerate(function_batches, 1):
                batch_func_names = [f['name_only'] for f in func_batch]
                self.logger.info(f"\n📦 Batch {batch_num}/{len(function_batches)}: {', '.join(batch_func_names)}")
                
                # Multi-trial loop (from legacy)
                for trial_no in range(experiment_trial_no):
                    if experiment_trial_no > 1:
                        self.logger.info(f"\n   🔄 Trial {trial_no + 1}/{experiment_trial_no}")
                    
                    # Reset seed for each trial's start
                    self._current_seed = initial_seed
                    random.seed(initial_seed)
                    
                    for func in func_batch:
                        func_index_display = func_index + func_batch.index(func) + 1
                        self.logger.info(
                            f"\n   [{func_index_display}/{len(selected_functions)}] "
                            f"Mutating: {func['name_only']}"
                            + (f" (trial {trial_no + 1})" if experiment_trial_no > 1 else "")
                        )
                        
                        try:
                            mutated = self._mutate_single_function(
                                func, mutation_config, mutation_constraints,
                                trial_no=trial_no,
                                seed=self._current_seed,
                                retry_attempts=retry_attempts,
                                source_code_response_format=source_code_response_format,
                                strat_all_order=strat_all_order,
                                batch_num=batch_num,
                                clang_analysis=clang_analysis,
                            )
                            
                            if mutated:
                                # Ensure signature preservation if enabled
                                if ENHANCED_TOOLS_AVAILABLE and mutation_config.get('preserve_signatures', True):
                                    for variant_func in mutated.get('variant_functions', []):
                                        MutationStrategyImprover.preserve_function_signature(
                                            func, variant_func
                                        )
                                
                                # Restore local variable names (C/C++ only; prevents macro breakage)
                                orig_body = func.get('body', '')
                                if orig_body and project_language in {'c', 'cpp'}:
                                    for variant_func in mutated.get('variant_functions', []):
                                        if 'body' in variant_func:
                                            variant_func['body'] = self._restore_local_variable_names(
                                                orig_body, variant_func['body']
                                            )
                                
                                # ── Clang Post-Mutation Validation ──
                                if CLANG_ANALYZER_AVAILABLE and clang_analysis:
                                    try:
                                        _analyzer = ClangAnalyzer()
                                        for variant_func in mutated.get('variant_functions', []):
                                            vf_body = variant_func.get('body', '')
                                            vf_name = variant_func.get('name_only', func.get('name_only', 'unknown'))
                                            if vf_body:
                                                issues = _analyzer.validate_mutation(
                                                    clang_analysis, vf_name, vf_body
                                                )
                                                if issues:
                                                    self.logger.warning(
                                                        f"   🔬 Clang validation found {len(issues)} issue(s) "
                                                        f"in {vf_name}:"
                                                    )
                                                    for issue in issues[:5]:
                                                        self.logger.warning(f"      - {issue}")
                                                    
                                                    # Try auto-fix
                                                    fixed_code, remaining = _analyzer.auto_fix_mutation(
                                                        clang_analysis, vf_name, vf_body, issues
                                                    )
                                                    if fixed_code != vf_body:
                                                        variant_func['body'] = fixed_code
                                                        self.logger.info(
                                                            f"   🔧 Auto-fixed {len(issues) - len(remaining)} "
                                                            f"issue(s), {len(remaining)} remaining"
                                                        )
                                    except Exception as e:
                                        self.logger.debug(f"Clang validation failed: {e}")
                                
                                trial_to_mutated_functions[trial_no].append(mutated)
                                is_failed_llm_generation_list[trial_no].append(False)
                                self.logger.info(f"   ✓ Mutation successful")
                            else:
                                is_failed_llm_generation_list[trial_no].append(True)
                                self.logger.warning(f"   ⚠️  Mutation failed")
                            
                            # Track seeds and timing
                            seeds_per_func_per_trial[trial_no].append(self._current_seed)
                            llm_response_time_per_func[trial_no].append(
                                mutated.get('llm_response_time', 0) if mutated else 0
                            )
                            
                        except Exception as e:
                            self.logger.error(f"   ❌ Error: {e}")
                            is_failed_llm_generation_list[trial_no].append(True)
                            seeds_per_func_per_trial[trial_no].append(self._current_seed)
                            llm_response_time_per_func[trial_no].append(0)
                
                func_index += len(func_batch)
            
            # Select best trial results
            # Strategy: pick the trial with most successful mutations
            best_trial = 0
            if experiment_trial_no > 1:
                trial_success_counts = {
                    t: len(funcs) for t, funcs in trial_to_mutated_functions.items()
                }
                best_trial = max(trial_success_counts, key=trial_success_counts.get)
                self.logger.info(
                    f"\n🏆 Best trial: {best_trial + 1} "
                    f"({trial_success_counts[best_trial]} successful mutations)"
                )
                for t, count in trial_success_counts.items():
                    self.logger.info(f"   Trial {t + 1}: {count} successful mutations")
            
            mutated_functions = trial_to_mutated_functions[best_trial]
            
            # Store mutation results with enhanced context + legacy tracking data
            self.mutation_results[project_name] = {
                'project': project,
                'parse_result': parse_result,
                'selected_functions': selected_functions,
                'mutated_functions': mutated_functions,
                'project_context': project_context,
                'mutation_constraints': mutation_constraints,
                'clang_analysis': clang_analysis,
                # Legacy tracking data
                'trial_to_mutated_functions': trial_to_mutated_functions,
                'best_trial': best_trial,
                'seeds_per_func_per_trial': seeds_per_func_per_trial,
                'is_failed_llm_generation_list': is_failed_llm_generation_list,
                'llm_response_time_per_func': llm_response_time_per_func,
                'experiment_trial_no': experiment_trial_no,
                'initial_seed': initial_seed,
            }
            
            # Export mutation results to run folder
            mutation_output_file = os.path.join(
                self.run_folder,
                f'mutated_{project_name}.json'
            )
            self._export_mutation_results(project_name, mutation_output_file)
            
            self.logger.info(f"\n✅ Mutated {len(mutated_functions)}/{len(selected_functions)} functions")
            if experiment_trial_no > 1:
                self.logger.info(f"   Best trial: {best_trial + 1}/{experiment_trial_no}")
            self.logger.info(f"   Exported to: {mutation_output_file}")
        
        if self.mutation_results:
            return True

        if skipped_unsupported > 0 and len(projects_to_mutate) == skipped_unsupported:
            self.logger.info(
                "ℹ️  No mutation executed because all selected projects are non-C/C++."
            )
            return True

        return False
    
    def _clean_llm_artifacts(self, code: str) -> str:
        """
        Clean up common LLM artifacts from generated code.
        
        Args:
            code: Generated code that may have artifacts
            
        Returns:
            Cleaned code
        """
        import re
        
        # Remove markdown code block markers
        code = re.sub(r'```[\w]*\n', '', code)
        code = re.sub(r'```\s*$', '', code, flags=re.MULTILINE)
        
        # Detect and extract code from instruction patterns
        instruction_patterns = [
            'Add #include',
            'Add include',  # ← NEW: Without #
            'Remove #include', 
            'Remove include',  # ← NEW: Without #
            'Add #define',
            'Add define',  # ← NEW: Without #
            'Change line',
            'Replace with',
            'Insert at',
            'Delete line',
            'Modify to',
            'Update to',
            'Fix by adding',
            'Add the following',
            'Include the following',
        ]
        
        lines = code.split('\n')
        cleaned_lines = []
        for line in lines:
            stripped = line.strip()
            
            # Check if line starts with instruction pattern
            is_instruction = False
            extracted_code = None
            
            # Try each pattern (order matters!)
            if stripped.startswith('Add #include '):
                is_instruction = True
                extracted_code = '#include ' + stripped[len('Add #include '):]
            elif stripped.startswith('Add include '):
                is_instruction = True
                extracted_code = '#include ' + stripped[len('Add include '):]
            elif stripped.startswith('Remove #include '):
                is_instruction = True
                # Skip remove instructions
            elif stripped.startswith('Add #define '):
                is_instruction = True
                extracted_code = '#define ' + stripped[len('Add #define '):]
            elif stripped.startswith('Add define '):
                is_instruction = True
                extracted_code = '#define ' + stripped[len('Add define '):]
            elif any(stripped.startswith(p) for p in [
                'Change line', 'Replace with', 'Insert at', 
                'Delete line', 'Modify to', 'Update to',
                'Fix by adding', 'Add the following', 'Include the following'
            ]):
                is_instruction = True
                # Try to extract anything after the instruction
                for pattern in instruction_patterns:
                    if stripped.startswith(pattern):
                        extracted_code = stripped[len(pattern):].strip()
                        break
            
            if is_instruction:
                if extracted_code:
                    cleaned_lines.append(extracted_code)
                # Otherwise skip instruction line
            else:
                cleaned_lines.append(line)
        
        code = '\n'.join(cleaned_lines)
        
        # AGGRESSIVE CLEANING: Remove ALL stray backticks (anywhere in code)
        # This fixes issues like: char *`nf → char *nf
        code = code.replace('`', '')
        
        # Additional cleaning: Remove common LLM instruction remnants
        # Fix patterns like "Add include <X>" → "#include <X>"
        import re
        code = re.sub(r'^\s*Add\s+include\s+', '#include ', code, flags=re.MULTILINE)
        code = re.sub(r'^\s*Add\s+define\s+', '#define ', code, flags=re.MULTILINE)
        code = re.sub(r'^\s*Remove\s+include\s+.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'^\s*Remove\s+define\s+.*$', '', code, flags=re.MULTILINE)
        
        # Remove explanation lines that LLMs sometimes add
        code = re.sub(r'^\s*//\s*(Here|This|Note|Important|Warning):.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'^\s*/\*\s*(Here|This|Note|Important|Warning):.*?\*/', '', code, flags=re.DOTALL)
        
        # Clean up multiple blank lines
        code = re.sub(r'\n\n\n+', '\n\n', code)
        
        return code
    
    # ===================================================================
    # Dangerous SDK types/macros/functions that LLM mutations must not
    # redefine. Used by _sanitize_mutation_output to clean variant code.
    # ===================================================================
    _SDK_TYPES_NO_REDEFINE = {
        # Core Windows types
        'DWORD', 'WORD', 'BYTE', 'BOOL', 'HANDLE', 'HWND', 'HDC', 'HINSTANCE',
        'HMODULE', 'HKEY', 'HRESULT', 'LPVOID', 'LPSTR', 'LPCSTR', 'LPWSTR',
        'LPCWSTR', 'LPARAM', 'WPARAM', 'LRESULT', 'UINT', 'INT', 'LONG',
        'ULONG', 'SHORT', 'USHORT', 'CHAR', 'WCHAR', 'TCHAR', 'SIZE_T',
        'PVOID', 'PDWORD', 'PWORD', 'PBYTE', 'PBOOL', 'VOID',
        # WinCrypt
        'DATA_BLOB', 'PDATA_BLOB', 'HCRYPTPROV', 'HCRYPTHASH', 'HCRYPTKEY',
        'CERT_CONTEXT', 'PCCERT_CONTEXT',
        # COM/OLE
        'VARIANT', 'SAFEARRAY', 'BSTR', 'IUnknown', 'IDispatch',
        'IWebBrowser2', 'CLSID', 'IID', 'GUID', 'OLECHAR',
        # Networking
        'SOCKET', 'sockaddr', 'sockaddr_in', 'in_addr', 'hostent',
        'WSADATA', 'IP_ADAPTER_INFO',
        # Process/Thread
        'STARTUPINFO', 'PROCESS_INFORMATION', 'SECURITY_ATTRIBUTES',
        'OVERLAPPED', 'CRITICAL_SECTION',
        # DNS
        'DNS_RECORD', 'PDNS_RECORD',
        # VFW
        'CAPDRIVERCAPS', 'CAPSTATUS',
    }
    
    _SDK_MACROS_NO_REDEFINE = {
        # WinCrypt constants
        'PROV_RSA_FULL', 'CRYPT_VERIFYCONTEXT', 'CRYPT_NEWKEYSET',
        'CALG_SHA', 'CALG_SHA1', 'CALG_MD5', 'CALG_SHA_256',
        'HP_HASHVAL', 'HP_HASHSIZE', 'AT_KEYEXCHANGE',
        # Boolean constants
        'TRUE', 'FALSE', 'NULL',
        # Windows constants
        'INVALID_HANDLE_VALUE', 'MAX_PATH', 'INFINITE',
        'GENERIC_READ', 'GENERIC_WRITE', 'FILE_SHARE_READ',
        'OPEN_EXISTING', 'CREATE_ALWAYS',
    }
    
    _SDK_DANGEROUS_DEFINES = {
        'string', 'bool', 'true', 'false', 'wstring',
        'vector', 'map', 'list', 'set', 'pair',
    }
    
    _KNOWN_WIN32_API_FUNCS = {
        'CryptUnprotectData', 'CryptAcquireContext', 'CryptCreateHash',
        'CryptHashData', 'CryptGetHashParam', 'CryptReleaseContext',
        'CryptDestroyHash', 'CryptDestroyKey', 'CryptEncrypt', 'CryptDecrypt',
        'GetAdaptersInfo', 'DnsQuery', 'DnsQuery_A', 'DnsQuery_W',
        'DnsRecordListFree', 'CreateFile', 'CreateFileA', 'CreateFileW',
        'ReadFile', 'WriteFile', 'CloseHandle', 'GetLastError',
        'GetProcAddress', 'LoadLibrary', 'LoadLibraryA', 'LoadLibraryW',
        'FreeLibrary', 'VirtualAlloc', 'VirtualFree', 'VirtualProtect',
        'CreateProcess', 'CreateProcessA', 'CreateProcessW',
        'OpenProcess', 'TerminateProcess', 'GetCurrentProcess',
        'CreateThread', 'ExitThread', 'GetCurrentThread',
        'RegOpenKey', 'RegOpenKeyEx', 'RegOpenKeyExA', 'RegOpenKeyExW',
        'RegQueryValueEx', 'RegSetValueEx', 'RegCloseKey',
        'HeapAlloc', 'HeapFree', 'HeapCreate', 'HeapDestroy',
        'GetModuleHandle', 'GetModuleHandleA', 'GetModuleHandleW',
        'GetModuleFileName', 'GetModuleFileNameA', 'GetModuleFileNameW',
        'SendMessage', 'SendMessageA', 'SendMessageW', 'PostMessage',
        'GetDesktopWindow', 'GetWindowRect', 'GetDC', 'ReleaseDC',
        'CreateCompatibleDC', 'CreateCompatibleBitmap', 'SelectObject',
        'BitBlt', 'DeleteDC', 'DeleteObject',
        'InternetOpen', 'InternetOpenA', 'InternetOpenW',
        'InternetOpenUrl', 'InternetOpenUrlA', 'InternetOpenUrlW',
        'InternetReadFile', 'InternetCloseHandle',
        'HttpOpenRequest', 'HttpSendRequest',
        'OleInitialize', 'OleUninitialize', 'CoInitialize',
        'CoInitializeEx', 'CoUninitialize', 'CoCreateInstance',
        'SHGetFolderPath', 'SHGetFolderPathA', 'SHGetFolderPathW',
        'SHGetSpecialFolderPath', 'PathAppend', 'PathFileExists',
        'FindFirstFile', 'FindFirstFileA', 'FindFirstFileW',
        'FindNextFile', 'FindClose',
        'GetWindowsDirectory', 'GetSystemDirectory', 'GetTempPath',
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        'OutputDebugString', 'QueryPerformanceCounter',
        'capCreateCaptureWindow', 'capCreateCaptureWindowA',
        'MessageBox', 'MessageBoxA', 'MessageBoxW',
        'WSAStartup', 'WSACleanup', 'socket', 'connect', 'send', 'recv',
        'closesocket', 'bind', 'listen', 'accept', 'select',
        'gethostbyname', 'inet_addr', 'inet_ntoa', 'htons', 'ntohs',
    }
    
    def _sanitize_mutation_output(self, code: str) -> str:
        """
        Sanitize LLM-generated mutation output to remove dangerous patterns
        that would break compilation.
        
        This runs AFTER mutation, before writing variant to disk.
        Removes:
        - #include directives added by LLM (originals are preserved from source)
        - typedef/struct redefinitions of SDK types
        - #define of dangerous macros (string, bool, etc.)
        - extern "C" blocks redeclaring SDK functions
        - Forward declarations of known Win32 API functions
        - Redefinitions of SDK macro constants as variables
        """
        import re
        
        lines = code.split('\n')
        cleaned_lines = []
        skip_extern_block = False
        extern_brace_depth = 0
        changes_made = 0
        
        for line in lines:
            stripped = line.strip()
            
            # 1. Remove #include directives added by LLM inside function bodies
            #    (they don't belong inside functions and will cause errors)
            if stripped.startswith('#include'):
                self.logger.debug(f"   🧹 Removed LLM-injected #include: {stripped}")
                changes_made += 1
                continue
            
            # 2. Remove #define of dangerous macros
            define_match = re.match(r'#define\s+(\w+)', stripped)
            if define_match:
                defined_name = define_match.group(1)
                if defined_name in self._SDK_DANGEROUS_DEFINES or defined_name in self._SDK_MACROS_NO_REDEFINE:
                    self.logger.debug(f"   🧹 Removed dangerous #define: {stripped}")
                    changes_made += 1
                    continue
            
            # 3. Remove typedef redefinitions of SDK types
            typedef_match = re.match(r'typedef\s+.*\b(\w+)\s*;', stripped)
            if typedef_match:
                typedef_name = typedef_match.group(1)
                if typedef_name in self._SDK_TYPES_NO_REDEFINE:
                    self.logger.debug(f"   🧹 Removed SDK typedef redefinition: {stripped}")
                    changes_made += 1
                    continue
            
            # 4. Remove struct redefinitions of SDK types
            struct_match = re.match(r'(?:typedef\s+)?struct\s+(\w+)', stripped)
            if struct_match:
                struct_name = struct_match.group(1)
                if struct_name in self._SDK_TYPES_NO_REDEFINE:
                    self.logger.debug(f"   🧹 Removed SDK struct redefinition: {stripped}")
                    changes_made += 1
                    continue
            
            # 5. Remove extern "C" { ... } blocks that redeclare SDK functions
            if 'extern' in stripped and '"C"' in stripped:
                if '{' in stripped:
                    skip_extern_block = True
                    extern_brace_depth = 1
                    changes_made += 1
                    continue
                elif any(func_name in stripped for func_name in self._KNOWN_WIN32_API_FUNCS):
                    changes_made += 1
                    continue
            
            if skip_extern_block:
                extern_brace_depth += stripped.count('{') - stripped.count('}')
                if extern_brace_depth <= 0:
                    skip_extern_block = False
                changes_made += 1
                continue
            
            # 6. Remove forward declarations of known Win32 API functions
            #    Pattern: return_type WINAPI FuncName(...);
            for func_name in self._KNOWN_WIN32_API_FUNCS:
                if func_name in stripped and stripped.rstrip().endswith(';') and '(' in stripped:
                    # Check it's a declaration (not a call) — declarations have return type before func name
                    decl_pattern = re.compile(
                        r'^\s*(?:extern\s+)?(?:__declspec\s*\([^)]*\)\s+)?'
                        r'(?:BOOL|DWORD|HANDLE|HRESULT|int|void|LONG|SOCKET|LPVOID|PVOID|UINT|HCRYPTPROV|DNS_STATUS)\s+'
                        r'(?:WINAPI\s+|CALLBACK\s+|__stdcall\s+|__cdecl\s+)?'
                        + re.escape(func_name) + r'\s*\('
                    )
                    if decl_pattern.match(stripped):
                        self.logger.debug(f"   🧹 Removed SDK function declaration: {stripped}")
                        changes_made += 1
                        line = None
                        break
            
            if line is None:
                continue
            
            # 7. Remove variable declarations using SDK macro names
            #    e.g., "const DWORD PROV_RSA_FULL = 1;" or "DWORD CRYPT_VERIFYCONTEXT;"
            for macro_name in self._SDK_MACROS_NO_REDEFINE:
                macro_var_pattern = re.compile(
                    r'^\s*(?:const\s+)?(?:DWORD|int|unsigned|UINT|ULONG|LONG)\s+' 
                    + re.escape(macro_name) + r'\s*[=;]'
                )
                if macro_var_pattern.match(stripped):
                    self.logger.debug(f"   🧹 Removed SDK macro used as variable: {stripped}")
                    changes_made += 1
                    line = None
                    break
            
            if line is None:
                continue
            
            # 8. Remove variable declarations using SDK type names as variable names
            #    e.g., "DWORD DATA_BLOB;" or "int HANDLE = 0;"
            for type_name in self._SDK_TYPES_NO_REDEFINE:
                type_var_pattern = re.compile(
                    r'^\s*(?:const\s+)?(?:DWORD|int|unsigned|UINT|ULONG|LONG|void|char|BYTE|WORD)\s+' 
                    + re.escape(type_name) + r'\s*[=;]'
                )
                if type_var_pattern.match(stripped):
                    self.logger.debug(f"   🧹 Removed SDK type used as variable: {stripped}")
                    changes_made += 1
                    line = None
                    break
            
            if line is None:
                continue
            
            cleaned_lines.append(line)
        
        if changes_made > 0:
            self.logger.info(f"   🧹 Sanitized mutation output: {changes_made} dangerous pattern(s) removed")
        
        return '\n'.join(cleaned_lines)
    
    def _ensure_includes_preserved(self, original_code: str, modified_code: str) -> str:
        """
        Ensure all #include directives from the original code are preserved
        in the modified code. If any are missing, re-inject them at the top.
        
        This is a safety net: mutations should only replace function bodies,
        so includes should never be lost. But LLM _clean_llm_artifacts or
        string replacement edge cases can sometimes corrupt them.
        """
        import re
        
        # Extract all #include lines from original
        orig_includes = set()
        for line in original_code.split('\n'):
            stripped = line.strip()
            if stripped.startswith('#include'):
                # Normalize whitespace for comparison
                normalized = re.sub(r'\s+', ' ', stripped)
                orig_includes.add(normalized)
        
        # Extract all #include lines from modified
        mod_includes = set()
        for line in modified_code.split('\n'):
            stripped = line.strip()
            if stripped.startswith('#include'):
                normalized = re.sub(r'\s+', ' ', stripped)
                mod_includes.add(normalized)
        
        # Find missing includes
        missing = orig_includes - mod_includes
        
        if missing:
            self.logger.warning(f"   ⚠️  {len(missing)} original #include(s) were lost during mutation, restoring:")
            for inc in sorted(missing):
                self.logger.warning(f"      + {inc}")
            
            # Re-inject missing includes at the very top of the file
            # (before any existing #include or code)
            inject_block = '\n'.join(sorted(missing)) + '\n'
            
            # Find the position of the first #include in modified code
            first_include_pos = -1
            for i, line in enumerate(modified_code.split('\n')):
                if line.strip().startswith('#include') or line.strip().startswith('#pragma'):
                    first_include_pos = sum(len(l) + 1 for l in modified_code.split('\n')[:i])
                    break
            
            if first_include_pos >= 0:
                modified_code = modified_code[:first_include_pos] + inject_block + modified_code[first_include_pos:]
            else:
                modified_code = inject_block + modified_code
        
        return modified_code
    
    def _restore_local_variable_names(self, original_body: str, mutated_body: str) -> str:
        """
        Detect and revert local variable renames in mutated function body.
        
        The LLM often renames local variables as part of obfuscation (e.g., 'written' -> 'w'),
        but this breaks macros that reference those variables by name (e.g., APPEND_STRING
        macro expects 'written' to exist). Since local variable names don't appear in compiled
        binaries, reverting these renames preserves obfuscation effectiveness while preventing
        macro-related compilation errors.
        
        Algorithm:
        1. Extract local variable declarations from both original and mutated bodies
        2. Match declarations by type and position to build a rename map
        3. Replace renamed variables back to original names using word-boundary regex
        
        Args:
            original_body: Original function body (full definition including signature)
            mutated_body: Mutated function body (full definition including signature)
            
        Returns:
            Mutated body with local variable names restored to originals
        """
        import re
        
        def _extract_local_var_decls(body: str):
            """
            Extract local variable declarations from a function body.
            Returns list of (type_str, var_name, initializer) tuples in order.
            """
            # Get just the body content (inside braces)
            brace_pos = body.find('{')
            if brace_pos < 0:
                return []
            
            inner = body[brace_pos + 1:]
            # Remove the closing brace
            last_brace = inner.rfind('}')
            if last_brace >= 0:
                inner = inner[:last_brace]
            
            decls = []
            # Match common C/C++ local variable declaration patterns
            # Pattern: [optional qualifiers] type [*&] name [= init] [, [*&] name2 [= init2]] ;
            # We process line by line for simplicity
            for line in inner.split('\n'):
                stripped = line.strip()
                if not stripped or stripped.startswith('//') or stripped.startswith('/*'):
                    continue
                if stripped.startswith('#') or stripped.startswith('return') or stripped.startswith('if'):
                    continue
                if stripped.startswith('for') or stripped.startswith('while') or stripped.startswith('switch'):
                    continue
                if stripped.startswith('case ') or stripped.startswith('default:') or stripped.startswith('break'):
                    continue
                
                # Match declaration patterns like:
                # int written = -1, written_total = 0;
                # const char *key = NULL, *string = NULL;
                # JSON_Value *temp_value = NULL;
                # size_t i = 0, count = 0;
                decl_pattern = re.match(
                    r'^((?:const\s+|static\s+|unsigned\s+|volatile\s+)*'  # qualifiers
                    r'(?:struct\s+|enum\s+)?'  # struct/enum prefix
                    r'[A-Za-z_]\w*(?:\s*(?:::)\s*[A-Za-z_]\w*)*'  # type name (with :: for C++)
                    r')\s+'  # space after type
                    r'(\*{0,3}\s*[A-Za-z_]\w*'  # first var (with optional pointer stars)
                    r'(?:\s*=\s*[^,;]+)?'  # optional initializer
                    r'(?:\s*,\s*\*{0,3}\s*[A-Za-z_]\w*(?:\s*=\s*[^,;]+)?)*'  # more vars
                    r')\s*;',  # semicolon
                    stripped
                )
                
                if decl_pattern:
                    type_str = decl_pattern.group(1).strip()
                    vars_part = decl_pattern.group(2)
                    
                    # Split multiple declarations: "*key = NULL, *string = NULL"
                    # Split by comma, but be careful with complex initializers
                    var_items = []
                    depth = 0
                    current = ''
                    for ch in vars_part:
                        if ch in '({[':
                            depth += 1
                            current += ch
                        elif ch in ')}]':
                            depth -= 1
                            current += ch
                        elif ch == ',' and depth == 0:
                            var_items.append(current.strip())
                            current = ''
                        else:
                            current += ch
                    if current.strip():
                        var_items.append(current.strip())
                    
                    for item in var_items:
                        # Extract name from "*name = init" or "name = init" or "name"
                        name_match = re.match(r'\*{0,3}\s*([A-Za-z_]\w*)', item)
                        if name_match:
                            var_name = name_match.group(1)
                            # Skip if var_name is itself a type keyword
                            if var_name not in {'int', 'char', 'void', 'float', 'double', 
                                                'long', 'short', 'unsigned', 'signed',
                                                'const', 'static', 'volatile', 'struct', 'enum',
                                                'NULL', 'true', 'false', 'TRUE', 'FALSE'}:
                                decls.append((type_str, var_name))
            
            return decls
        
        orig_decls = _extract_local_var_decls(original_body)
        mut_decls = _extract_local_var_decls(mutated_body)
        
        if not orig_decls or not mut_decls:
            return mutated_body
        
        # Build rename map by matching declarations by type and position
        # Strategy: for each type group, match variables in order
        from collections import defaultdict
        
        orig_by_type = defaultdict(list)
        for type_str, name in orig_decls:
            # Normalize type for matching (remove extra spaces)
            norm_type = re.sub(r'\s+', ' ', type_str).strip()
            orig_by_type[norm_type].append(name)
        
        mut_by_type = defaultdict(list)
        for type_str, name in mut_decls:
            norm_type = re.sub(r'\s+', ' ', type_str).strip()
            mut_by_type[norm_type].append(name)
        
        rename_map = {}  # mutated_name -> original_name
        for type_str in orig_by_type:
            orig_names = orig_by_type[type_str]
            mut_names = mut_by_type.get(type_str, [])
            
            # Only map if same count (same variables, just renamed)
            if len(orig_names) == len(mut_names):
                for orig_name, mut_name in zip(orig_names, mut_names):
                    if orig_name != mut_name:
                        rename_map[mut_name] = orig_name
        
        if not rename_map:
            # Even if no local variable renames detected by type matching,
            # still try to detect member variable / undeclared identifier renames
            # by comparing line-by-line patterns between original and mutated bodies
            pass
        
        # === PHASE 2: Detect member variable / undeclared identifier renames ===
        # Compare statements between original and mutated bodies to find identifiers
        # that were renamed but aren't local variable declarations (e.g., class members)
        orig_brace = original_body.find('{')
        mut_brace = mutated_body.find('{')
        if orig_brace >= 0 and mut_brace >= 0:
            orig_stmts = [s.strip() for s in original_body[orig_brace + 1:].split('\n') if s.strip()]
            mut_stmts = [s.strip() for s in mutated_body[mut_brace + 1:].split('\n') if s.strip()]
            
            # Compare each pair of statements with same structure
            # "if (oerr) return ZR_FAILED;" vs "if (e) return ZR_FAILED;"
            member_rename_map = {}
            for orig_line, mut_line in zip(orig_stmts, mut_stmts):
                if orig_line == mut_line:
                    continue
                # Tokenize both lines into identifiers and non-identifiers
                orig_tokens = re.findall(r'[A-Za-z_]\w*|[^A-Za-z_\w]+', orig_line)
                mut_tokens = re.findall(r'[A-Za-z_]\w*|[^A-Za-z_\w]+', mut_line)
                
                if len(orig_tokens) != len(mut_tokens):
                    continue  # structural difference, not just renames
                
                for ot, mt in zip(orig_tokens, mut_tokens):
                    if ot == mt:
                        continue
                    # Both must be identifiers
                    if re.match(r'^[A-Za-z_]\w*$', ot) and re.match(r'^[A-Za-z_]\w*$', mt):
                        # Skip if already in rename_map
                        if mt in rename_map:
                            continue
                        # Skip common keywords/types
                        skip_names = {'int', 'char', 'void', 'float', 'double', 'long',
                                      'short', 'unsigned', 'signed', 'const', 'static',
                                      'if', 'else', 'for', 'while', 'do', 'switch', 'case',
                                      'break', 'continue', 'return', 'struct', 'enum',
                                      'class', 'public', 'private', 'protected', 'virtual',
                                      'NULL', 'nullptr', 'true', 'false', 'TRUE', 'FALSE',
                                      'sizeof', 'typedef', 'extern', 'inline', 'volatile'}
                        if ot in skip_names or mt in skip_names:
                            continue
                        # Check consistency: if we've seen this mutated name before, 
                        # it should map to the same original name
                        if mt in member_rename_map:
                            if member_rename_map[mt] != ot:
                                continue  # inconsistent, skip
                        else:
                            member_rename_map[mt] = ot
                    else:
                        break  # non-identifier difference = structural change
            
            # Filter member_rename_map: only keep renames that appear consistent
            # (at least the identifier must appear in the mutated body)
            for mt, ot in member_rename_map.items():
                if mt not in rename_map:
                    rename_map[mt] = ot
        
        if not rename_map:
            return mutated_body
        
        self.logger.info(f"   🔄 Reverting {len(rename_map)} variable rename(s): "
                         f"{', '.join(f'{m}->{o}' for m, o in rename_map.items())}")
        
        # Get body content (after opening brace)
        brace_pos = mutated_body.find('{')
        if brace_pos < 0:
            return mutated_body
        
        signature = mutated_body[:brace_pos]
        body_content = mutated_body[brace_pos:]
        
        # Two-phase replacement to avoid conflicts
        # Phase 1: Replace with unique placeholders
        placeholders = {}
        for i, (mut_name, orig_name) in enumerate(rename_map.items()):
            placeholder = f"__LOCALVAR_PH_{i}_{hash(mut_name) & 0xFFFFFF}__"
            placeholders[placeholder] = orig_name
            body_content = re.sub(r'\b' + re.escape(mut_name) + r'\b', placeholder, body_content)
        
        # Phase 2: Replace placeholders with original names
        for placeholder, orig_name in placeholders.items():
            body_content = body_content.replace(placeholder, orig_name)
        
        return signature + body_content
    
    def _mutate_single_function(self, func, mutation_config, mutation_constraints=None,
                                trial_no=0, seed=42, retry_attempts=5,
                                source_code_response_format='backticks',
                                strat_all_order=None, batch_num=1,
                                clang_analysis=None):
        """Mutate a single function with LLM (supports Hybrid LLM, multi-trial, strategy chaining)
        
        Legacy features ported from src/run_pipeline.py:
        - trial_no: Current trial number for multi-trial experiments
        - seed: Random seed for reproducibility (mutated on retry failure)
        - retry_attempts: Number of retries when LLM generation fails
        - source_code_response_format: 'backticks' or 'json' for parsing LLM response
        - strat_all_order: List of strategies for chaining when strategy == 'strat_all'
        - batch_num: Current batch number for batch processing
        """
        try:
            def _normalize_language(src_file: str) -> str:
                ext = os.path.splitext(src_file)[1].lower().lstrip('.')
                if ext == 'py':
                    return 'python'
                if ext in {'cpp', 'cxx', 'cc'}:
                    return 'cpp'
                if ext == 'c':
                    return 'c'
                return ext or 'c'

            def _parse_python_response(response_text: str):
                import re as _re

                code_blocks = _re.findall(r'```(.*?)```', response_text, _re.DOTALL)
                cleaned_blocks = []
                for block in code_blocks:
                    block = _re.sub(r'^[a-zA-Z+#]*\n', '\n', block, count=1)
                    cleaned_blocks.append(block)

                code = ''.join(cleaned_blocks).strip() if cleaned_blocks else response_text.strip()
                if not code:
                    return None, 0, None

                parser = ProjectParser()
                parsed = parser._parse_python_file('temp_mutation.py', code)
                if not parsed.get('success'):
                    return None, 0, None

                segmented = (
                    parsed.get('headers', []),
                    parsed.get('globals', []),
                    parsed.get('functions', []),
                    parsed.get('classes', []),
                    parsed.get('structs', []),
                )
                return segmented, len(code.splitlines()), None

            def _is_stub_body(body: str) -> bool:
                """Heuristic to reject placeholder/stub bodies returned by LLM."""
                if not body:
                    return True
                b = body.strip()
                # Common placeholder markers
                if "Implementation of" in b or "TODO" in b or "stub" in b.lower():
                    return True
                # Remove braces-only bodies
                if b in ("{}", "{ }", "{\n}"):
                    return True
                import re
                # Drop comments and whitespace-only lines
                lines = []
                comment_block = False
                for line in b.split('\n'):
                    stripped = line.strip()
                    if stripped.startswith("/*"):
                        comment_block = True
                    if not comment_block and stripped and not stripped.startswith("//"):
                        lines.append(stripped)
                    if stripped.endswith("*/"):
                        comment_block = False
                if not lines:
                    return True
                # Very short bodies (no statements) are likely stubs
                body_no_space = re.sub(r"\s+", "", "".join(lines))
                has_stmt = any(tok in body_no_space for tok in [";", "return", "if(", "for(", "while(", "switch("])
                if not has_stmt:
                    return True
                # Too few non-comment lines → likely stub
                if len(lines) < 2 and len(body_no_space) < 30:
                    return True
                return False

            def _contains_inline_asm(body: str) -> bool:
                if not body:
                    return False
                b = body.lower()
                asm_markers = ["__asm", " asm", "pushad", "popad", "naked", " __attribute__", " __declspec(naked)"]
                return any(tok in b for tok in asm_markers)

            # Prepare function definition
            func_def = func.get('body', '')
            func_name = func.get('name_only', 'unknown')
            func_size = len(func_def)

            # Get mutation strategy and prompt from utility_prompt_library
            from utility_prompt_library import strategy_prompt_dict
            strategy = mutation_config['strategy']
            strategy_prompt = strategy_prompt_dict.get(strategy, strategy_prompt_dict['strat_1'])
            language = _normalize_language(func.get('source_file', ''))
            num_functions = 1
            
            # Compose mutation prompt
            if language == 'python':
                mutation_prompt = (
                    f"Below is a Python function named ***{func_name}***. "
                    f"Modify it following these instructions:\n"
                    f"{strategy_prompt}\n"
                    f"\nPYTHON RULES:\n"
                    f"1. Keep function name and parameter list unchanged.\n"
                    f"2. Preserve behavior and return semantics.\n"
                    f"3. Keep valid Python indentation and syntax.\n"
                    f"4. Output ONLY the complete modified function. No explanations.\n"
                )
            else:
                mutation_prompt = (
                    f"Below is a {language} function named ***{func_name}***. "
                    f"Modify it following these instructions:\n"
                    f"{strategy_prompt}\n"
                    f"\nCOMPILATION RULES:\n"
                    f"1. Do NOT add, remove, or change any #include directives. Do NOT redefine Windows SDK types or macros.\n"
                    f"2. No inline assembly. Target MSVC x86, portable C/C++.\n"
                    f"3. Keep ALL original function calls and macro invocations with the same arguments and types.\n"
                    f"4. Keep the original return type, parameter types, and return statements.\n"
                    f"5. Do NOT rename, remove, or change the type of ANY variable declaration. Keep every variable name and type identical.\n"
                    f"6. Do NOT merge variables, shadow existing names, or use macro names (like APPEND_STRING) as variable names.\n"
                    f"7. Do NOT change narrow string functions (strcpy, strlen, strcmp, strcat, sprintf) to wide-string equivalents (wcscpy, wcslen, wcscmp, wcscat, wsprintf) or vice versa.\n"
                    f"8. Output ONLY the complete modified function. No explanations, no comments before/after.\n"
                )
            
            # Add mutation safety constraints if available
            safety_prompt = ""
            if ENHANCED_TOOLS_AVAILABLE and mutation_constraints:
                safety_prompt = MutationStrategyImprover.add_mutation_safety_prompt(mutation_constraints)
            
            # Add Clang dependency context if available
            clang_context_prompt = ""
            if CLANG_ANALYZER_AVAILABLE and clang_analysis and func_name:
                try:
                    analyzer = ClangAnalyzer()
                    clang_context_prompt = analyzer.generate_mutation_prompt_context(
                        clang_analysis, func_name
                    )
                    if clang_context_prompt:
                        clang_context_prompt = "\n" + clang_context_prompt + "\n"
                except Exception as e:
                    self.logger.debug(f"Clang context generation failed: {e}")
            
            code_supply_prompt = "Here is the code : \n"
            user_prompt = mutation_prompt + "\n" + safety_prompt + clang_context_prompt + "\n" + code_supply_prompt + func_def

            # Retrieve hybrid mode and llm_model from mutation_config
            use_hybrid = mutation_config.get('use_hybrid_llm', False)
            llm_model = mutation_config.get('llm_model', 'codestral-2508')
            if language == 'python':
                system_prompt = "You are an intelligent coding assistant specialized in Python refactoring and code mutation. Return only valid Python code."
            else:
                system_prompt = "You are an intelligent coding assistant who is expert in writing, editing, refactoring and debugging code. You listen to exact instructions and specialize in systems programming and use of C, C++ and C# languages with Windows platforms"

            # =====================================================
            # Legacy feature: STRATEGY CHAINING (strat_all)
            # When strategy is 'strat_all', chain multiple strategies
            # sequentially — output of one becomes input to next
            # =====================================================
            if strategy == 'strat_all' and strat_all_order and language != 'python':
                llm_response = None
                current_user_prompt = user_prompt
                initial_seed_val = seed
                
                strat_index = 0
                while True:
                    # Retry loop for each strategy in the chain
                    try_again = 0
                    code_blocks = []
                    
                    while try_again < retry_attempts:
                        self.logger.info(f"      📝 Strategy chain step {strat_index + 1}, attempt {try_again + 1}")
                        
                        llm_response = self._call_llm(
                            system_prompt, current_user_prompt, func_size,
                            use_hybrid, llm_model, language, trial_no, seed, batch_num
                        )
                        
                        # Check if response has code blocks
                        import re as _re
                        code_blocks = _re.findall(r'```(.*?)```', llm_response, _re.DOTALL)
                        
                        if len(code_blocks) == 0:
                            self.logger.warning(f"      ⚠️  No code blocks found, retrying...")
                            try_again += 1
                            seed = random.randint(0, 10000)
                            self._current_seed = seed
                        else:
                            break
                    
                    # If all retries failed for this step, use original code as fallback
                    if try_again >= retry_attempts and len(code_blocks) == 0:
                        llm_response = f"```{language}\n{func_def}```"
                        self.logger.warning(f"      ⚠️  All retries failed, using original code")
                    
                    # Check if we've exhausted all strategies in the chain
                    if strat_index >= len(strat_all_order):
                        self.logger.info(f"      ✓ All {len(strat_all_order)} strategies in chain completed")
                        break
                    
                    # Parse the LLM response to feed as input to next strategy
                    try:
                        # Get the parsed code to compose next prompt
                        # Reuse headers/globals from original parse context
                        headers = []
                        globals_list = []
                        
                        llm_generated_code, llm_function_names, llm_num_functions = \
                            generate_code_from_llm_response(llm_response, language, headers, globals_list)
                        
                        next_strategy = strat_all_order[strat_index]
                        next_strategy_prompt = strategy_prompt_dict.get(next_strategy, strategy_prompt_dict['strat_1'])
                        
                        self.logger.info(f"      🔗 Chaining to: {next_strategy}")
                        
                        # Build next prompt using output of current step
                        next_mutation_prompt = (
                            f"Below this prompt you are provided headers, global variables, class and struct definitions "
                            f"and {llm_num_functions} global function definition(s) from a {language} source code file. "
                            f"As a coding assistant, GENERATE VARIANTS of these functions namely: ***{', '.join(llm_function_names)}*** following these instructions: \n"
                            f"{next_strategy_prompt}\n"
                            f"ABSOLUTE CONSTRAINTS: Target MSVC x64 and C11; DO NOT use inline assembly or compiler-specific extensions. "
                            f"Prohibit any use of __asm/asm blocks, x86 opcodes (pushad/popad), inline jmp blocks, naked functions, or non-portable attributes. "
                            f"Emit portable C only, compatible with cl.exe /std:c11 on 64-bit Windows.\n"
                            f"REMEMBER, the generated code MUST MAINTAIN the same FUNCTIONALITY as the original code. Make sure to ALWAYS generate the code, I don't need the code explanation.\n"
                        )
                        
                        current_user_prompt = next_mutation_prompt + "\n" + code_supply_prompt + llm_generated_code
                        strat_index += 1
                        
                    except Exception as chain_error:
                        self.logger.warning(f"      ⚠️  Strategy chain parsing failed: {chain_error}, stopping chain")
                        break
                
                # Reset seed after chaining
                seed = initial_seed_val
                self._current_seed = seed
            
            # =====================================================  
            # Standard single-strategy mutation with retry loop
            # (from legacy pipeline's single strategy path)
            # =====================================================
            else:
                llm_response = None
                try_again = 0
                initial_seed_val = seed
                
                while try_again < retry_attempts:
                    llm_response = self._call_llm(
                        system_prompt, user_prompt, func_size,
                        use_hybrid, llm_model, language, trial_no, seed, batch_num
                    )
                    
                    # Try parsing immediately to check validity
                    if language == 'python':
                        segmented_code_check, _, _ = _parse_python_response(llm_response)
                    else:
                        segmented_code_check, _, _ = parse_code_any_format(
                            llm_response,
                            language=language,
                            source_code_response_format=source_code_response_format,
                        )
                    
                    if segmented_code_check is None:
                        self.logger.warning(f"      ⚠️  LLM response parse failed, retry {try_again + 1}/{retry_attempts}")
                        try_again += 1
                        seed = random.randint(0, 10000)  # New seed for retry (from legacy)
                        self._current_seed = seed
                    else:
                        break
                
                # Reset seed after retries
                seed = initial_seed_val
                self._current_seed = seed

            if llm_response is None:
                return None
            
            # Measure total time
            llm_response_time = getattr(self, '_last_llm_response_time', 0)
            
            # Parse response FIRST (needs backtick markers intact)
            if language == 'python':
                segmented_code, lines_of_code_generated, mapping = _parse_python_response(llm_response)
            else:
                segmented_code, lines_of_code_generated, mapping = parse_code_any_format(
                    llm_response,
                    language=language,
                    source_code_response_format=source_code_response_format,
                )
            
            # If parsing failed, try cleaning artifacts and parsing as raw code
            if segmented_code is None and language != 'python':
                cleaned_response = self._clean_llm_artifacts(llm_response)
                if cleaned_response and cleaned_response.strip():
                    # Try parsing the cleaned code directly (without backtick extraction)
                    temp_file = f'temp.{language}'
                    try:
                        with open(temp_file, 'w', encoding='utf-8') as f:
                            f.write(cleaned_response)
                        from src.run_pipeline import initialize_parser, read_source_code
                        from src.tree_sitter_parser import extract_functions_globals_headers
                        temp_parser = initialize_parser(temp_file)
                        temp_code = read_source_code(temp_file)
                        temp_tree = temp_parser.parse(bytes(temp_code, 'utf8'))
                        segmented_code = extract_functions_globals_headers(temp_code, temp_tree)
                        self.logger.info(f"   ✓ Parsed via fallback (raw code without backticks)")
                    except Exception as e:
                        self.logger.warning(f"   ⚠️  Fallback parsing also failed: {e}")
                        segmented_code = None
            
            if segmented_code is None:
                return None
            
            # Generate variant function object
            variant_headers, variant_globals, variant_functions, _, _ = segmented_code
            
            # Clean LLM artifacts from variant function bodies AFTER parsing
            for vf in variant_functions:
                if 'body' in vf and language != 'python':
                    vf['body'] = self._clean_llm_artifacts(vf['body'])

            # Filter out stub/placeholder variants and any with inline asm/non-portable extensions
            if language == 'python':
                variant_functions = [
                    vf for vf in variant_functions
                    if vf.get('body', '').strip()
                ]
            else:
                variant_functions = [
                    vf for vf in variant_functions
                    if not _is_stub_body(vf.get('body', '')) and not _contains_inline_asm(vf.get('body', ''))
                ]
            
            if not variant_functions:
                return None
            
            # === POST-MUTATION VALIDATION ===
            # Sanitize variant functions to remove dangerous patterns that break compilation
            for vf in variant_functions:
                if 'body' in vf and language != 'python':
                    vf['body'] = self._sanitize_mutation_output(vf['body'])
            
            # === COMPREHENSIVE MUTATION VALIDATION GATES ===
            orig_body = func.get('body', '')
            orig_body_lines = len(orig_body.strip().splitlines()) if orig_body else 0
            orig_body_len = len(orig_body)
            valid_variants = []
            
            for vf in variant_functions:
                body = vf.get('body', '')
                vf_name = vf.get('name_only', vf.get('variant_name', '?'))
                body_len = len(body)
                body_lines = len(body.strip().splitlines()) if body else 0
                rejected = False
                
                # Gate 1: SIZE RATIO — variant must not be drastically smaller
                if orig_body_len > 100:  # Only check for non-trivial functions
                    size_ratio = body_len / orig_body_len if orig_body_len > 0 else 0
                    if size_ratio < 0.40:
                        self.logger.warning(
                            f"   ⚠️  GATE 1 REJECT '{vf_name}': size ratio {size_ratio:.1%} "
                            f"({body_len} vs {orig_body_len} chars) — variant too short, using original"
                        )
                        rejected = True
                    elif size_ratio > 5.0:
                        self.logger.warning(
                            f"   ⚠️  GATE 1 REJECT '{vf_name}': size ratio {size_ratio:.1%} "
                            f"({body_len} vs {orig_body_len} chars) — variant too bloated, using original"
                        )
                        rejected = True
                
                # Gate 2: LINE COUNT — variant must not lose too many lines
                if not rejected and orig_body_lines > 5:
                    line_ratio = body_lines / orig_body_lines if orig_body_lines > 0 else 0
                    if line_ratio < 0.40:
                        self.logger.warning(
                            f"   ⚠️  GATE 2 REJECT '{vf_name}': line ratio {line_ratio:.1%} "
                            f"({body_lines} vs {orig_body_lines} lines) — too many lines deleted, using original"
                        )
                        rejected = True
                
                # Gate 3: STUB DETECTION — check for placeholder patterns
                if not rejected:
                    body_lower = body.lower()
                    stub_markers = [
                        '// implementation goes here', '// todo', '// stub',
                        '/* implementation */', '// placeholder', '// not implemented',
                        '// add implementation', '// fill in',
                    ]
                    # Count non-trivial lines (not comment, not blank, not just braces)
                    import re as _re_val
                    non_trivial = [l.strip() for l in body.splitlines() 
                                   if l.strip() and not l.strip().startswith('//')
                                   and l.strip() not in ('{', '}', 'return 0;', 'return NULL;', 'return;')]
                    if any(marker in body_lower for marker in stub_markers):
                        self.logger.warning(
                            f"   ⚠️  GATE 3 REJECT '{vf_name}': contains stub/placeholder markers, using original"
                        )
                        rejected = True
                    elif orig_body_lines > 10 and len(non_trivial) < 3:
                        self.logger.warning(
                            f"   ⚠️  GATE 3 REJECT '{vf_name}': only {len(non_trivial)} non-trivial lines "
                            f"(original had {orig_body_lines} lines) — likely stub, using original"
                        )
                        rejected = True
                
                # Gate 4: BRACE BALANCE — check balanced braces
                if not rejected and language != 'python':
                    brace_depth = 0
                    for ch in body:
                        if ch == '{':
                            brace_depth += 1
                        elif ch == '}':
                            brace_depth -= 1
                        if brace_depth < 0:
                            break
                    if brace_depth != 0:
                        self.logger.warning(
                            f"   ⚠️  GATE 4 REJECT '{vf_name}': unbalanced braces "
                            f"(depth={brace_depth}), using original"
                        )
                        rejected = True
                
                # Gate 5: VARIABLE DECLARATIONS — check that original variables are preserved
                # The LLM often removes or renames variable declarations, breaking macros
                if not rejected and orig_body and language != 'python':
                    import re as _re_var
                    def _extract_var_names(fn_body):
                        """Extract set of local variable names from a function body."""
                        brace = fn_body.find('{')
                        if brace < 0:
                            return set()
                        inner = fn_body[brace+1:]
                        last = inner.rfind('}')
                        if last >= 0:
                            inner = inner[:last]
                        names = set()
                        for line in inner.split('\n'):
                            s = line.strip()
                            if not s or s.startswith('//') or s.startswith('/*') or s.startswith('#'):
                                continue
                            if s.startswith('if') or s.startswith('for') or s.startswith('while'):
                                continue
                            if s.startswith('return') or s.startswith('switch') or s.startswith('case'):
                                continue
                            m = _re_var.match(
                                r'^(?:const\s+|static\s+|unsigned\s+|volatile\s+)*'
                                r'(?:struct\s+|enum\s+)?'
                                r'[A-Za-z_]\w*(?:\s*(?:::)\s*[A-Za-z_]\w*)*'
                                r'\s+'
                                r'(\*{0,3}\s*[A-Za-z_]\w*'
                                r'(?:\s*=\s*[^,;]+)?'
                                r'(?:\s*,\s*\*{0,3}\s*[A-Za-z_]\w*(?:\s*=\s*[^,;]+)?)*)'
                                r'\s*;', s)
                            if m:
                                vars_part = m.group(1)
                                for item in vars_part.split(','):
                                    nm = _re_var.match(r'\*{0,3}\s*([A-Za-z_]\w*)', item.strip())
                                    if nm:
                                        vn = nm.group(1)
                                        skip = {'int','char','void','float','double','long','short',
                                                'unsigned','signed','const','static','volatile',
                                                'struct','enum','NULL','true','false','TRUE','FALSE'}
                                        if vn not in skip:
                                            names.add(vn)
                        return names
                    
                    orig_vars = _extract_var_names(orig_body)
                    mut_vars = _extract_var_names(body)
                    missing_vars = orig_vars - mut_vars
                    # Reject if 2+ original variables were removed/renamed.
                    # The strat_1 prompt explicitly prohibits removing ANY variable,
                    # so even 2 missing vars indicates the LLM violated the rules.
                    if orig_vars and len(missing_vars) >= 2:
                        self.logger.warning(
                            f"   ⚠️  GATE 5 REJECT '{vf_name}': {len(missing_vars)}/{len(orig_vars)} "
                            f"original variables removed ({', '.join(sorted(missing_vars)[:5])}...), using original"
                        )
                        rejected = True
                
                # Apply result
                if rejected:
                    if orig_body:
                        vf['body'] = orig_body
                        valid_variants.append(vf)
                        self.logger.info(f"   ↩️  Falling back to original body for '{vf_name}'")
                else:
                    valid_variants.append(vf)
                    self.logger.info(
                        f"   ✅ VALIDATED '{vf_name}': {body_lines} lines, "
                        f"{body_len} chars (ratio: {body_len/orig_body_len:.1%})" if orig_body_len > 0 else
                        f"   ✅ VALIDATED '{vf_name}': {body_lines} lines, {body_len} chars"
                    )
            
            variant_functions = valid_variants
            
            return {
                'original_function': func,
                'variant_functions': variant_functions,
                'llm_response': llm_response,
                'llm_response_time': llm_response_time,
                'mapping': mapping,
                'trial_no': trial_no,
                'seed': seed,
            }
            
        except Exception as e:
            self.logger.error(f"Error mutating function: {e}")
            return None
    
    def _call_llm(self, system_prompt, user_prompt, func_size,
                  use_hybrid, llm_model, language, trial_no, seed, batch_num):
        """Call LLM (Hybrid or Cloud) and return response string.
        
        Extracted as helper to support retry loops and strategy chaining.
        Tracks response time in self._last_llm_response_time.
        """
        start_time = time.time()
        
        def _run_cloud_model_direct(model_name: str):
            from src.llm_api import ollama_chat_api
            api_key = self._get_cloud_api_key()
            return ollama_chat_api(
                model_name=model_name,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                seed=seed,
                api_key=api_key,
            )

        is_cloud_model = (
            llm_model.startswith("deepseek-")
            or llm_model.startswith("codestral-")
            or llm_model.startswith("mistral-")
            or llm_model == "codestral-latest"
        )

        if use_hybrid:
            try:
                hybrid_provider = self._get_hybrid_provider()
                llm_response = hybrid_provider.generate(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    file_size=func_size,
                    error_count=0,
                    is_header=False
                )
                self.logger.info(f"   🔀 Hybrid LLM used: {hybrid_provider.stats}")
            except Exception as e:
                self.logger.warning(f"   ⚠️  Hybrid LLM failed, falling back to cloud: {e}")
                if is_cloud_model:
                    llm_response = _run_cloud_model_direct(llm_model)
                else:
                    llm = get_llm_name_from_input(llm_model)
                    llm_response, _ = run_experiment_trial(
                        llm, system_prompt, user_prompt, trial_no, "", language, "", 1, seed, batch_num, set()
                    )
        else:
            if is_cloud_model:
                llm_response = _run_cloud_model_direct(llm_model)
            else:
                llm = get_llm_name_from_input(llm_model)
                llm_response, _ = run_experiment_trial(
                    llm, system_prompt, user_prompt, trial_no, "", language, "", 1, seed, batch_num, set()
                )
        
        self._last_llm_response_time = time.time() - start_time
        return llm_response
    
    def _export_mutation_results(self, project_name, output_file):
        """Export mutation results to JSON file (with legacy tracking data)"""
        try:
            mutation_data = self.mutation_results.get(project_name)
            if not mutation_data:
                return
            
            # Prepare exportable data (exclude non-serializable objects)
            export_data = {
                'project_name': project_name,
                'timestamp': datetime.now().isoformat(),
                'selected_functions': [
                    {
                        'name': func.get('name_only', 'unknown'),
                        'source_file': func.get('source_file', 'unknown'),
                        'start_line': func.get('start_line', -1),
                        'end_line': func.get('end_line', -1),
                        'body_preview': func.get('body', '')[:200] + '...' if len(func.get('body', '')) > 200 else func.get('body', ''),
                    }
                    for func in mutation_data['selected_functions']
                ],
                'mutated_functions': [
                    {
                        'original_function_name': m['original_function'].get('name_only', 'unknown'),
                        'variant_count': len(m['variant_functions']),
                        'llm_response_time': m.get('llm_response_time', 0),
                        'trial_no': m.get('trial_no', 0),
                        'seed': m.get('seed', 42),
                        'variant_names': [
                            vf.get('name_only', 'unknown') 
                            for vf in m['variant_functions']
                        ],
                    }
                    for m in mutation_data['mutated_functions']
                ],
                'statistics': {
                    'total_selected': len(mutation_data['selected_functions']),
                    'total_mutated': len(mutation_data['mutated_functions']),
                    'success_rate': len(mutation_data['mutated_functions']) / len(mutation_data['selected_functions']) * 100 if mutation_data['selected_functions'] else 0,
                },
                # Legacy tracking data
                'experiment_config': {
                    'trials': mutation_data.get('experiment_trial_no', 1),
                    'best_trial': mutation_data.get('best_trial', 0),
                    'initial_seed': mutation_data.get('initial_seed', 42),
                },
                'seeds_per_func_per_trial': mutation_data.get('seeds_per_func_per_trial', []),
                'is_failed_llm_generation_list': mutation_data.get('is_failed_llm_generation_list', []),
                'llm_response_time_per_func': mutation_data.get('llm_response_time_per_func', []),
            }
            
            # Add per-trial summary if multi-trial
            if mutation_data.get('experiment_trial_no', 1) > 1:
                trial_summaries = {}
                for trial_no, funcs in mutation_data.get('trial_to_mutated_functions', {}).items():
                    trial_summaries[str(trial_no)] = {
                        'successful_mutations': len(funcs),
                        'function_names': [
                            m['original_function'].get('name_only', 'unknown') for m in funcs
                        ],
                    }
                export_data['trial_summaries'] = trial_summaries
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to export mutation results: {e}")
    
    def stage4_generate_variants(self, project_names=None):
        """Stage 4: Generate complete project variants"""
        self.logger.info("\n" + "="*70)
        self.logger.info("STAGE 4: VARIANT GENERATION")
        self.logger.info("="*70)
        
        # Filter projects
        projects_to_generate = self.mutation_results
        if project_names:
            projects_to_generate = {
                k: v for k, v in self.mutation_results.items()
                if k in project_names
            }
        
        for project_name, mutation_data in projects_to_generate.items():
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Generating variants: {project_name}")
            self.logger.info(f"{'='*60}")
            
            project = mutation_data['project']
            parse_result = mutation_data['parse_result']
            mutated_functions = mutation_data['mutated_functions']
            
            # Create output directory in run folder to separate each mutation run
            variant_dir = os.path.join(
                self.run_folder,
                'variants',
                project_name
            )
            os.makedirs(variant_dir, exist_ok=True)
            
            # Generate variant for each source file
            # IMPORTANT: Filter out _original.* files to avoid duplicate definitions
            # If both xxx_original.cpp and xxx_changed.cpp exist, only use _changed
            filtered_source_files = []
            for source_file in project.source_files:
                basename = os.path.basename(source_file)
                # Skip _original files if corresponding _changed file exists
                if '_original.' in basename:
                    # Check if _changed version exists
                    changed_version = source_file.replace('_original.', '_changed.')
                    if changed_version in project.source_files:
                        self.logger.debug(f"Skipping {basename} (using _changed version instead)")
                        continue
                filtered_source_files.append(source_file)
            
            # Get Clang analysis result from Stage 3 for post-stitch validation
            clang_analysis = mutation_data.get('clang_analysis', None)
            
            for source_file in filtered_source_files:
                self._generate_file_variant(
                    source_file,
                    mutated_functions,
                    variant_dir,
                    parse_result,
                    project_root=project.root_dir,
                    clang_analysis=clang_analysis,
                )
            
            # Copy header files — preserve original content, apply compat fixes
            for header_file in project.header_files:
                dest = os.path.join(
                    variant_dir,
                    os.path.relpath(header_file, project.root_dir)
                )
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                
                try:
                    with open(header_file, 'r', encoding='utf-8', errors='ignore') as f:
                        header_content = f.read()
                    
                    # Do NOT clean artifacts on original headers (would corrupt backticks etc.)
                    # Only apply compiler compatibility fixes (SAL annotations, SEH, etc.)
                    # Skip when using MSVC — these are GCC-specific workarounds
                    compiler_type = self.config.get('compilation', {}).get('compiler', 'auto')
                    if compiler_type not in ('msvc',):  # Only apply for GCC
                        try:
                            from src.automation.compiler_compatibility import CompilerCompatibility
                            if self.config.get('compilation', {}).get('apply_compiler_compatibility', False):
                                header_content, num_changes = CompilerCompatibility.make_gcc_compatible(header_content)
                                if num_changes > 0:
                                    self.logger.debug(f"   Applied {num_changes} GCC compat fix(es) to header: {os.path.basename(dest)}")
                        except Exception as e:
                            self.logger.warning(f"   Could not apply header compat: {e}")
                    
                    with open(dest, 'w', encoding='utf-8') as f:
                        f.write(header_content)
                    
                    self.logger.debug(f"   ✓ Copied header: {os.path.basename(dest)}")
                except Exception as e:
                    # Fallback to direct copy if processing fails
                    self.logger.warning(f"   ⚠️  Failed to process {os.path.basename(header_file)}, copying as-is: {e}")
                    shutil.copy2(header_file, dest)
            
            # Copy resource/support files (tlb, rc, def, lib, etc.)
            # These are needed for compilation but are not source or header files
            RESOURCE_EXTS = {'.tlb', '.tlh', '.tli', '.rc', '.def', '.lib', '.a',
                             '.res', '.ico', '.manifest', '.idl', '.odl'}
            for other_file in project.other_files:
                ext = os.path.splitext(other_file)[1].lower()
                if ext in RESOURCE_EXTS:
                    dest = os.path.join(
                        variant_dir,
                        os.path.relpath(other_file, project.root_dir)
                    )
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    try:
                        shutil.copy2(other_file, dest)
                        self.logger.debug(f"   ✓ Copied resource: {os.path.basename(dest)}")
                    except Exception as e:
                        self.logger.warning(f"   ⚠️  Failed to copy resource {os.path.basename(other_file)}: {e}")
            
            self.logger.info(f"\n✅ Variant generated: {variant_dir}")
            
            # Store variant info
            if project_name not in self.mutation_results:
                self.mutation_results[project_name] = {}
            self.mutation_results[project_name]['variant_dir'] = variant_dir
    
    def _generate_file_variant(self, source_file, mutated_functions, variant_dir, parse_result, project_root=None, clang_analysis=None):
        """Generate variant for a single source file"""
        try:
            # Read original source
            with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                original_code = f.read()
            
            # Find mutations for this file
            file_mutations = [
                m for m in mutated_functions
                if m['original_function'].get('source_file') == source_file
            ]
            
            if not file_mutations:
                # No mutations for this file — copy as-is (do NOT clean artifacts!)
                # Original source files should be preserved verbatim.
                # _clean_llm_artifacts strips backticks which corrupts valid code
                # like sqlite3.c's case '`': → case '': (empty char constant)
                code_to_write = original_code
                
                # Only apply compiler compatibility fixes (MSVC -> GCC) — skip if using MSVC
                compiler_type = self.config.get('compilation', {}).get('compiler', 'auto')
                if compiler_type not in ('msvc',):
                    try:
                        from src.automation.compiler_compatibility import CompilerCompatibility
                        if self.config.get('compilation', {}).get('apply_compiler_compatibility', False):
                            code_to_write, num_changes = CompilerCompatibility.make_gcc_compatible(code_to_write)
                            if num_changes > 0:
                                self.logger.debug(f"   Applied {num_changes} GCC compatibility fix(es)")
                    except Exception as e:
                        self.logger.warning(f"   Could not apply compiler compatibility: {e}")
                
                relative_path = os.path.relpath(source_file, project_root) if project_root else os.path.basename(source_file)
                dest = os.path.join(variant_dir, relative_path)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, 'w', encoding='utf-8') as f:
                    f.write(code_to_write)
                return
            
            # Apply mutations
            modified_code = original_code
            
            for mutation in file_mutations:
                orig_func = mutation['original_function']
                variant_funcs = mutation['variant_functions']
                
                if not variant_funcs:
                    continue
                
                # Use first variant function
                variant_func = variant_funcs[0]
                
                orig_body = orig_func.get('body', '')
                variant_body = variant_func.get('body', '')
                
                # CRITICAL: Clean variant_body one more time before writing!
                # This catches any artifacts that survived parsing
                variant_body = self._clean_llm_artifacts(variant_body)
                
                # Replace function
                if orig_body in modified_code:
                    modified_code = modified_code.replace(orig_body, variant_body, 1)
            
            # CRITICAL: Clean the ENTIRE modified file one more time!
            # This catches artifacts in top-level code (outside functions)
            modified_code = self._clean_llm_artifacts(modified_code)
            
            # === POST-MUTATION VALIDATION: Ensure original #includes are preserved ===
            # The LLM should only modify function bodies, but sometimes artifacts
            # in the replacement corrupt the includes section. Re-verify and restore.
            modified_code = self._ensure_includes_preserved(original_code, modified_code)
            
            # === CLANG POST-STITCH VALIDATION ===
            # Validate that the stitched mutations don't break cross-file dependencies
            if clang_analysis and CLANG_ANALYZER_AVAILABLE:
                try:
                    analyzer = ClangAnalyzer()
                    for mutation in file_mutations:
                        orig_func = mutation['original_function']
                        variant_funcs = mutation.get('variant_functions', [])
                        if not variant_funcs:
                            continue
                        func_name = orig_func.get('name_only', '')
                        variant_body = variant_funcs[0].get('body', '')
                        if func_name and variant_body:
                            issues = analyzer.validate_mutation(
                                clang_analysis, func_name, variant_body
                            )
                            if issues:
                                self.logger.warning(
                                    f"   ⚠️  Clang post-stitch issues for {func_name}: "
                                    f"{'; '.join(issues[:3])}"
                                )
                                # Try auto-fix for critical issues
                                fixed_body = analyzer.auto_fix_mutation(
                                    clang_analysis, func_name, variant_body
                                )
                                if fixed_body != variant_body:
                                    modified_code = modified_code.replace(variant_body, fixed_body, 1)
                                    self.logger.info(f"   ✓ Auto-fixed stitch issues for {func_name}")
                except Exception as e:
                    self.logger.debug(f"   Clang post-stitch validation error: {e}")
            
            # Apply compiler compatibility fixes (MSVC -> GCC) — skip if using MSVC
            compiler_type = self.config.get('compilation', {}).get('compiler', 'auto')
            if compiler_type not in ('msvc',):
                try:
                    from src.automation.compiler_compatibility import CompilerCompatibility
                    if self.config.get('compilation', {}).get('apply_compiler_compatibility', False):
                        modified_code, num_changes = CompilerCompatibility.make_gcc_compatible(modified_code)
                        if num_changes > 0:
                            self.logger.debug(f"   Applied {num_changes} GCC compatibility fix(es)")
                except Exception as e:
                    self.logger.warning(f"   Could not apply compiler compatibility: {e}")
            
            # Write variant
            relative_path = os.path.relpath(source_file, project_root) if project_root else os.path.basename(source_file)
            dest = os.path.join(variant_dir, relative_path)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            
            with open(dest, 'w', encoding='utf-8') as f:
                f.write(modified_code)
            
            self.logger.info(f"   ✓ Generated: {os.path.basename(dest)}")
            
        except Exception as e:
            self.logger.error(f"   ❌ Failed to generate variant: {e}")

    def _compile_python_variant(self, project_name, variant_dir, output_dir, timeout_seconds=300):
        """Compile a Python project variant into a single executable via PyInstaller."""
        result = CompilationResult()
        start_time = time.time()

        try:
            def _normalize_python2_syntax(code: str) -> str:
                import re
                # print x  -> print(x)
                def _replace_print(match):
                    indent = match.group(1)
                    expr = match.group(2).strip()
                    if expr.startswith('('):
                        return match.group(0)
                    return f"{indent}print({expr})"

                code = re.sub(r'(?m)^(\s*)print\s+([^\n]+)$', _replace_print, code)
                # except E, e: -> except E as e:
                code = re.sub(
                    r'(?m)^(\s*)except\s+([^:\n,]+)\s*,\s*([A-Za-z_]\w*)\s*:',
                    r'\1except \2 as \3:',
                    code,
                )
                code = code.replace('xrange(', 'range(')
                code = code.replace('raw_input(', 'input(')
                return code

            py_files = []
            for root, _, files in os.walk(variant_dir):
                for filename in files:
                    if filename.lower().endswith('.py'):
                        py_files.append(os.path.join(root, filename))

            if not py_files:
                result.errors = f"No Python source files found in {variant_dir}"
                return result

            # Convert legacy Python 2 syntax so Python 3 based packagers can compile.
            for py_file in py_files:
                try:
                    with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                        original = f.read()
                    normalized = _normalize_python2_syntax(original)
                    if normalized != original:
                        with open(py_file, 'w', encoding='utf-8') as f:
                            f.write(normalized)
                except Exception:
                    continue

            # Entry-point heuristic: prefer common runner names, then __main__ guard, then first file.
            preferred_names = [
                f"{project_name}.py",
                "main.py",
                "__main__.py",
                "run.py",
                "compileZIB.py",
            ]

            entry_file = None
            by_name = {os.path.basename(p): p for p in py_files}
            for name in preferred_names:
                if name in by_name:
                    entry_file = by_name[name]
                    break

            if entry_file is None:
                for candidate in sorted(py_files):
                    try:
                        with open(candidate, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        if '__name__' in content and '__main__' in content:
                            entry_file = candidate
                            break
                    except Exception:
                        continue

            if entry_file is None:
                entry_file = sorted(py_files)[0]

            exe_name = f"{project_name}_mutated"
            work_dir = os.path.join(output_dir, "pyinstaller_work")
            spec_dir = os.path.join(output_dir, "pyinstaller_spec")
            os.makedirs(work_dir, exist_ok=True)
            os.makedirs(spec_dir, exist_ok=True)

            command = [
                sys.executable,
                "-m",
                "PyInstaller",
                "--noconfirm",
                "--clean",
                "--onefile",
                "--distpath",
                output_dir,
                "--workpath",
                work_dir,
                "--specpath",
                spec_dir,
                "--name",
                exe_name,
                entry_file,
            ]

            proc = subprocess.run(
                command,
                cwd=variant_dir,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )

            result.output = (proc.stdout or "") + "\n" + (proc.stderr or "")

            if proc.returncode != 0:
                result.errors = result.output
                return result

            executable_path = os.path.join(output_dir, f"{exe_name}.exe")
            if not os.path.exists(executable_path):
                result.errors = f"PyInstaller succeeded but executable not found: {executable_path}"
                return result

            result.success = True
            result.executable_path = executable_path
            result.executable_size = os.path.getsize(executable_path)
            return result

        except subprocess.TimeoutExpired:
            result.errors = f"Python compilation timed out after {timeout_seconds} seconds"
            return result
        except Exception as e:
            result.errors = str(e)
            return result
        finally:
            result.compile_time = time.time() - start_time
    
    def stage5_compile_variants(self, project_names=None):
        """Stage 5: Compile project variants"""
        self.logger.info("\n" + "="*70)
        self.logger.info("STAGE 5: VARIANT COMPILATION")
        self.logger.info("="*70)
        
        # Filter projects
        projects_to_compile = self.mutation_results
        if project_names:
            projects_to_compile = {
                k: v for k, v in self.mutation_results.items()
                if k in project_names
            }
        
        comp_config = self.config['compilation']
        compiler_pref = comp_config.get('compiler', 'auto')
        msvc_arch = comp_config.get('msvc_arch', 'x64')
        self.compiler = ProjectCompiler(compiler=compiler_pref, msvc_arch=msvc_arch)
        
        # Set DEEPSEEK_API_KEY env var if configured (so project_compiler can find it)
        deepseek_key = self.config.get('environment', {}).get('deepseek_api_key', '')
        if deepseek_key and not os.environ.get('DEEPSEEK_API_KEY'):
            os.environ['DEEPSEEK_API_KEY'] = deepseek_key
            self.logger.info("🔑 DEEPSEEK_API_KEY set from config")
        
        mutation_config = self.config['mutation']
        supported_compile_languages = {'c', 'cpp', 'python'}
        
        for project_name, mutation_data in projects_to_compile.items():
            project = mutation_data.get('project')
            project_language = project.get_language() if project else 'unknown'
            if project_language not in supported_compile_languages:
                self.logger.info(
                    f"ℹ️  Skipping compilation for {project_name}: unsupported language '{project_language}'."
                )
                continue

            variant_dir = mutation_data.get('variant_dir')
            if not variant_dir:
                self.logger.warning(f"⚠️  No variant directory for {project_name}")
                continue

            if project_language == 'python':
                self.logger.info(f"\n{'='*60}")
                self.logger.info(f"Compiling Python variant: {project_name}")
                self.logger.info(f"{'='*60}")

                output_dir = os.path.join(
                    self.run_folder,
                    'executables',
                    project_name
                )
                os.makedirs(output_dir, exist_ok=True)

                compile_timeout = comp_config.get('compile_timeout', 300)
                result = self._compile_python_variant(
                    project_name=project_name,
                    variant_dir=variant_dir,
                    output_dir=output_dir,
                    timeout_seconds=compile_timeout,
                )

                self.compilation_results[project_name] = result

                if result.success:
                    self.logger.info(f"\n🎉 PYTHON COMPILATION SUCCESS!")
                    self.logger.info(f"   Executable: {result.executable_path}")
                else:
                    self.logger.error(f"\n❌ PYTHON COMPILATION FAILED!")
                    if result.errors:
                        self.logger.error(f"   Error: {result.errors[:1200]}")
                continue
            
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Compiling variant: {project_name}")
            self.logger.info(f"{'='*60}")
            
            # Create variant project object
            from project_detector import MalwareProject
            
            variant_project = MalwareProject(project_name, variant_dir)
            
            # Find source and header files in variant directory
            for root, dirs, files in os.walk(variant_dir):
                for f in files:
                    filepath = os.path.join(root, f)
                    ext = os.path.splitext(f)[1].lower()
                    
                    if ext in ['.c', '.cpp', '.cxx', '.cc']:
                        variant_project.add_source_file(filepath)
                    elif ext in ['.h', '.hpp', '.hxx']:
                        variant_project.add_header_file(filepath)
                    else:
                        variant_project.other_files.append(filepath)
            
            # Compile - save to run folder to separate each mutation run
            output_dir = os.path.join(
                self.run_folder,
                'executables',
                project_name
            )
            os.makedirs(output_dir, exist_ok=True)
            
            # Get parse result if available
            parse_result = mutation_data.get('parse_result', None)
            
            # Get Clang analysis from Stage 3 if available
            clang_analysis = mutation_data.get('clang_analysis', None)
            
            result = self.compiler.compile_project(
                variant_project,
                output_dir=output_dir,
                output_name=f"{project_name}_mutated.exe",
                auto_fix=comp_config.get('auto_fix', True),
                max_fix_attempts=comp_config.get('max_fix_attempts', 5),
                llm_model=comp_config.get('llm_model', 'deepseek-chat'),
                use_llm_fixer=comp_config.get('use_llm_fixer', True),
                llm_fixer_max_code_length=comp_config.get('llm_fixer_max_code_length', 50000),
                permissive_mode=comp_config.get('permissive_mode', True),
                parse_result=parse_result,
                pre_validate=comp_config.get('pre_validate', True),
                auto_generate_headers=comp_config.get('auto_generate_headers', True),
                use_enhanced_categorization=comp_config.get('use_enhanced_categorization', True),
                use_project_context=comp_config.get('use_project_context', True),
                use_hybrid_llm=comp_config.get('use_hybrid_llm', False),
                hybrid_local_model=comp_config.get('hybrid_local_model', 'qwen2.5-coder:7b-instruct-q4_K_M'),
                hybrid_cloud_file_size_limit=comp_config.get('hybrid_cloud_file_size_limit', 15000),
                hybrid_mode=comp_config.get('hybrid_mode', 'hybrid'),
                use_mahoraga=False,
                mahoraga_memory_file=None,
                external_fixer=None,
                clang_analysis=clang_analysis,
            )
            
            # Store result
            self.compilation_results[project_name] = result
            
            if result.success:
                self.logger.info(f"\n🎉 COMPILATION SUCCESS!")
                self.logger.info(f"   Executable: {result.executable_path}")
            else:
                self.logger.error(f"\n❌ COMPILATION FAILED!")
                
                # ── SMART FALLBACK: Preserve as many mutations as possible ──
                # Strategy: 3 tiers to maximize preserved mutations
                #   Tier 1: Per-function revert — only revert functions causing errors
                #   Tier 2: Selective file revert — only revert files with errors
                #   Tier 3: Full revert — revert all mutated files (last resort)
                
                import re as _re
                import shutil as _shutil
                
                # Build mutation map: basename -> list of {orig_func, variant_func, func_name}
                file_mutations_map = {}  # basename -> [{orig_body, variant_body, name, src_file}]
                for m in mutation_data.get('mutated_functions', []):
                    orig_func = m.get('original_function', {})
                    src_file = orig_func.get('source_file', '')
                    if not src_file or not os.path.exists(src_file):
                        continue
                    basename = os.path.basename(src_file)
                    variant_funcs = m.get('variant_functions', [])
                    if not variant_funcs:
                        continue
                    if basename not in file_mutations_map:
                        file_mutations_map[basename] = []
                    file_mutations_map[basename].append({
                        'name': orig_func.get('name_only', 'unknown'),
                        'orig_body': orig_func.get('body', ''),
                        'variant_body': variant_funcs[0].get('body', ''),
                        'src_file': src_file,
                        'start_line': orig_func.get('start_line', -1),
                        'end_line': orig_func.get('end_line', -1),
                    })
                
                if not file_mutations_map:
                    self.logger.warning(f"   No mutated files found to revert")
                else:
                    # Parse error output to find which files have errors
                    error_text = result.errors if isinstance(result.errors, str) else str(result.errors)
                    files_with_errors = set()
                    for bname in file_mutations_map:
                        if bname in error_text:
                            files_with_errors.add(bname)
                    
                    files_without_errors = set(file_mutations_map.keys()) - files_with_errors
                    total_mutations = sum(len(v) for v in file_mutations_map.values())
                    error_mutations = sum(len(file_mutations_map[f]) for f in files_with_errors)
                    
                    self.logger.info(f"\n🔄 SMART FALLBACK: {len(files_with_errors)}/{len(file_mutations_map)} "
                                     f"mutated file(s) have errors, {error_mutations}/{total_mutations} mutations at risk")
                    
                    if files_without_errors:
                        self.logger.info(f"   ✅ Keeping mutations in: {', '.join(files_without_errors)}")
                    
                    # ── Tier 1: Per-function revert in error files ──
                    # Rebuild variant files from scratch: start from original,
                    # only apply mutations whose line ranges don't overlap with errors.
                    # This works even after the auto_fixer has modified the variant.
                    self.logger.info(f"\n   📌 Tier 1: Per-function selective mutation in error files...")
                    
                    # Parse error lines per file from MSVC output
                    # Format: path\file.ext(LINE): error CXXXX: message
                    error_lines_per_file = {}  # basename -> set of line numbers
                    for line in error_text.split('\n'):
                        em = _re.search(r'[/\\]([^/\\]+)\((\d+)\)\s*:\s*error\s+C\d+', line)
                        if em:
                            efname = em.group(1)
                            eline = int(em.group(2))
                            if efname not in error_lines_per_file:
                                error_lines_per_file[efname] = set()
                            error_lines_per_file[efname].add(eline)
                    
                    tier1_reverted_funcs = []
                    tier1_kept_funcs = []
                    tier1_any_written = False
                    
                    for err_file in files_with_errors:
                        variant_file = os.path.join(variant_dir, err_file)
                        original_file = file_mutations_map[err_file][0]['src_file']
                        if not os.path.exists(original_file):
                            continue
                        
                        # Read original source
                        with open(original_file, 'r', encoding='utf-8', errors='ignore') as f:
                            original_code = f.read()
                        
                        error_lines = error_lines_per_file.get(err_file, set())
                        funcs_in_file = file_mutations_map[err_file]
                        
                        # For each mutation, find original function line range
                        # and check if any error line falls within it
                        rebuilt_code = original_code
                        for func_info in funcs_in_file:
                            orig_body = func_info['orig_body']
                            variant_body = func_info['variant_body']
                            fname = func_info['name']
                            
                            if not orig_body or not variant_body:
                                continue
                            
                            # Find the original function's line range
                            start_line = func_info.get('start_line', -1)
                            end_line = func_info.get('end_line', -1)
                            
                            if start_line < 0 or end_line < 0:
                                # Fallback: compute from body position in original file
                                body_start = original_code.find(orig_body)
                                if body_start < 0:
                                    self.logger.warning(f"      ⚠ Could not find {fname} body in original {err_file}")
                                    continue
                                start_line = original_code[:body_start].count('\n') + 1
                                end_line = start_line + orig_body.count('\n')
                            
                            # Check if any error falls within this function's range (with margin)
                            margin = 5
                            func_error_lines = {el for el in error_lines 
                                                 if start_line - margin <= el <= end_line + margin}
                            
                            if func_error_lines:
                                # This function likely caused errors → keep original (don't apply mutation)
                                tier1_reverted_funcs.append(f"{fname} ({err_file})")
                                self.logger.info(f"      ↩ Revert: {fname} (errors at lines {sorted(func_error_lines)[:5]})")
                            else:
                                # No errors in this function → apply mutation
                                clean_variant = self._clean_llm_artifacts(variant_body)
                                if orig_body in rebuilt_code:
                                    rebuilt_code = rebuilt_code.replace(orig_body, clean_variant, 1)
                                    tier1_kept_funcs.append(f"{fname} ({err_file})")
                                    self.logger.info(f"      ✓ Keep mutation: {fname}")
                        
                        # Write rebuilt file
                        if tier1_reverted_funcs or tier1_kept_funcs:
                            # Apply same post-processing as _generate_file_variant
                            rebuilt_code = self._clean_llm_artifacts(rebuilt_code)
                            rebuilt_code = self._ensure_includes_preserved(original_code, rebuilt_code)
                            
                            with open(variant_file, 'w', encoding='utf-8') as f:
                                f.write(rebuilt_code)
                            tier1_any_written = True
                    
                    if tier1_any_written and tier1_reverted_funcs:
                        preserved = len(tier1_kept_funcs)
                        self.logger.info(f"   Tier 1: Reverted {len(tier1_reverted_funcs)} function(s), "
                                         f"kept {preserved}/{total_mutations} mutations")
                        self.logger.info(f"   Retrying compilation...")
                        
                        result = self._fallback_compile(
                            variant_project, output_dir, project_name,
                            mutation_config, comp_config, parse_result
                        )
                        self.compilation_results[project_name] = result
                        
                        if result.success:
                            self.logger.info(f"\n🎉 TIER 1 SUCCESS! Preserved {preserved}/{total_mutations} mutations")
                            self.logger.info(f"   Executable: {result.executable_path}")
                            self.logger.info(f"   Kept: {', '.join(tier1_kept_funcs)}")
                            self.logger.info(f"   Reverted: {', '.join(tier1_reverted_funcs)}")
                    
                    # ── Tier 2: Selective file revert (only error files) ──
                    if not result.success and files_without_errors:
                        self.logger.info(f"\n   📌 Tier 2: Selective file revert (only error files)...")
                        
                        tier2_reverted = []
                        for err_file in files_with_errors:
                            variant_file = os.path.join(variant_dir, err_file)
                            original_file = file_mutations_map[err_file][0]['src_file']
                            if os.path.exists(variant_file) and os.path.exists(original_file):
                                _shutil.copy2(original_file, variant_file)
                                tier2_reverted.append(err_file)
                                self.logger.info(f"      ↩ Reverted file: {err_file}")
                        
                        if tier2_reverted:
                            preserved = sum(len(file_mutations_map[f]) for f in files_without_errors)
                            self.logger.info(f"   Tier 2: Reverted {len(tier2_reverted)} file(s), "
                                             f"preserved {preserved}/{total_mutations} mutations")
                            self.logger.info(f"   Retrying compilation...")
                            
                            result = self._fallback_compile(
                                variant_project, output_dir, project_name,
                                mutation_config, comp_config, parse_result
                            )
                            self.compilation_results[project_name] = result
                            
                            if result.success:
                                self.logger.info(f"\n🎉 TIER 2 SUCCESS! Preserved {preserved}/{total_mutations} mutations")
                                self.logger.info(f"   Executable: {result.executable_path}")
                                self.logger.info(f"   Kept mutations in: {', '.join(files_without_errors)}")
                    
                    # ── Tier 3: Full revert (last resort) ──
                    if not result.success:
                        self.logger.info(f"\n   📌 Tier 3: Full revert (all mutated files)...")
                        
                        tier3_reverted = []
                        for bname, funcs_list in file_mutations_map.items():
                            variant_file = os.path.join(variant_dir, bname)
                            original_file = funcs_list[0]['src_file']
                            if os.path.exists(variant_file) and os.path.exists(original_file):
                                _shutil.copy2(original_file, variant_file)
                                tier3_reverted.append(bname)
                                self.logger.info(f"      ↩ Reverted file: {bname}")
                        
                        if tier3_reverted:
                            self.logger.info(f"   Tier 3: Reverted ALL {len(tier3_reverted)} file(s)")
                            self.logger.info(f"   Retrying compilation...")
                            
                            result = self._fallback_compile(
                                variant_project, output_dir, project_name,
                                mutation_config, comp_config, parse_result
                            )
                            self.compilation_results[project_name] = result
                            
                            if result.success:
                                self.logger.info(f"\n🎉 TIER 3 SUCCESS! (all mutations reverted)")
                                self.logger.info(f"   Executable: {result.executable_path}")
                            else:
                                self.logger.error(f"\n❌ ALL FALLBACK TIERS FAILED!")
        
        # Mahoraga disabled: no adaptive fixer snapshots or memory handling
    
    def _fallback_compile(self, variant_project, output_dir, project_name,
                          mutation_config, comp_config, parse_result):
        """Compile with minimal settings for fallback retry"""
        return self.compiler.compile_project(
            variant_project,
            output_dir=output_dir,
            output_name=f"{project_name}_mutated.exe",
            auto_fix=True,
            max_fix_attempts=3,
            llm_model=comp_config.get('llm_model', 'deepseek-chat'),
            use_llm_fixer=True,
            llm_fixer_max_code_length=comp_config.get('llm_fixer_max_code_length', 50000),
            permissive_mode=True,
            parse_result=parse_result,
            pre_validate=False,
            auto_generate_headers=True,
            use_enhanced_categorization=False,
            use_project_context=False,
            use_hybrid_llm=comp_config.get('use_hybrid_llm', True),
            hybrid_local_model=comp_config.get('hybrid_local_model', 'qwen2.5-coder:7b-instruct-q4_K_M'),
            hybrid_cloud_file_size_limit=comp_config.get('hybrid_cloud_file_size_limit', 15000),
            hybrid_mode=comp_config.get('hybrid_mode', 'hybrid'),
            use_mahoraga=False,
            mahoraga_memory_file=None,
            external_fixer=None,
        )

    def _normalize_project_key(self, name: str) -> str:
        """Normalize project/config keys for resilient matching."""
        if not name:
            return ''
        return ''.join(ch.lower() for ch in name if ch.isalnum())

    def _resolve_original_executable_path(self, project_name: str, sandbox_cfg: dict) -> str:
        """Resolve original executable path from config and common fallback locations."""
        mapping = sandbox_cfg.get('original_executables', {}) or {}
        candidates = []

        # 1) Exact key match
        configured = mapping.get(project_name, '')
        if configured:
            candidates.append(configured)

        # 2) Normalized key match (case/punctuation-insensitive)
        if not configured and mapping:
            target_key = self._normalize_project_key(project_name)
            for cfg_key, cfg_path in mapping.items():
                if self._normalize_project_key(cfg_key) == target_key and cfg_path:
                    candidates.append(cfg_path)
                    break

        # 3) compilation_result.json in original_executables/<project>
        original_root = os.path.join(
            self.config.get('environment', {}).get('project_root', ''),
            'original_executables',
            project_name,
        )
        comp_result_path = os.path.join(original_root, 'compilation_result.json')
        if os.path.exists(comp_result_path):
            try:
                with open(comp_result_path, 'r', encoding='utf-8') as f:
                    comp_result = json.load(f)
                exe_from_result = comp_result.get('executable_path', '')
                if exe_from_result:
                    candidates.append(exe_from_result)
            except Exception as e:
                self.logger.debug(f"Could not read {comp_result_path}: {e}")

        # 4) Any .exe under original_executables/<project>
        if os.path.isdir(original_root):
            for root, _, files in os.walk(original_root):
                for fname in files:
                    if fname.lower().endswith('.exe'):
                        candidates.append(os.path.join(root, fname))

        # Return first existing candidate
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate

        return ''

    def _find_detected_project(self, project_name: str):
        """Find detected MalwareProject by name (robust matching)."""
        target_key = self._normalize_project_key(project_name)
        for project in self.detected_projects:
            if self._normalize_project_key(project.name) == target_key:
                return project
        return None

    def _build_original_executable(self, project_name: str, output_path: str) -> str:
        """Build original executable on-the-fly if missing from disk."""
        project = self._find_detected_project(project_name)
        if not project:
            self.logger.warning(f"   ⚠️  Cannot auto-build original: project '{project_name}' not found in detected projects.")
            return ''

        comp_config = self.config.get('compilation', {})

        # Ensure compiler is initialized
        if self.compiler is None:
            compiler_pref = comp_config.get('compiler', 'auto')
            msvc_arch = comp_config.get('msvc_arch', 'x64')
            self.compiler = ProjectCompiler(compiler=compiler_pref, msvc_arch=msvc_arch)

        output_dir = os.path.dirname(output_path)
        output_name = os.path.basename(output_path)
        os.makedirs(output_dir, exist_ok=True)

        parse_result = self.parse_results.get(project_name, {}).get('parse_result')

        self.logger.info(f"   🔧 Building original executable (fallback): {output_path}")
        result = self.compiler.compile_project(
            project,
            output_dir=output_dir,
            output_name=output_name,
            auto_fix=comp_config.get('auto_fix', True),
            max_fix_attempts=comp_config.get('max_fix_attempts', 5),
            llm_model=comp_config.get('llm_model', 'deepseek-chat'),
            use_llm_fixer=comp_config.get('use_llm_fixer', True),
            llm_fixer_max_code_length=comp_config.get('llm_fixer_max_code_length', 50000),
            permissive_mode=comp_config.get('permissive_mode', True),
            parse_result=parse_result,
            pre_validate=comp_config.get('pre_validate', False),
            auto_generate_headers=comp_config.get('auto_generate_headers', True),
            use_enhanced_categorization=comp_config.get('use_enhanced_categorization', True),
            use_project_context=comp_config.get('use_project_context', True),
            use_hybrid_llm=comp_config.get('use_hybrid_llm', False),
            hybrid_local_model=comp_config.get('hybrid_local_model', 'qwen2.5-coder:7b-instruct-q4_K_M'),
            hybrid_cloud_file_size_limit=comp_config.get('hybrid_cloud_file_size_limit', 120000),
            hybrid_mode=comp_config.get('hybrid_mode', 'hybrid'),
            use_mahoraga=False,
            mahoraga_memory_file=None,
            external_fixer=None,
        )

        if result.success:
            # Prefer compiler-reported path when it exists
            if result.executable_path and os.path.exists(result.executable_path):
                self.logger.info(f"   ✅ Original build success: {result.executable_path}")
                return result.executable_path

            # Fallback to requested output path
            if output_path and os.path.exists(output_path):
                self.logger.info(f"   ✅ Original build success: {output_path}")
                return output_path

            # Last resort: find any .exe produced in output directory
            output_dir = os.path.dirname(output_path)
            exe_candidates = []
            if os.path.isdir(output_dir):
                for fname in os.listdir(output_dir):
                    if fname.lower().endswith('.exe'):
                        full_path = os.path.join(output_dir, fname)
                        if os.path.isfile(full_path):
                            exe_candidates.append(full_path)

            if exe_candidates:
                exe_candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
                recovered = exe_candidates[0]
                self.logger.warning(
                    f"   ⚠️  Expected original executable missing at '{output_path}', "
                    f"using recovered executable: {recovered}"
                )
                return recovered

            self.logger.warning(
                f"   ⚠️  Original build reported success but executable is missing on disk for {project_name}. "
                f"This may be caused by external quarantine/removal."
            )
            return ''

        self.logger.warning(f"   ⚠️  Original build failed for {project_name}")
        return ''

    def _resolve_sandbox_backends(self, sandbox_cfg: dict):
        """Resolve requested sandbox backends with backward compatibility."""
        backends = []

        configured_backends = sandbox_cfg.get('backends', None)
        if isinstance(configured_backends, list):
            backends.extend(str(b).strip().lower() for b in configured_backends if str(b).strip())

        if not backends:
            backend = str(sandbox_cfg.get('backend', 'cape')).strip().lower()
            if backend in ('combined', 'cape+virustotal', 'virustotal+cape'):
                backends.extend(['cape', 'virustotal'])
            elif ',' in backend:
                backends.extend([b.strip().lower() for b in backend.split(',') if b.strip()])
            else:
                backends.append(backend)

        # Keep order while de-duplicating and filtering unsupported values
        supported = {'cape', 'cuckoo', 'virustotal'}
        seen = set()
        resolved = []
        for b in backends:
            if b in supported and b not in seen:
                resolved.append(b)
                seen.add(b)

        return resolved or ['cape']

    def _get_backend_runtime_config(self, backend: str, sandbox_cfg: dict) -> dict:
        """Get effective per-backend runtime config with sensible defaults."""
        backend_settings = sandbox_cfg.get('backend_settings', {}) or {}
        bcfg = backend_settings.get(backend, {}) or {}

        if backend == 'virustotal':
            default_url = 'https://www.virustotal.com'
        else:
            default_url = 'http://localhost:8090'

        # Backward compatibility keys + backend-specific overrides
        api_url = (
            bcfg.get('api_url')
            or sandbox_cfg.get(f'{backend}_api_url')
            or sandbox_cfg.get('api_url')
            or default_url
        )

        api_token = (
            bcfg.get('api_token')
            or sandbox_cfg.get(f'{backend}_api_token')
            or sandbox_cfg.get('api_token', '')
        )

        token_env = bcfg.get('api_token_env') or sandbox_cfg.get(f'{backend}_api_token_env')
        if token_env and not api_token:
            api_token = os.environ.get(token_env, '')

        if backend == 'virustotal' and not api_token:
            api_token = os.environ.get('VIRUSTOTAL_API_KEY', '')

        return {
            'backend': backend,
            'api_url': api_url,
            'api_token': api_token,
            'machine': bcfg.get('machine', sandbox_cfg.get('machine', '')),
            'analysis_timeout': bcfg.get('analysis_timeout', sandbox_cfg.get('analysis_timeout', 120)),
            'poll_interval': bcfg.get('poll_interval', sandbox_cfg.get('poll_interval', 15)),
            'max_wait': bcfg.get('max_wait', sandbox_cfg.get('max_wait', 600)),
            'cleanup': bcfg.get('cleanup', sandbox_cfg.get('cleanup', False)),
            'submission_options': bcfg.get('submission_options', sandbox_cfg.get('submission_options', {})) or {},
        }

    def _build_backend_failure_report(self, sample_path: str, status: str, error_message: str):
        """Create a synthetic sandbox report for backend initialization/connection failures."""
        return SandboxReport(
            status=status,
            error_message=error_message,
            sample_name=os.path.basename(sample_path) if sample_path else '',
            sample_size=os.path.getsize(sample_path) if sample_path and os.path.exists(sample_path) else 0,
        )

    def _build_combined_sandbox_summary(self, project_sandbox: dict) -> dict:
        """Aggregate CAPE/Cuckoo/VirusTotal backend results into a combined summary."""
        backend_results = project_sandbox.get('backends', {}) or {}
        completed_backends = []
        failed_backends = {}
        mutated_detection_counts = {}
        original_detection_counts = {}
        mutated_scores = {}
        original_scores = {}
        mutated_ttp_counts = {}
        original_ttp_counts = {}
        comparison_by_backend = {}

        for backend, backend_result in backend_results.items():
            mutated = backend_result.get('mutated', {}) or {}
            original = backend_result.get('original', {}) or {}
            comparison = backend_result.get('comparison', {}) or {}

            mutated_status = mutated.get('status', 'unknown')
            if mutated_status == 'completed':
                completed_backends.append(backend)
            else:
                failed_backends[backend] = {
                    'status': mutated_status,
                    'error_message': mutated.get('error_message', ''),
                }

            mutated_detection_counts[backend] = len(mutated.get('detections', []) or [])
            original_detection_counts[backend] = len(original.get('detections', []) or [])
            mutated_scores[backend] = mutated.get('score', 0)
            original_scores[backend] = original.get('score', 0)
            mutated_ttp_counts[backend] = len(mutated.get('ttps', []) or [])
            original_ttp_counts[backend] = len(original.get('ttps', []) or [])

            if comparison:
                comparison_by_backend[backend] = comparison

        best_backend = None
        if comparison_by_backend:
            best_backend = min(
                comparison_by_backend,
                key=lambda name: (
                    comparison_by_backend[name].get('detection_delta', float('inf')),
                    comparison_by_backend[name].get('score_delta', float('inf')),
                )
            )

        return {
            'requested_backends': project_sandbox.get('requested_backends', []),
            'available_backends': sorted(list(project_sandbox.get('available_backends', []))),
            'completed_backends': completed_backends,
            'failed_backends': failed_backends,
            'status': 'completed' if completed_backends else 'failed',
            'mutated_detection_counts': mutated_detection_counts,
            'original_detection_counts': original_detection_counts,
            'mutated_scores': mutated_scores,
            'original_scores': original_scores,
            'mutated_ttp_counts': mutated_ttp_counts,
            'original_ttp_counts': original_ttp_counts,
            'comparison_by_backend': comparison_by_backend,
            'best_backend_for_evasion': best_backend,
        }
    
    def stage6_sandbox_analysis(self, project_names=None):
        """Stage 6: Submit compiled executables to CAPE/Cuckoo/VirusTotal for behavioral analysis"""
        self.logger.info("\n" + "="*70)
        self.logger.info("STAGE 6: SANDBOX BEHAVIORAL ANALYSIS")
        self.logger.info("="*70)
        
        if not SANDBOX_AVAILABLE:
            self.logger.warning("⚠️  sandbox_analyzer module not available. Skipping.")
            return
        
        sandbox_cfg = self.config.get('sandbox', {})
        if not sandbox_cfg.get('enabled', False):
            self.logger.info("   Sandbox analysis disabled in config.")
            return

        backends = self._resolve_sandbox_backends(sandbox_cfg)
        submit_original = sandbox_cfg.get('submit_original', True)

        self.logger.info(f"   Backends: {', '.join(backends)}")

        analyzers = {}
        backend_health = {}
        for backend in backends:
            cfg = self._get_backend_runtime_config(backend, sandbox_cfg)
            self.logger.info(
                f"   [{backend}] URL={cfg['api_url']}, timeout={cfg['analysis_timeout']}s, max_wait={cfg['max_wait']}s"
            )

            # VT requires API key; skip gracefully if missing
            if backend == 'virustotal' and not cfg['api_token']:
                message = "Missing API token. Set VIRUSTOTAL_API_KEY or sandbox.backend_settings.virustotal.api_token"
                self.logger.warning(f"   ⚠️  [virustotal] {message}")
                backend_health[backend] = {
                    'available': False,
                    'error_message': message,
                    'api_url': cfg['api_url'],
                }
                continue

            try:
                analyzer = SandboxAnalyzer(
                    backend=cfg['backend'],
                    api_url=cfg['api_url'],
                    api_token=cfg['api_token'],
                    machine=cfg['machine'],
                    analysis_timeout=cfg['analysis_timeout'],
                    poll_interval=cfg['poll_interval'],
                    max_wait=cfg['max_wait'],
                    cleanup=cfg['cleanup'],
                    submission_options=cfg.get('submission_options', {})
                )
            except Exception as e:
                self.logger.error(f"❌ Failed to initialize {backend} analyzer: {e}")
                backend_health[backend] = {
                    'available': False,
                    'error_message': f'Failed to initialize analyzer: {e}',
                    'api_url': cfg['api_url'],
                }
                continue

            if not analyzer.test_connection():
                self.logger.error(f"❌ Cannot connect to {backend} at {cfg['api_url']}")
                backend_health[backend] = {
                    'available': False,
                    'error_message': f"Cannot connect to {backend} at {cfg['api_url']}",
                    'api_url': cfg['api_url'],
                }
                continue

            analyzers[backend] = analyzer
            backend_health[backend] = {
                'available': True,
                'error_message': '',
                'api_url': cfg['api_url'],
            }

        if not analyzers:
            self.logger.error("❌ No sandbox backend available. Stage 6 skipped.")
            return

        primary_backend = next(iter(analyzers.keys()))
        self.logger.info(f"   Primary backend for top-level summary: {primary_backend}")
        
        # Create sandbox output directory
        sandbox_output = os.path.join(self.run_folder, 'sandbox_reports')
        os.makedirs(sandbox_output, exist_ok=True)
        
        # Filter to successfully compiled projects
        projects_to_analyze = {}
        for pname, result in self.compilation_results.items():
            if project_names and pname not in project_names:
                continue
            if result.success and result.executable_path:
                if os.path.exists(result.executable_path):
                    projects_to_analyze[pname] = result.executable_path
                else:
                    self.logger.warning(f"⚠️  {pname}: executable not found at {result.executable_path}")
        
        if not projects_to_analyze:
            self.logger.warning("⚠️  No successfully compiled executables to analyze.")
            return
        
        self.logger.info(f"\n   Executables to analyze: {len(projects_to_analyze)}")
        
        for project_name, exe_path in projects_to_analyze.items():
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Sandbox analysis: {project_name}")
            self.logger.info(f"{'='*60}")
            self.logger.info(f"   Executable: {exe_path}")
            
            project_sandbox = {
                'requested_backends': backends,
                'available_backends': list(analyzers.keys()),
                'primary_backend': primary_backend,
                'backend_health': backend_health,
                'backends': {},
            }

            # Resolve original executable once per project (shared by all backends)
            original_exe = ''
            if submit_original:
                original_exe = self._resolve_original_executable_path(project_name, sandbox_cfg)
                if not original_exe:
                    default_output = os.path.join(
                        self.config.get('environment', {}).get('project_root', ''),
                        'original_executables',
                        project_name,
                        f'{project_name}_original.bin.exe',
                    )
                    original_exe = self._build_original_executable(project_name, default_output)

                if not (original_exe and os.path.exists(original_exe)):
                    self.logger.info(f"   ℹ️  No usable original executable found for comparison.")
                    self.logger.info(f"      Checked sandbox.original_executables.{project_name} and fallback paths.")
                    self.logger.info(f"      Please ensure an original .exe exists or can be compiled for this project.")
                    original_exe = ''

            for backend, analyzer in analyzers.items():
                self.logger.info(f"\n   ▶ Backend: {backend}")
                backend_result = {}

                # Submit mutated executable
                self.logger.info(f"   📤 Submitting mutated variant...")
                try:
                    mutated_report = analyzer.submit_and_wait(exe_path)
                except Exception as e:
                    self.logger.exception(f"   ❌ [{backend}] Mutated submission crashed: {e}")
                    mutated_report = SandboxReport(
                        status='failed',
                        error_message=f'Exception during mutated analysis: {e}',
                        sample_name=os.path.basename(exe_path),
                        sample_size=os.path.getsize(exe_path) if os.path.exists(exe_path) else 0,
                    )
                backend_result['mutated'] = mutated_report.to_dict()

                if mutated_report.status == 'completed':
                    self.logger.info(f"   ✅ [{backend}] Analysis complete")
                    self.logger.info(f"      Score: {mutated_report.score}/10")
                    self.logger.info(f"      Detections: {len(mutated_report.detections)}")
                    self.logger.info(f"      API calls: {mutated_report.api_call_count}")
                    self.logger.info(f"      Signatures: {len(mutated_report.signatures)}")
                    self.logger.info(f"      Registry ops: {len(mutated_report.registry_operations)}")
                    self.logger.info(f"      Network ops: {len(mutated_report.network_operations)}")
                else:
                    self.logger.error(f"   ❌ [{backend}] Analysis failed: {mutated_report.error_message}")

                if submit_original and original_exe:
                    # File may disappear after initial resolution/build (e.g. quarantine/removal).
                    # Re-validate right before submission and try one recovery pass.
                    if not os.path.exists(original_exe):
                        self.logger.warning(
                            f"   ⚠️  Original executable no longer exists before submission: {original_exe}"
                        )

                        recovered_original = self._resolve_original_executable_path(project_name, sandbox_cfg)
                        if not recovered_original:
                            default_output = os.path.join(
                                self.config.get('environment', {}).get('project_root', ''),
                                'original_executables',
                                project_name,
                                f'{project_name}_original.bin.exe',
                            )
                            recovered_original = self._build_original_executable(project_name, default_output)

                        if recovered_original and os.path.exists(recovered_original):
                            original_exe = recovered_original
                            self.logger.info(f"   ✅ Recovered original executable: {original_exe}")
                        else:
                            self.logger.warning(
                                "   ⚠️  Skipping original comparison for this backend: no usable original executable."
                            )
                            backend_result['original'] = self._build_backend_failure_report(
                                original_exe,
                                'skipped',
                                'Original executable missing on disk before submission'
                            ).to_dict()
                            project_sandbox['backends'][backend] = backend_result
                            continue

                    self.logger.info(f"   📤 Submitting original for comparison...")
                    self.logger.info(f"      Original executable: {original_exe}")
                    try:
                        original_report = analyzer.submit_and_wait(original_exe)
                    except Exception as e:
                        self.logger.exception(f"   ❌ [{backend}] Original submission crashed: {e}")
                        original_report = SandboxReport(
                            status='failed',
                            error_message=f'Exception during original analysis: {e}',
                            sample_name=os.path.basename(original_exe),
                            sample_size=os.path.getsize(original_exe) if os.path.exists(original_exe) else 0,
                        )
                    backend_result['original'] = original_report.to_dict()

                    if original_report.status == 'completed' and mutated_report.status == 'completed':
                        comparison = analyzer.compare_reports(original_report, mutated_report)
                        backend_result['comparison'] = comparison.to_dict()

                        self.logger.info(f"   📊 [{backend}] BEHAVIORAL COMPARISON:")
                        self.logger.info(f"      Original score:  {original_report.score}")
                        self.logger.info(f"      Mutated score:   {mutated_report.score} (delta: {comparison.score_delta:+.1f})")
                        self.logger.info(f"      Detection delta: {comparison.detection_delta:+d}")
                        self.logger.info(f"      API similarity:  {comparison.api_similarity:.1%}")
                        self.logger.info(f"      Behavior preserved: {comparison.behavioral_preserved}")

                        if comparison.removed_signatures:
                            self.logger.info(f"      ✅ Signatures evaded: {', '.join(comparison.removed_signatures)}")
                        if comparison.new_signatures:
                            self.logger.info(f"      ⚠️  New signatures:   {', '.join(comparison.new_signatures)}")

                project_sandbox['backends'][backend] = backend_result

            for backend in backends:
                if backend in project_sandbox['backends']:
                    continue

                backend_error = (project_sandbox.get('backend_health', {}).get(backend, {}) or {}).get('error_message', '')
                project_sandbox['backends'][backend] = {
                    'mutated': self._build_backend_failure_report(
                        exe_path,
                        'unavailable',
                        backend_error or f'{backend} backend unavailable'
                    ).to_dict()
                }
                if submit_original and original_exe:
                    project_sandbox['backends'][backend]['original'] = self._build_backend_failure_report(
                        original_exe,
                        'unavailable',
                        backend_error or f'{backend} backend unavailable'
                    ).to_dict()

            project_sandbox['combined_summary'] = self._build_combined_sandbox_summary(project_sandbox)
            combined = project_sandbox['combined_summary']
            self.logger.info(
                "   🧩 Combined summary: status=%s, completed_backends=%s",
                combined.get('status', 'unknown'),
                ', '.join(combined.get('completed_backends', [])) or 'none'
            )

            # Backward compatibility: keep top-level keys from primary backend
            primary_result = project_sandbox['backends'].get(primary_backend, {})
            if primary_result:
                for key in ('mutated', 'original', 'comparison'):
                    if key in primary_result:
                        project_sandbox[key] = primary_result[key]
            
            # Save per-project report
            report_file = os.path.join(sandbox_output, f'{project_name}_sandbox_report.json')
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(project_sandbox, f, indent=2)
            self.logger.info(f"\n   📁 Report saved: {report_file}")
            
            self.sandbox_results[project_name] = project_sandbox
        
        # Summary
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"SANDBOX ANALYSIS SUMMARY")
        self.logger.info(f"{'='*60}")
        total = len(projects_to_analyze)
        completed = sum(
            1 for r in self.sandbox_results.values()
            if (r.get('combined_summary', {}) or {}).get('status') == 'completed'
        )
        self.logger.info(f"   Analyzed: {completed}/{total}")
        
        for pname, result in self.sandbox_results.items():
            mut = result.get('mutated', {})
            status = mut.get('status', 'unknown')
            score = mut.get('score', 0)
            detections = mut.get('detections', [])
            self.logger.info(f"   {'✅' if status == 'completed' else '❌'} {pname}: "
                           f"score={score}, detections={len(detections)}")

            for backend, backend_result in result.get('backends', {}).items():
                bmut = backend_result.get('mutated', {})
                bstatus = bmut.get('status', 'unknown')
                bscore = bmut.get('score', 0)
                bdetections = bmut.get('detections', [])
                self.logger.info(
                    f"      - [{backend}] {'✅' if bstatus == 'completed' else '❌'} "
                    f"score={bscore}, detections={len(bdetections)}"
                )
            combined = result.get('combined_summary', {}) or {}
            if combined:
                self.logger.info(
                    f"      - [combined] {'✅' if combined.get('status') == 'completed' else '❌'} "
                    f"completed_backends={','.join(combined.get('completed_backends', [])) or 'none'}"
                )
    
    def generate_final_report(self):
        """Generate final report"""
        self.logger.info("\n" + "="*70)
        self.logger.info("FINAL REPORT")
        self.logger.info("="*70)
        
        report = {
            'run_id': self.run_id,
            'run_folder': self.run_folder,
            'timestamp': datetime.now().isoformat(),
            'configuration': self.config,
            'statistics': {
                'detected_projects': len(self.detected_projects),
                'parsed_projects': len(self.parse_results),
                'mutated_projects': len(self.mutation_results),
                'compiled_projects': len(self.compilation_results),
                'successful_compilations': sum(
                    1 for r in self.compilation_results.values()
                    if r.success
                ),
                'sandbox_analyzed': len(self.sandbox_results),
            },
            'projects': {},
        }
        
        # Add project details
        for project_name, result in self.compilation_results.items():
            project_report = {
                'compilation_success': result.success,
                'executable_path': result.executable_path,
                'executable_size': result.executable_size,
                'compile_time': result.compile_time,
            }
            # Add mutation tracking data if available
            if project_name in self.mutation_results:
                mut_data = self.mutation_results[project_name]
                project_report['mutation_stats'] = {
                    'trials': mut_data.get('experiment_trial_no', 1),
                    'best_trial': mut_data.get('best_trial', 0),
                    'initial_seed': mut_data.get('initial_seed', 42),
                    'seeds_per_func_per_trial': mut_data.get('seeds_per_func_per_trial', []),
                    'success_rate': len(mut_data.get('mutated_functions', [])) / max(len(mut_data.get('selected_functions', [])), 1) * 100,
                }
            # Add sandbox data if available
            if project_name in self.sandbox_results:
                project_report['sandbox'] = self.sandbox_results[project_name]
            report['projects'][project_name] = project_report
        
        # Save report to run folder
        report_file = os.path.join(
            self.run_folder,
            'final_report.json'
        )
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"\n✅ Report saved: {report_file}")
        
        # Print summary
        self.logger.info("\n" + "="*70)
        self.logger.info("📊 SUMMARY")
        self.logger.info("="*70)
        self.logger.info(f"Run ID: {self.run_id}")
        self.logger.info(f"Run Folder: {self.run_folder}")
        self.logger.info(f"Projects detected: {len(self.detected_projects)}")
        self.logger.info(f"Projects parsed: {len(self.parse_results)}")
        self.logger.info(f"Projects mutated: {len(self.mutation_results)}")
        self.logger.info(f"Projects compiled: {len(self.compilation_results)}")
        self.logger.info(f"Successful compilations: {report['statistics']['successful_compilations']}")
        
        if self.compilation_results:
            self.logger.info(f"\n✅ GENERATED EXECUTABLES:")
            for project_name, result in self.compilation_results.items():
                if result.success:
                    self.logger.info(f"   ✓ {project_name}: {result.executable_path}")
                else:
                    self.logger.info(f"   ✗ {project_name}: Failed")
        
        self.logger.info(f"\n📁 All results saved in: {self.run_folder}")
        self.logger.info(f"   - Stage 1 (Detection): detected_projects.json")
        self.logger.info(f"   - Stage 2 (Parsing): parsed_*.json")
        self.logger.info(f"   - Stage 3 (Mutation): mutated_*.json")
        self.logger.info(f"   - Stage 4 (Variants): {os.path.join(self.run_folder, 'variants')}")
        self.logger.info(f"   - Stage 5 (Executables): {os.path.join(self.run_folder, 'executables')}")
        if self.sandbox_results:
            self.logger.info(f"   - Stage 6 (Sandbox): {os.path.join(self.run_folder, 'sandbox_reports')}")
        self.logger.info(f"   - Final Report: {report_file}")
        self.logger.info(f"   - Log File: {os.path.join(self.run_folder, 'pipeline.log')}")
        
        self.logger.info("\n" + "="*70)
    
    def run(self, stages='all', project_names=None):
        """Run the pipeline"""
        self.logger.info("\n" + "="*70)
        self.logger.info("🚀 PROJECT-BASED MUTATION PIPELINE")
        self.logger.info("="*70)
        self.logger.info(f"Mode: {'All stages' if stages == 'all' else f'Stage {stages}'}")
        self.logger.info(f"Projects: {'All' if not project_names else ', '.join(project_names)}")
        
        try:
            # Stage 1: Detect projects
            if stages in ['all', '1']:
                if not self.stage1_detect_projects():
                    return
            
            # Stage 2: Parse projects
            if stages in ['all', '2']:
                if not self.stage2_parse_projects(project_names):
                    return
            
            # Stage 3: Mutate functions
            if stages in ['all', '3']:
                if not self.stage3_mutate_functions(project_names):
                    return
            
            # Stage 4: Generate variants
            if stages in ['all', '4']:
                self.stage4_generate_variants(project_names)
            
            # Stage 5: Compile variants
            if stages in ['all', '5']:
                self.stage5_compile_variants(project_names)
            
            # Stage 6: Sandbox analysis (optional)
            if stages in ['all', '6']:
                sandbox_cfg = self.config.get('sandbox', {})
                if sandbox_cfg.get('enabled', False):
                    self.stage6_sandbox_analysis(project_names)
                elif stages == '6':
                    self.logger.info("⚠️  Sandbox analysis disabled in config (sandbox.enabled=false)")
            
            # Generate final report
            if stages == 'all':
                self.generate_final_report()
            
            self.logger.info("\n✅ PIPELINE COMPLETED!")
            
        except KeyboardInterrupt:
            self.logger.warning("\n\n⚠️  Pipeline interrupted by user")
        except Exception as e:
            self.logger.error(f"\n❌ Pipeline failed: {e}")
            traceback.print_exc()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Project-Based Mutation Pipeline for LLMalMorph'
    )
    parser.add_argument(
        '--config',
        default='project_config.json',
        help='Path to config file (default: project_config.json)'
    )
    parser.add_argument(
        '--stage',
        choices=['1', '2', '3', '4', '5', '6', 'all'],
        default='all',
        help='Pipeline stage to run (1-5=mutation pipeline, 6=sandbox analysis, all=everything)'
    )
    parser.add_argument(
        '--project',
        nargs='+',
        help='Specific project names to process'
    )
    parser.add_argument(
        '--trials',
        type=int,
        default=None,
        help='Number of mutation trials per function (overrides config)'
    )
    parser.add_argument(
        '--seed',
        type=int,
        default=None,
        help='Initial random seed for reproducibility (overrides config)'
    )
    parser.add_argument(
        '--skip-over',
        type=int,
        default=None,
        dest='skip_over',
        help='Number of functions to skip from the beginning (overrides config)'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=None,
        dest='func_batch_size',
        help='Number of functions per LLM call (overrides config, -1 for all)'
    )
    parser.add_argument(
        '--strategy',
        type=str,
        default=None,
        help='Mutation strategy: strat_1..strat_6, strat_all (overrides config)'
    )
    parser.add_argument(
        '--response-format',
        type=str,
        default=None,
        dest='source_code_response_format',
        choices=['backticks', 'json'],
        help='LLM response format (overrides config)'
    )
    
    args = parser.parse_args()
    
    try:
        pipeline = ProjectBasedMutationPipeline(args.config)
        
        # Apply CLI overrides to config
        if args.trials is not None:
            pipeline.config['mutation']['trials'] = args.trials
        if args.seed is not None:
            pipeline.config['mutation']['initial_seed'] = args.seed
        if args.skip_over is not None:
            pipeline.config['mutation']['skip_over'] = args.skip_over
        if args.func_batch_size is not None:
            pipeline.config['mutation']['func_batch_size'] = args.func_batch_size
        if args.strategy is not None:
            pipeline.config['mutation']['strategy'] = args.strategy
        if args.source_code_response_format is not None:
            pipeline.config['mutation']['source_code_response_format'] = args.source_code_response_format
        
        pipeline.run(args.stage, args.project)
    except KeyboardInterrupt:
        print("\n\n⚠️  Pipeline interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Pipeline failed: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

