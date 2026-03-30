"""
Improved pipeline utilities with better error handling, logging, and unified LLM interface.
"""
import os
import time
import logging
from typing import Optional, Tuple, List, Dict, Any

from llm_api import (
    get_llm_provider,
    LLMProvider,
    LLMAPIError,
    ollama_chat_api,
)
from parse_llm_generated_code import parse_code

# Configure logging
logger = logging.getLogger(__name__)


def get_llm_name_from_input(llm_input: str) -> str:
    """
    Map user-friendly LLM names to actual model names.
    
    Args:
        llm_input: User-provided LLM name
    
    Returns:
        Actual model name for the LLM provider
    """
    llm_name_to_model_name = {
        "deepseek_33b": "deepseek-coder:33b-instruct",
        "deepseek_v2_16b": "deepseek-coder-v2:16b-lite-instruct-q4_0",
        "starcoder2": "starcoder2:instruct",
        "codestral": "codestral-latest",
        "codestral-2508": "codestral-2508",
        "codellama_7b": "codellama:7b-instruct",
        "codegemma_7b": "codegemma:7b-instruct",
        "codellama_13b": "codellama:13b-instruct",
        "llama3_8b": "llama3:8b-instruct-q4_0",
        "mistral": "mistral:7b-instruct",
    }
    
    if llm_input not in llm_name_to_model_name:
        raise ValueError(
            f"Unknown LLM name: {llm_input}. "
            f"Available options: {list(llm_name_to_model_name.keys())}"
        )
    
    return llm_name_to_model_name[llm_input]


def prepend_headers_globals(headers: List[str], globals: List[Any]) -> str:
    """
    Combine headers and globals into a single string.
    
    Args:
        headers: List of header includes
        globals: List of global declarations (strings or dicts with 'body' key)
    
    Returns:
        Combined string
    """
    result = ""
    
    for header in headers:
        result += header + "\n"
    
    for global_ in globals:
        if isinstance(global_, dict):
            result += global_["body"] + "\n"
        else:
            result += str(global_) + "\n"
    
    return result


def prepend_function_def_with_batching(
    parsed_info: Tuple,
    num_functions: int,
    batch_size: int
) -> Tuple[List[str], List[List[Dict]], int, List[str], List[Any]]:
    """
    Combine headers, globals and functions into batches.
    
    Args:
        parsed_info: Parsed source code info (headers, globals, functions, classes, structs)
        num_functions: Number of functions to process
        batch_size: Number of functions per batch
    
    Returns:
        Tuple of (function_definitions, function_objects, total_functions, headers, globals)
    """
    headers, globals, functions, _, _ = parsed_info
    function_names = []
    function_param_count = []
    function_definitions = []
    function_objects = []
    
    global_information = prepend_headers_globals(headers, globals)
    
    temp_function_names = []
    temp_function_param_count = []
    temp_function_definitions = global_information
    temp_function_objects = []
    
    num_functions = min(num_functions, len(functions))
    
    for i in range(0, num_functions, batch_size):
        for j in range(i, min(i + batch_size, num_functions)):
            temp_function_objects.append(functions[j])
            temp_function_names.append(functions[j]["name_only"])
            temp_function_param_count.append(functions[j]["parameters_count"])
            temp_function_definitions += functions[j]["body"] + "\n"
        
        # Add to main lists
        function_names.append(temp_function_names)
        function_definitions.append(temp_function_definitions)
        function_param_count.append(temp_function_param_count)
        function_objects.append(temp_function_objects)
        
        # Reset temporary variables
        temp_function_names = []
        temp_function_objects = []
        temp_function_definitions = global_information
    
    return function_definitions, function_objects, len(functions), headers, globals


def prepend_function_defs(
    parsed_info: Tuple,
    num_functions: int
) -> Tuple[str, List[str], int]:
    """
    Combine headers, globals and functions into a single string.
    
    Args:
        parsed_info: Parsed source code info
        num_functions: Number of functions to include
    
    Returns:
        Tuple of (combined_code, function_names, total_functions)
    """
    headers, globals, functions, _, _ = parsed_info
    result = ""
    function_names = []
    
    result = prepend_headers_globals(headers, globals)
    
    num_functions = min(num_functions, len(functions))
    
    for i in range(num_functions):
        function_names.append(functions[i]["name_with_params"])
        result += functions[i]["body"] + "\n"
    
    return result, function_names, len(functions)


def write_llm_response_to_file(output_dir: str, llm_response: str, file_name: str) -> None:
    """
    Write LLM response to file.
    
    Args:
        output_dir: Output directory
        llm_response: Response text to write
        file_name: Name of the file
    """
    file_path = os.path.join(output_dir, file_name)
    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(llm_response)
        logger.debug(f"Written LLM response to {file_path}")
    except Exception as e:
        logger.error(f"Failed to write LLM response to {file_path}: {str(e)}")
        raise


def run_llm(
    llm_name: str,
    system_prompt: str,
    user_prompt: str,
    seed: int = 42,
    api_key: Optional[str] = None,
    warmup: bool = True,
) -> Tuple[str, float]:
    """
    Run LLM generation with optional warmup.
    
    Args:
        llm_name: Model name
        system_prompt: System prompt
        user_prompt: User prompt
        seed: Random seed
        api_key: Optional API key for Mistral
        warmup: Whether to do a warmup call (Ollama only)
    
    Returns:
        Tuple of (response, response_time)
    """
    provider = get_llm_provider(llm_name, api_key=api_key)
    
    # Normalize model name
    if llm_name.startswith("codestral-") or llm_name == "codestral-latest":
        model = llm_name.replace(":", "-")
    else:
        model = llm_name
    
    # Warmup call for Ollama (not needed for Mistral API)
    from llm_api import OllamaProvider
    if warmup and isinstance(provider, OllamaProvider):
        try:
            logger.debug("Performing warmup call...")
            provider.generate(system_prompt, user_prompt, model=model, seed=seed)
        except Exception as e:
            logger.warning(f"Warmup call failed: {str(e)}")
    
    # Actual generation
    start_time = time.time()
    try:
        llm_response = provider.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            model=model,
            seed=seed,
        )
        end_time = time.time()
        model_response_time = end_time - start_time
        
        logger.info(f"{llm_name} took {model_response_time:.2f} seconds")
        return llm_response, model_response_time
        
    except LLMAPIError as e:
        logger.error(f"LLM API error: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during LLM generation: {str(e)}")
        raise


def run_experiment_trial(
    llm: str,
    system_prompt: str,
    user_prompt: str,
    trial_no: int,
    llm_response_sub_dir_final: str,
    language_name: str,
    source_file_name: str,
    num_functions: int,
    seed: int = 42,
    batch_num: int = -1,
    llm_responses_path: Optional[set] = None,
    api_key: Optional[str] = None,
) -> Tuple[str, float]:
    """
    Run a single experiment trial and save the response.
    
    Args:
        llm: LLM model name
        system_prompt: System prompt
        user_prompt: User prompt
        trial_no: Trial number (0-indexed)
        llm_response_sub_dir_final: Directory to save responses
        language_name: Language identifier
        source_file_name: Source file name
        num_functions: Number of functions being processed
        seed: Random seed
        batch_num: Batch number
        llm_responses_path: Set to store response file paths
        api_key: Optional API key for Mistral
    
    Returns:
        Tuple of (llm_response, response_time)
    """
    try:
        # Determine if we should use warmup (only for Ollama)
        use_warmup = not (llm.startswith("codestral-") or llm == "codestral-latest")
        
        llm_response, model_response_time = run_llm(
            llm,
            system_prompt,
            user_prompt,
            seed=seed,
            api_key=api_key,
            warmup=use_warmup,
        )
        
        model_response_time_to_write = f"Response Time: {model_response_time:.2f} seconds\n\n"
        base_file_name = f"{source_file_name}_{num_functions}_trial_{trial_no+1}_batch_{batch_num}.txt"
        file_name = os.path.join(llm_response_sub_dir_final, base_file_name)
        
        logger.info(f"Writing LLM response to: {file_name}")
        write_llm_response_to_file(
            llm_response_sub_dir_final,
            model_response_time_to_write + language_name + llm_response,
            base_file_name,
        )
        
        if llm_responses_path is not None:
            llm_responses_path.add(file_name)
        
        return llm_response, model_response_time
        
    except LLMAPIError as e:
        logger.error(f"LLM API error in trial {trial_no + 1}: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error in trial {trial_no + 1}: {str(e)}")
        raise


def generate_code_from_llm_response(
    llm_response: str,
    language: str,
    headers: List[str],
    globals: List[Any],
) -> Tuple[str, List[str], int]:
    """
    Parse LLM response and generate code information.
    
    Args:
        llm_response: Raw LLM response
        language: Programming language
        headers: Original headers
        globals: Original globals
    
    Returns:
        Tuple of (code_information, function_names, num_functions)
    """
    try:
        llm_parsed_code = parse_code(llm_response, language=language)
    except Exception as e:
        logger.error(f"Failed to parse LLM response: {str(e)}")
        raise
    
    function_names = []
    llm_code_information = ""
    
    llm_gen_headers, llm_gen_globals, llm_gen_functions, _, _ = llm_parsed_code
    
    globals_no_dict = []
    llm_gen_globals_no_dict = []
    
    # Normalize globals (handle dict format)
    for global_ in globals:
        if isinstance(global_, dict):
            globals_no_dict.append(global_["body"])
        else:
            globals_no_dict.append(global_)
    
    for global_ in llm_gen_globals:
        if isinstance(global_, dict):
            llm_gen_globals_no_dict.append(global_["body"])
        else:
            llm_gen_globals_no_dict.append(global_)
    
    # Merge headers and globals
    llm_gen_headers = list(set(headers).union(set(llm_gen_headers)))
    llm_gen_globals = list(set(globals_no_dict).union(set(llm_gen_globals_no_dict)))
    
    llm_code_information = prepend_headers_globals(llm_gen_headers, llm_gen_globals)
    
    # Add functions
    llm_num_functions = len(llm_gen_functions)
    
    for i in range(llm_num_functions):
        function_names.append(llm_gen_functions[i]["name_only"])
        llm_code_information += llm_gen_functions[i]["body"] + "\n"
    
    return llm_code_information, function_names, llm_num_functions


def verify_mapping_structure(mapping: str, error_message: str) -> Optional[Tuple[str, str]]:
    """
    Verify and extract mapping structure from LLM response.
    
    Args:
        mapping: Mapping string in format "original:replacer|variant1|variant2"
        error_message: Error message to display if parsing fails
    
    Returns:
        Tuple of (target_func_name, replacer_func_name) or None if invalid
    """
    target_func_name_from_mapping = None
    replacer_func_name_from_mapping = None
    
    try:
        # Format: 'original_func_name: replacer_variant_func_name|variant_func_name1|...'
        mapping_list = mapping.split(":")
        
        if len(mapping_list) != 2:
            logger.warning("Mapping information is not in the correct format")
            return None
        
        target_func_name_from_mapping = mapping_list[0].strip()
        replacer_func_name_from_mapping = mapping_list[1].split("|")[0].strip()
        
        return target_func_name_from_mapping, replacer_func_name_from_mapping
        
    except Exception as e:
        logger.error(f"{error_message}: {str(e)}")
        logger.error(f"Mapping Information: {mapping}")
        return None

