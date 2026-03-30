"""
Parallel processing for LLMalMorph.
Supports async processing and parallel function mutations.
"""
import asyncio
import logging
from typing import List, Dict, Callable, Any, Optional
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import time

logger = logging.getLogger(__name__)


class ParallelProcessor:
    """
    Parallel processor for mutating multiple functions.
    Supports both async and threaded execution.
    """
    
    def __init__(self, max_workers: int = 4, use_threads: bool = True):
        """
        Initialize parallel processor.
        
        Args:
            max_workers: Maximum number of parallel workers
            use_threads: Use threads (True) or processes (False)
        """
        self.max_workers = max_workers
        self.use_threads = use_threads
        self.executor_class = ThreadPoolExecutor if use_threads else ProcessPoolExecutor
        
        logger.info(
            f"Initialized parallel processor: "
            f"max_workers={max_workers}, use_threads={use_threads}"
        )
    
    async def process_async(
        self,
        items: List[Any],
        process_func: Callable,
        *args,
        **kwargs
    ) -> List[Any]:
        """
        Process items asynchronously.
        
        Args:
            items: List of items to process
            process_func: Async function to process each item
            *args, **kwargs: Additional arguments for process_func
        
        Returns:
            List of results
        """
        tasks = [process_func(item, *args, **kwargs) for item in items]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Error processing item {i}: {result}")
                processed_results.append(None)
            else:
                processed_results.append(result)
        
        return processed_results
    
    def process_parallel(
        self,
        items: List[Any],
        process_func: Callable,
        *args,
        **kwargs
    ) -> List[Any]:
        """
        Process items in parallel using thread/process pool.
        
        Args:
            items: List of items to process
            process_func: Function to process each item
            *args, **kwargs: Additional arguments for process_func
        
        Returns:
            List of results
        """
        results = [None] * len(items)
        
        with self.executor_class(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_index = {
                executor.submit(process_func, item, *args, **kwargs): i
                for i, item in enumerate(items)
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    results[index] = future.result()
                except Exception as e:
                    logger.error(f"Error processing item {index}: {e}")
                    results[index] = None
        
        return results
    
    def process_batch(
        self,
        items: List[Any],
        process_func: Callable,
        batch_size: Optional[int] = None,
        *args,
        **kwargs
    ) -> List[Any]:
        """
        Process items in batches.
        
        Args:
            items: List of items to process
            process_func: Function to process each item
            batch_size: Batch size (default: max_workers)
            *args, **kwargs: Additional arguments for process_func
        
        Returns:
            List of results
        """
        if batch_size is None:
            batch_size = self.max_workers
        
        results = []
        
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            logger.debug(f"Processing batch {i // batch_size + 1} ({len(batch)} items)")
            
            batch_results = self.process_parallel(batch, process_func, *args, **kwargs)
            results.extend(batch_results)
        
        return results


async def mutate_function_async(
    function_data: Dict,
    llm_provider,
    system_prompt: str,
    user_prompt_template: str = None,
) -> Dict:
    """
    Async function to mutate a single function.
    
    Args:
        function_data: Function data dictionary
        llm_provider: LLM provider instance
        system_prompt: System prompt
        user_prompt_template: Optional prompt template
    
    Returns:
        Mutation result dictionary
    """
    func_name = function_data.get('name', 'unknown')
    func_body = function_data.get('body', '')
    
    if user_prompt_template:
        user_prompt = user_prompt_template.format(
            function_name=func_name,
            function_body=func_body,
        )
    else:
        user_prompt = f"Mutate this function: {func_body}"
    
    try:
        # Run LLM call in thread pool (since LLM API might be sync)
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: llm_provider.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
        )
        
        return {
            'function': func_name,
            'success': True,
            'response': response,
            'original_body': func_body,
        }
    
    except Exception as e:
        logger.error(f"Error mutating function {func_name}: {e}")
        return {
            'function': func_name,
            'success': False,
            'error': str(e),
            'original_body': func_body,
        }


def mutate_function_sync(
    function_data: Dict,
    llm_provider,
    system_prompt: str,
    user_prompt_template: str = None,
) -> Dict:
    """
    Sync function to mutate a single function.
    
    Args:
        function_data: Function data dictionary
        llm_provider: LLM provider instance
        system_prompt: System prompt
        user_prompt_template: Optional prompt template
    
    Returns:
        Mutation result dictionary
    """
    func_name = function_data.get('name', 'unknown')
    func_body = function_data.get('body', '')
    
    if user_prompt_template:
        user_prompt = user_prompt_template.format(
            function_name=func_name,
            function_body=func_body,
        )
    else:
        user_prompt = f"Mutate this function: {func_body}"
    
    try:
        response = llm_provider.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
        
        return {
            'function': func_name,
            'success': True,
            'response': response,
            'original_body': func_body,
        }
    
    except Exception as e:
        logger.error(f"Error mutating function {func_name}: {e}")
        return {
            'function': func_name,
            'success': False,
            'error': str(e),
            'original_body': func_body,
        }

