# threading_utils.py
import asyncio
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from functools import partial
import time

# Create a thread pool
thread_pool = ThreadPoolExecutor(max_workers=10)

async def run_in_thread(func, *args, timeout: int = 30):
    """
    Run a synchronous function in a thread pool with timeout
    """
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(thread_pool, partial(func, *args)),
            timeout=timeout
        )
        return result
    except TimeoutError:
        print(f"[TIMEOUT] Function {func.__name__} timed out after {timeout}s")
        return {"error": "Timeout", "status": "timeout"}
    except Exception as e:
        print(f"[ERROR] Thread execution failed: {str(e)}")
        return {"error": str(e)}

# For batch processing multiple URLs
async def process_batch(urls: list, check_func, max_concurrent: int = 5):
    """
    Process multiple URLs concurrently with semaphore limiting
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def process_with_limit(url):
        async with semaphore:
            return await check_func(url)
    
    tasks = [process_with_limit(url) for url in urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    return results