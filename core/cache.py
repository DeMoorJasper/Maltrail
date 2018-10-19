MAX_RESULT_CACHE_ENTRIES = 10000

result_cache = {}

def checkCache():
  if len(result_cache) > MAX_RESULT_CACHE_ENTRIES:
        result_cache.clear()