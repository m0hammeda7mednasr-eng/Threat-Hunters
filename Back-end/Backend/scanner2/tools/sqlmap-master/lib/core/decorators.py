import functools
import threading

from lib.core.datatype import LRUDict
from lib.core.settings import MAX_CACHE_ITEMS
from lib.core.threads import getCurrentThreadData

_cache = {}
_method_locks = {}

def cachedmethod(f):

    _cache[f] = LRUDict(capacity=MAX_CACHE_ITEMS)
    _method_locks[f] = threading.RLock()

    def _freeze(val):
        if isinstance(val, (list, set, tuple)):
            return tuple(_freeze(x) for x in val)
        if isinstance(val, dict):
            return tuple(sorted((k, _freeze(v)) for k, v in val.items()))
        return val

    @functools.wraps(f)
    def _f(*args, **kwargs):
        lock, cache = _method_locks[f], _cache[f]

        try:
            if kwargs:
                key = (args, frozenset(kwargs.items()))
            else:
                key = args

            with lock:
                if key in cache:
                    return cache[key]

        except TypeError:
            if kwargs:
                key = (_freeze(args), _freeze(kwargs))
            else:
                key = _freeze(args)

            with lock:
                if key in cache:
                    return cache[key]

        result = f(*args, **kwargs)

        with lock:
            cache[key] = result

        return result

    return _f

def stackedmethod(f):

    @functools.wraps(f)
    def _(*args, **kwargs):
        threadData = getCurrentThreadData()
        originalLevel = len(threadData.valueStack)

        try:
            result = f(*args, **kwargs)
        finally:
            if len(threadData.valueStack) > originalLevel:
                del threadData.valueStack[originalLevel:]

        return result

    return _

def lockedmethod(f):

    lock = threading.RLock()

    @functools.wraps(f)
    def _(*args, **kwargs):
        with lock:
            result = f(*args, **kwargs)
        return result

    return _
