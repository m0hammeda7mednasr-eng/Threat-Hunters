import copy
import threading
import types

from thirdparty.odict import OrderedDict
from thirdparty.six.moves import collections_abc as _collections

class AttribDict(dict):

    def __init__(self, indict=None, attribute=None, keycheck=True):
        if indict is None:
            indict = {}

        dict.__init__(self, indict)
        self.__dict__["_attribute"] = attribute
        self.__dict__["_keycheck"] = keycheck
        self.__dict__["_initialized"] = True

    def __getattr__(self, item):
        if item.startswith('__') and item.endswith('__'):
             raise AttributeError(item)

        try:
            return self.__getitem__(item)
        except KeyError:
            if self.__dict__.get("_keycheck"):
                raise AttributeError("unable to access item '%s'" % item)
            else:
                return None

    def __delattr__(self, item):

        try:
            return self.pop(item)
        except KeyError:
            if self.__dict__.get("_keycheck"):
                raise AttributeError("unable to access item '%s'" % item)
            else:
                return None

    def __setattr__(self, item, value):

        if "_initialized" not in self.__dict__ or item in self.__dict__:
            self.__dict__[item] = value
        else:
            self.__setitem__(item, value)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, dict):
        self.__dict__ = dict

    def __deepcopy__(self, memo):
        retVal = self.__class__(keycheck=self.__dict__.get("_keycheck"))
        memo[id(self)] = retVal

        for attr, value in self.__dict__.items():
            if attr not in ('_attribute', '_keycheck', '_initialized'):
                setattr(retVal, attr, copy.deepcopy(value, memo))

        for key, value in self.items():
            retVal.__setitem__(key, copy.deepcopy(value, memo))

        return retVal

class InjectionDict(AttribDict):
    def __init__(self, **kwargs):
        AttribDict.__init__(self, **kwargs)

        self.place = None
        self.parameter = None
        self.ptype = None
        self.prefix = None
        self.suffix = None
        self.clause = None
        self.notes = []  # Note: https://github.com/sqlmapproject/sqlmap/issues/1888

        self.data = AttribDict()

        self.conf = AttribDict()

        self.dbms = None
        self.dbms_version = None
        self.os = None

class LRUDict(object):

    def __init__(self, capacity):
        self.capacity = capacity
        self.cache = OrderedDict()
        self.__lock = threading.Lock()

    def __len__(self):
        return len(self.cache)

    def __contains__(self, key):
        return key in self.cache

    def __getitem__(self, key):
        with self.__lock:
            value = self.cache.pop(key)
            self.cache[key] = value
            return value

    def get(self, key, default=None):
        try:
            return self.__getitem__(key)
        except:
            return default

    def __setitem__(self, key, value):
        with self.__lock:
            try:
                self.cache.pop(key)
            except KeyError:
                if len(self.cache) >= self.capacity:
                    self.cache.popitem(last=False)
            self.cache[key] = value

    def set(self, key, value):
        self.__setitem__(key, value)

    def keys(self):
        return self.cache.keys()

class OrderedSet(_collections.MutableSet):

    def __init__(self, iterable=None):
        self.end = end = []
        end += [None, end, end]         # sentinel node for doubly linked list
        self.map = {}                   # key --> [key, prev, next]
        if iterable is not None:
            self |= iterable

    def __len__(self):
        return len(self.map)

    def __contains__(self, key):
        return key in self.map

    def add(self, value):
        if value not in self.map:
            end = self.end
            curr = end[1]
            curr[2] = end[1] = self.map[value] = [value, curr, end]

    def discard(self, value):
        if value in self.map:
            value, prev, next = self.map.pop(value)
            prev[2] = next
            next[1] = prev

    def __iter__(self):
        end = self.end
        curr = end[2]
        while curr is not end:
            yield curr[0]
            curr = curr[2]

    def __reversed__(self):
        end = self.end
        curr = end[1]
        while curr is not end:
            yield curr[0]
            curr = curr[1]

    def pop(self, last=True):
        if not self:
            raise KeyError('set is empty')
        key = self.end[1][0] if last else self.end[2][0]
        self.discard(key)
        return key

    def __repr__(self):
        if not self:
            return '%s()' % (self.__class__.__name__,)
        return '%s(%r)' % (self.__class__.__name__, list(self))

    def __eq__(self, other):
        if isinstance(other, OrderedSet):
            return len(self) == len(other) and list(self) == list(other)
        return set(self) == set(other)
