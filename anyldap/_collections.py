from collections.abc import MutableMapping


class InsensitiveDict(MutableMapping):
    def __init__(self, initial=None):
        self.data = {}
        if initial is not None:
            self.update(initial)

    def _normalize(self, key):
        try:
            return key.lower()
        except AttributeError:
            return key

    def __getitem__(self, key):
        return self.data[self._normalize(key)][1]

    def __setitem__(self, key, value):
        self.data[self._normalize(key)] = (key, value)

    def __delitem__(self, key):
        del self.data[self._normalize(key)]

    def __iter__(self):
        return self.iterkeys()

    def __len__(self):
        return len(self.data)

    def __contains__(self, key):
        return self._normalize(key) in self.data

    def get(self, key, default=None):
        item = self.data.get(self._normalize(key))
        if item is None:
            return default
        return item[1]

    def items(self):
        return [(key, value) for key, value in self.data.values()]

    def keys(self):
        return [key for key, _ in self.data.values()]

    def values(self):
        return [value for _, value in self.data.values()]

    def iterkeys(self):
        for key, _ in self.data.values():
            yield key
