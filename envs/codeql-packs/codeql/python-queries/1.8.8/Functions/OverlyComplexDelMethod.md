# Overly complex `__del__` method
The `__del__` method exists to release any resources held by an object when that object is deleted. The `__del__` is called only by the garbage collector which may call it after an indefinite delay or never.

Consequently, `__del__` method should not be relied on to release resources, such as file descriptors. Rather, these resources should be released explicitly.

The existence of a complex `__del__` method suggests that this is the main or only way to release resources associated with the object.


## Recommendation
In order to ensure correct cleanup of the object add an explicit close(), or similar, method. Possibly make the object a context manager.

The __del__ method should just call close()


## Example
The first example below shows a class which relies on `__del__` to release resources. The second example shows an improved version of the class where `__del__` simply calls close.


```python

#Relies on __del__ being called by the garbage collector.
class CachedPreferencesFile

    ...

    def __del__(self):
        for key, value in self.preferences.items():
            self.write_pair(key, value)
        self.backing.close()


#Better version
class CachedPreferencesFile

    ...

    def close(self):
        for key, value in self.preferences.items():
            self.write_pair(key, value)
        self.backing.close()

    def __del__(self):
        self.close()

```

## References
* Python Standard Library: [Context manager](http://docs.python.org/library/stdtypes.html#context-manager-types).
