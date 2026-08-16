# Class should be a context manager
If a class has a `close()` or similar method to release resources, then it should be made a context manager. Using a context manager allows instances of the class to be used in the `with` statement, improving code size and readability. This is a simpler and more reliable method than implementing just a `__del__` method.


## Recommendation
The context manager requires an `__enter__` and an `__exit__` method:

* `__enter__` method acquires the resource or does nothing if the resource is acquired in the `__init__` method
* `__exit__` method releases the resource, this can just be a simple wrapper around the `close` method.

## Example
The following example shows how a class definition that implements `__del__` can be updated to use a context manager.


```python
class remotelock(object):     # Resources can be released using __del__

    def __init__(self, repo):
        self.repo = repo

    def release(self):
        self.repo.unlock()
        self.repo = None

    def __del__(self):
        if self.repo:
            self.release()


class remotelock2(object):     # Resources can be released using a with statement

    def __init__(self, repo):
        self.repo = repo

    def __enter__(self):
        return self

    def release(self):
        self.repo.unlock()
        self.repo = None
        
    def __del__(self):
        if self.repo:
            self.release()

    def __exit__(self, exct_type, exce_value, traceback):
        if self.repo:
            self.release()

```

## References
* Effbot: [Python with statement](https://web.archive.org/web/20201012110738/http://effbot.org/zone/python-with-statement.htm).
* Python Standard Library: [Context manager ](http://docs.python.org/library/stdtypes.html#context-manager-types).
* Python Language Reference: [ With Statement Context Managers](http://docs.python.org/2.7/reference/datamodel.html#with-statement-context-managers).
* Python PEP 343: [The "with" Statement](http://www.python.org/dev/peps/pep-0343).
