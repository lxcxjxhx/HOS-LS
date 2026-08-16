# `__init__` method is a generator
The `__init__` method of a class is used to initialize new objects, not create them. As such, it should not return any value. By including a `yield` expression in the method turns it into a generator method. On calling it will return a generator resulting in a runtime error.


## Recommendation
The presence of a `yield` expression in an `__init__` method suggests a logical error, so it is not possible to suggest a general fix.


## Example
In this example the `__init__` method contains a yield expression. This is not logical in the context of an initializer.


```python
class InitIsGenerator(object):
    def __init__(self, i):
        yield i
```

## References
* Python: [The __init__ method](http://docs.python.org/3/reference/datamodel.html#object.__init__).
