# First parameter of a method is not named 'self'
Normal methods should have at least one parameter and the first parameter should be called `self`.


## Recommendation
Ensure that the first parameter of a normal method is named `self`, as recommended by the style guidelines in PEP 8.

If a `self` parameter is unneeded, the method should be decorated with `staticmethod`, or moved out of the class as a regular function.


## Example
In the following cases, the first argument of `Point.__init__` is named `val` instead; whereas in `Point2.__init__` it is correctly named `self`.


```python
class Point:
    def __init__(val, x, y):  # BAD: first parameter is mis-named 'val'
        val._x = x
        val._y = y

class Point2:
    def __init__(self, x, y):  # GOOD: first parameter is correctly named 'self'
        self._x = x
        self._y = y
```

## References
* Python PEP 8: [Function and method arguments](http://www.python.org/dev/peps/pep-0008/#function-and-method-arguments).
* Python Tutorial: [Classes](http://docs.python.org/2/tutorial/classes.html).
* Python Docs: [staticmethod](https://docs.python.org/3/library/functions.html#staticmethod).
