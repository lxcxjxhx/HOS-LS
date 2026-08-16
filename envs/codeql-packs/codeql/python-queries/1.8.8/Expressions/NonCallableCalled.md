# Non-callable called
If an object is called, `obj()`, then that object must be a callable or a `TypeError` will be raised. A callable object is any object whose class defines the `__call__` special method. Callable objects include functions, methods, classes.

The `callable(object)` builtin function determines if an object is callable or not.

When the Python interpreter attempts to evaluate a call such as `func(arg)` it will invoke the `__call__` special method on `func`. Thus, `func(arg)` is roughly equivalent to `type(func).__call__(func, arg)` which means that the *class* must define the attribute `__call__`, merely adding it to the instance is not sufficient.


## Recommendation
Since this problem usually indicates a logical error, it is not possible to give a general recipe for fixing it.


## Example
`list`s are not callable. In this example, an attempt is made to call a `list` which will fail with a `TypeError`.


```python
a_list = []
a_list()

```

## References
* Python Standard Library: [callable](http://docs.python.org/2/library/functions.html#callable).
* Python Language Reference: [object.__call__](http://docs.python.org/2/reference/datamodel.html#object.__call__).
