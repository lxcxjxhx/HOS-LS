# First parameter of a class method is not named 'cls'
The first parameter of a class method (including certain special methods such as `__new__`), or a method of a metaclass, should be named `cls`.


## Recommendation
Ensure that the first parameter of class methods is named `cls`, as recommended by the style guidelines in PEP 8.


## Example
In the following example, the first parameter of the class method `make` is named `self` instead of `cls`.


```python
class Entry(object):
    @classmethod
    def make(self):
        return Entry()

```

## References
* Python PEP 8: [Function and method arguments](http://www.python.org/dev/peps/pep-0008/#function-and-method-arguments).
* Python Tutorial: [Classes](http://docs.python.org/2/tutorial/classes.html).
* Python Docs: [classmethod](https://docs.python.org/3/library/functions.html#classmethod).
