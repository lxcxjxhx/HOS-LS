# `__slots__` in old-style class
The ability to override the class dictionary using a `__slots__` declaration is supported only by new-style classes. When you add a `__slots__` declaration to an old-style class it just creates a class attribute called `__slots__`.


## Recommendation
If you want to override the dictionary for a class, then ensure that the class is a new-style class. You can convert an old-style class to a new-style class by inheriting from `object`.


## Example
In the following Python 2 example the `Point` class is an old-style class (no inheritance). The `__slots__` declaration in this class creates a class attribute called `__slots__`, the class dictionary is unaffected. The `Point2` class is a new-style class so the `__slots__` declaration causes special compact attributes to be created for each name in the slots list and saves space by not creating attribute dictionaries.


```python
class Point:

    __slots__ = [ '_x', '_y' ] # Incorrect: 'Point' is an old-style class.
                               # No slots are created.
                               # Instances of Point have an attribute dictionary.

    def __init__(self, x, y):
        self._x = x
        self._y = y


class Point2(object):

    __slots__ = [ '_x', '_y' ] # Correct: 'Point2' is an new-style class
                               # Two slots '_x' and '_y' are created.
                               # Instances of Point2 have no attribute dictionary.

    def __init__(self, x, y):
        self._x = x
        self._y = y

```

## References
* Python Glossary: [New-style class](http://docs.python.org/glossary.html#term-new-style-class).
* Python Language Reference: [New-style and classic classes](http://docs.python.org/2/reference/datamodel.html#newstyle), [__slots__](http://docs.python.org/reference/datamodel.html#__slots__).
