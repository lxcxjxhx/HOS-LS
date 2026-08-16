# Property in old-style class
Property descriptors are only supported for the new-style classes that were introduced in Python 2.1. Property descriptors should only be used in new-style classes.


## Recommendation
If you want to define properties in a class, then ensure that the class is a new-style class. You can convert an old-style class to a new-style class by inheriting from `object`.


## Example
In the following example all the classes attempt to set a property for `x`. However, only the third and fourth classes are new-style classes. Consequently, the `x` property is only available for the `NewStyle` and `InheritNewStyle` classes.

If you define the `OldStyle` class as inheriting from a new-style class, then the `x ` property would be available for both the `OldStyle` and `InheritOldStyle` classes.


```python

class OldStyle:

    def __init__(self, x):
        self._x = x

    # Incorrect: 'OldStyle' is not a new-style class and '@property' is not supported
    @property
    def x(self):
        return self._x


class InheritOldStyle(OldStyle):

    def __init__(self, x):
        self._x = x

    # Incorrect: 'InheritOldStyle' is not a new-style class and '@property' is not supported
    @property
    def x(self):
        return self._x


class NewStyle(object):

    def __init__(self, x):
        self._x = x

    # Correct: 'NewStyle' is a new-style class and '@property' is supported
    @property
    def x(self):
        return self._x

class InheritNewStyle(NewStyle):

    def __init__(self, x):
        self._x = x

    # Correct: 'InheritNewStyle' inherits from a new-style class and '@property' is supported
    @property
    def x(self):
        return self._x

```

## References
* Python Glossary: [New-style class](http://docs.python.org/glossary.html#term-new-style-class).
* Python Language Reference: [New-style and classic classes](http://docs.python.org/2/reference/datamodel.html#newstyle), [ Descriptors](http://docs.python.org/2/reference/datamodel.html#implementing-descriptors).
* Python Standard Library: [Property](http://docs.python.org/library/functions.html#property).
* The History of Python: [ Inside story on new-style classes](http://python-history.blogspot.co.uk/2010/06/inside-story-on-new-style-classes.html).
