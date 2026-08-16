# Special method has incorrect signature
Special methods (sometimes also called magic methods) are how user defined classes interact with the Python virtual machine. For example, for a class to support addition it must implement the `__add__` and `__radd__` special methods. When the expression `a + b` is evaluated the Python virtual machine will call `type(a).__add__(a, b)` and if that is not implemented it will call `type(b).__radd__(b, a)`.

Since these special methods are always called by the virtual machine with a fixed number of parameters, if the method is implemented with a different number of parameters it will fail at runtime with a `TypeError`.


## Recommendation
Ensure that the method has the correct number of parameters


## Example
In the example the `__str__` method has an extra parameter. This means that if `str(p)` is called when `p` is a `Point` then it will fail with a `TypeError`.


```python
#-*- coding: utf-8 -*-

class Point(object):

    def __init__(self, x, y):
        self.x
        self.y

    def __add__(self, other):
        if not isinstance(other, Point):
            return NotImplemented
        return Point(self.x + other.x, self.y + other.y)

    def __str__(self, style): #Spurious extra parameter
        if style == 'polar':
            u"%s @ %s\u00b0" % (abs(self), self.angle())
        else:
            return "[%s, %s]" % (self.x, self.y)

```

## References
* Python Language Reference: [Special Method Names](http://docs.python.org/dev/reference/datamodel.html#special-method-names).
