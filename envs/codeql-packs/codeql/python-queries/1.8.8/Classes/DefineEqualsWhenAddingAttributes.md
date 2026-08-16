# `__eq__` not overridden when adding attributes
A class that defines attributes that are not present in its superclasses may need to override the `__eq__()` method (`__ne__()` should also be defined).

Adding additional attributes without overriding `__eq__()` means that the additional attributes will not be accounted for in equality tests.


## Recommendation
Override the `__eq__` method.


## Example
In the following example the `ColorPoint` class subclasses the `Point` class and adds a new attribute, but does not override the `__eq__` method.


```python
class Point(object):

    def __init__(self, x, y):
        self._x = x
        self._y = y

    def __repr__(self):
        return 'Point(%r, %r)' % (self._x, self._y)

    def __eq__(self, other):
        if not isinstance(other, Point):
            return False
        return self._x == other._x and self._y == other._y

class ColorPoint(Point):

    def __init__(self, x, y, color):
        Point.__init__(self, x, y)
        self._color = color

    def __repr__(self):
        return 'ColorPoint(%r, %r)' % (self._x, self._y, self._color)

#ColorPoint(0, 0, Red) == ColorPoint(0, 0, Green) should be False, but is True.

#Fixed version
class ColorPoint(Point):

    def __init__(self, x, y, color):
        Point.__init__(self, x, y)
        self._color = color

    def __repr__(self):
        return 'ColorPoint(%r, %r)' % (self._x, self._y, self._color)

    def __eq__(self, other):
        if not isinstance(other, ColorPoint):
            return False
        return Point.__eq__(self, other) and self._color = other._color


```

## References
* Peter Grogono, Philip Santas: [Equality in Object Oriented Languages](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.48.5109&rep=rep1&type=pdf)
