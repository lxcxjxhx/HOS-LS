# Iterator does not return self from `__iter__` method
Iterator classes (classes defining a `__next__` method) should have an `__iter__` method that returns the iterator itself. This ensures that the object is also an iterable; and behaves as expected when used anywhere an iterator or iterable is expected, such as in `for` loops.


## Recommendation
Ensure that the `__iter__` method returns `self`, or is otherwise equivalent as an iterator to `self`.


## Example
In the following example, the `MyRange` class's `__iter__` method does not return `self`. This would lead to unexpected results when used with a `for` loop or `in` statement.


```python
class MyRange(object):
    def __init__(self, low, high):
        self.current = low
        self.high = high

    def __iter__(self):
        return (self.current, self.high) # BAD: does not return `self`.

    def __next__(self):
        if self.current > self.high:
            return None
        self.current += 1
        return self.current - 1
```

## References
* Python Language Reference: [object.__iter__](http://docs.python.org/3/reference/datamodel.html#object.__iter__).
* Python Standard Library: [Iterators](http://docs.python.org/3/library/stdtypes.html#typeiter).
