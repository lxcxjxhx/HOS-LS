# `__iter__` method returns a non-iterator
The `__iter__` method of a class should always return an iterator.

Iterators must implement both `__next__` and `__iter__` for Python 3, or both `next` and `__iter__` for Python 2. The `__iter__` method of the iterator must return the iterator object itself.

Iteration in Python relies on this behavior and attempting to iterate over an instance of a class with an incorrect `__iter__` method can raise a `TypeError`.


## Recommendation
Make sure the value returned by `__iter__` implements the full iterator protocol.


## Example
In this example, we have implemented our own version of `range`, extending the normal functionality with the ability to skip some elements by using the `skip` method. However, the iterator `MyRangeIterator` does not fully implement the iterator protocol (namely it is missing `__iter__`).

Iterating over the elements in the range seems to work on the surface, for example the code `x = sum(my_range)` gives the expected result. However, if we run `sum(iter(my_range))` we get a `TypeError: 'MyRangeIterator' object is not iterable`.

If we try to skip some elements using our custom method, for example `y = sum(my_range.skip({6,9}))`, this also raises a `TypeError`.

The fix is to implement the `__iter__` method in `MyRangeIterator`.


```python
class MyRange(object):
    def __init__(self, low, high):
        self.low = low
        self.high = high

    def __iter__(self):
        return MyRangeIterator(self.low, self.high)

    def skip(self, to_skip):
        return MyRangeIterator(self.low, self.high, to_skip)

class MyRangeIterator(object):
    def __init__(self, low, high, skip=None):
        self.current = low
        self.high = high
        self.skip = skip

    def __next__(self):
        if self.current >= self.high:
            raise StopIteration
        to_return = self.current
        self.current += 1
        if self.skip and to_return in self.skip:
            return self.__next__()
        return to_return

    # Problem is fixed by uncommenting these lines
    # def __iter__(self):
    #     return self

my_range = MyRange(0,10)
x = sum(my_range) # x = 45
y = sum(my_range.skip({6,9})) # TypeError: 'MyRangeIterator' object is not iterable

```

## References
* Python Language Reference: [object.__iter__](https://docs.python.org/3/reference/datamodel.html#object.__iter__).
* Python Standard Library: [Iterator Types](https://docs.python.org/3/library/stdtypes.html#typeiter).
