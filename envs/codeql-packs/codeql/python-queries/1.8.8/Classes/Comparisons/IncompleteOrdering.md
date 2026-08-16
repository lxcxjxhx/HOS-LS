# Incomplete ordering
A class that implements the rich comparison operators (`__lt__`, `__gt__`, `__le__`, or `__ge__`) should ensure that all four comparison operations `<`, `<=`, `>`, and `>=` function as expected, consistent with expected mathematical rules. In Python 3, this is ensured by implementing one of `__lt__` or `__gt__`, and one of `__le__` or `__ge__`. If the ordering is not consistent with default equality, then `__eq__` should also be implemented.


## Recommendation
Ensure that at least one of `__lt__` or `__gt__` and at least one of `__le__` or `__ge__` is defined.

The `functools.total_ordering` class decorator can be used to automatically implement all four comparison methods from a single one, which is typically the cleanest way to ensure all necessary comparison methods are implemented consistently.


## Example
In the following example, only the `__lt__` operator has been implemented, which would lead to unexpected errors if the `<=` or `>=` operators are used on `A` instances. The `__le__` method should also be defined, as well as `__eq__` in this case.


```python
class A:
    def __init__(self, i):
        self.i = i

    # BAD: le is not defined, so `A(1) <= A(2)` would result in an error.
    def __lt__(self, other):
        return self.i < other.i
    
```

## References
* Python Language Reference: [Rich comparisons in Python](http://docs.python.org/3/reference/datamodel.html#object.__lt__).
