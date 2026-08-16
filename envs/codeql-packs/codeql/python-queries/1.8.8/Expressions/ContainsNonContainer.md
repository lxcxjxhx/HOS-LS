# Membership test with a non-container
A membership test, that is a binary expression with `in` or `not in` as the operator, expects that the expression to the right of the operator will be a container.

As well as standard containers such as `list`, `tuple`, `dict` or `set`, a container can be an instance of any class that has the `__contains__`, `__iter__` or `__getitem__` method.


## Recommendation
Ensure that the right hand side of the expression is a container, or add a guard clause for other cases. For example, if the right side may be a container or `None` then change `if x in seq:` to `if seq is not None and x in seq:`


## Example
In this example the `NotAContainer` class has no `__contains__`, `__iter__` or `__getitem__` method. Consequently, when the line `if 2 in cont:` is executed a TypeError will be raised. Adding a `__getitem__` method to the `NotAContainer` class would solve the problem.


```python
class NotAContainer(object):

    def __init__(self, *items):
        self.items = items

def main():
    cont = NotAContainer(1, 2, 3)
    if 2 in cont:
        print("2 in container")

```

## References
* Python: [Membership test details](http://docs.python.org/reference/expressions.html#membership-test-details).
* Python: [The __contains__ method](http://docs.python.org/reference/datamodel.html#object.__contains__).
