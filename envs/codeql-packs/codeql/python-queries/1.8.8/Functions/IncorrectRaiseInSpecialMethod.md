# Non-standard exception raised in special method
User-defined classes interact with the Python virtual machine via special methods (also called "magic methods"). For example, for a class to support addition it must implement the `__add__` and `__radd__` special methods. When the expression `a + b` is evaluated, the Python virtual machine will call `type(a).__add__(a, b)`, and if that is not implemented it will call `type(b).__radd__(b, a)`.

Since the virtual machine calls these special methods for common expressions, users of the class will expect these operations to raise standard exceptions. For example, users would expect that the expression `a.b` may raise an `AttributeError` if the object `a` does not have an attribute `b`. If a `KeyError` were raised instead, then this would be unexpected and may break code that expected an `AttributeError`, but not a `KeyError`.

Therefore, if a method is unable to perform the expected operation then its response should conform to the standard protocol, described below.

* Attribute access, `a.b` (`__getattr__`): Raise `AttributeError`.
* Arithmetic operations, `a + b` (`__add__`): Do not raise an exception, return `NotImplemented` instead.
* Indexing, `a[b]` (`__getitem__`): Raise `KeyError` or `IndexError`.
* Hashing, `hash(a)` (`__hash__`): Should not raise an exception. Use `__hash__ = None` to indicate that an object is unhashable rather than raising an exception.
* Equality methods, `a == b` (`__eq__`): Never raise an exception, always return `True` or `False`.
* Ordering comparison methods, `a < b` (`__lt__`): Raise a `TypeError` if the objects cannot be ordered.
* Most others: If the operation is never supported, the method often does not need to be implemented at all; otherwise a `TypeError` should be raised.

## Recommendation
If the method always raises as exception, then if it is intended to be an abstract method, the `@abstractmethod` decorator should be used. Otherwise, ensure that the method raises an exception of the correct type, or remove the method if the operation does not need to be supported.


## Example
In the following example, the `__add__` method of `A` raises a `TypeError` if `other` is of the wrong type. However, it should return `NotImplemented` instead of rising an exception, to allow other classes to support adding to `A`. This is demonstrated in the class `B`.


```python
class A:
    def __init__(self, a):
        self.a = a 

    def __add__(self, other):
        # BAD: Should return NotImplemented instead of raising
        if not isinstance(other,A):
            raise TypeError(f"Cannot add A to {other.__class__}")
        return A(self.a + other.a)

class B:
    def __init__(self, a):
        self.a = a 

    def __add__(self, other):
        # GOOD: Returning NotImplemented allows for the operation to fallback to other implementations to allow other classes to support adding to B.
        if not isinstance(other,B):
            return NotImplemented
        return B(self.a + other.a)
    

        

```
In the following example, the `__getitem__` method of `C` raises a `ValueError`, rather than a `KeyError` or `IndexError` as expected.


```python
class C:
    def __getitem__(self, idx):
        if self.idx < 0:
            # BAD: Should raise a KeyError or IndexError instead.
            raise ValueError("Invalid index")
        return self.lookup(idx)
 

```
In the following example, the class `__hash__` method of `D` raises `NotImplementedError`. This causes `D` to be incorrectly identified as hashable by `isinstance(obj, collections.abc.Hashable)`; so the correct way to make a class unhashable is to set `__hash__ = None`.


```python
class D:
    def __hash__(self):
        # BAD: Use `__hash__ = None` instead.
        raise NotImplementedError(f"{self.__class__} is unhashable.")
```

## References
* Python Language Reference: [Special Method Names](http://docs.python.org/dev/reference/datamodel.html#special-method-names).
* Python Library Reference: [Exceptions](https://docs.python.org/3/library/exceptions.html).
