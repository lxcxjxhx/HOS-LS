# Inconsistent equality and hashing
A hashable class has an `__eq__` method, and a `__hash__` method that agrees with equality. When a hash method is defined, an equality method should also be defined; otherwise object identity is used for equality comparisons which may not be intended.

Note that defining an `__eq__` method without defining a `__hash__` method automatically makes the class unhashable in Python 3. (even if a superclass defines a hash method).


## Recommendation
If a `__hash__` method is defined, ensure a compatible `__eq__` method is also defined.

To explicitly declare a class as unhashable, set `__hash__ = None`, rather than defining a `__hash__` method that always raises an exception. Otherwise, the class would be incorrectly identified as hashable by an `isinstance(obj, collections.abc.Hashable)` call.


## Example
In the following example, the `A` class defines an hash method but no equality method. Equality will be determined by object identity, which may not be the expected behaviour.


```python
class A:
    def __init__(self, a, b):
        self.a = a 
        self.b = b

    # No equality method is defined
    def __hash__(self):
        return hash((self.a, self.b))

```

## References
* Python Language Reference: [object.__hash__](http://docs.python.org/reference/datamodel.html#object.__hash__).
* Python Glossary: [hashable](http://docs.python.org/3/glossary.html#term-hashable).
* Common Weakness Enumeration: [CWE-581](https://cwe.mitre.org/data/definitions/581.html).
