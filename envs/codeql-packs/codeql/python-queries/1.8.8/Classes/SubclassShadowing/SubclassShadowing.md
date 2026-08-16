# Superclass attribute shadows subclass method
When an object has an attribute that shares its name with a method on the object's class (or another class attribute), the instance attribute is prioritized during attribute lookup, shadowing the method. If a method on a subclass is shadowed by an attribute on a superclass in this way, this may lead to unexpected results or errors, as this shadowing behavior is nonlocal and may be unintended.


## Recommendation
Ensure method names on subclasses don't conflict with attribute names on superclasses, and rename one. If the shadowing behavior is intended, ensure this is explicit in the superclass.


## Example
In the following example, the `_foo` attribute of class `A` shadows the method `_foo` of class `B`. Calls to `B()._foo()` will result in a `TypeError`, as `3` will be called instead.


```python
class A:
    def __init__(self):
        self._foo = 3

class B(A):
    # BAD: _foo is shadowed by attribute A._foo
    def _foo(self):
        return 2


```
In the following example, the behavior of the `default` attribute being shadowed to allow for customization during initialization is intended in within the superclass `A`. Overriding `default` in the subclass `B` is then OK.


```python
class A:
    def __init__(self, default_func=None):
        if default_func is not None:
            self.default = default_func 

    # GOOD: The shadowing behavior is explicitly intended in the superclass.
    def default(self):
        return []
    
class B(A):
    
    # Subclasses may override the method `default`, which will still be shadowed by the attribute `default` if it is set.
    # As this is part of the expected behavior of the superclass, this is fine. 
    def default(self):
        return {}
```
