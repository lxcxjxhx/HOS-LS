# Inconsistent equality and inequality
In order to ensure the `==` and `!=` operators behave consistently as expected (i.e. they should be negations of each other), care should be taken when implementing the `__eq__` and `__ne__` special methods.

In Python 3, if the `__eq__` method is defined in a class while the `__ne__` is not, then the `!=` operator will automatically delegate to the `__eq__` method in the expected way.

However, if the `__ne__` method is defined without a corresponding `__eq__` method, the `==` operator will still default to object identity (equivalent to the `is` operator), while the `!=` operator will use the `__ne__` method, which may be inconsistent.

Additionally, if the `__ne__` method is defined on a superclass, and the subclass defines its own `__eq__` method without overriding the superclass `__ne__` method, the `!=` operator will use this superclass `__ne__` method, rather than automatically delegating to `__eq__`, which may be incorrect.


## Recommendation
Ensure that when an `__ne__` method is defined, the `__eq__` method is also defined, and their results are consistent. In most cases, the `__ne__` method does not need to be defined at all, as the default behavior is to delegate to `__eq__` and negate the result.


## Example
In the following example, `A` defines a `__ne__` method, but not an `__eq__` method. This leads to inconsistent results between equality and inequality operators.


```python
class A:
    def __init__(self, a):
        self.a = a 

    # BAD: ne is defined, but not eq.
    def __ne__(self, other):
        if not isinstance(other, A):
            return NotImplemented 
        return self.a != other.a

x = A(1)
y = A(1)

print(x == y) # Prints False (potentially unexpected - object identity is used)
print(x != y) # Prints False

```
In the following example, `C` defines an `__eq__` method, but its `__ne__` implementation is inherited from `B`, which is not consistent with the equality operation.


```python
class B:
    def __init__(self, b):
        self.b = b 
    
    def __eq__(self, other):
        return self.b == other.b 
    
    def __ne__(self, other):
        return self.b != other.b 
    
class C(B):
    def __init__(self, b, c):
        super().__init__(b)
        self.c = c 

    # BAD: eq is defined, but != will use superclass ne method, which is not consistent
    def __eq__(self, other):
        return self.b == other.b and self.c == other.c 
    
print(C(1,2) == C(1,3)) # Prints False 
print(C(1,2) != C(1,3)) # Prints False (potentially unexpected)
```

## References
* Python Language Reference: [object.__ne__](http://docs.python.org/3/reference/datamodel.html#object.__ne__), [Comparisons](http://docs.python.org/3/reference/expressions.html#comparisons).
