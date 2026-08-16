# Inconsistent method resolution order
Python 2.3 introduced new-style classes (classes inheriting from object). New-style classes use the C3 linearization method to determine a method resolution ordering (MRO) for each class. The C3 linearization method ensures that for a class C, if a class C1 precedes a class C2 in the MRO of C then C1 should also precede C2 in the MRO of all subclasses of C. It is possible to create a situation where it is impossible to achieve this consistency and this will guarantee that a ` TypeError` will be raised at runtime.


## Recommendation
Use a class hierarchy that is not ambiguous.


## Example
The MRO of class `X` is just `X, object`. The program will fail when the MRO of class `Y` needs to be calculated because `object` precedes `X` in the definition of `Y` but the opposite is true in the MRO of `X`.


```python
class X(object):
    def __init__(self):
        print("X")
class Y(object,X):
    def __init__(self):
        print("Y")
```

## References
* Python: [The Python 2.3 Method Resolution Order](http://www.python.org/download/releases/2.3/mro/).
