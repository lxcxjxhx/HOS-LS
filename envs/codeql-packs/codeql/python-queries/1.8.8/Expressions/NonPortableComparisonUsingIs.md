# Non-portable comparison using is when operands support `__eq__`
When you compare two values using the `is` or `is not` operator, it is the object identities of the two values that is tested rather than their equality. If the class of either of the values in the comparison redefines equality then the `is` operator may return `False` even though the objects compare as equal.

CPython interns a number of commonly used values, such as small integers, which means that using `is` instead of `==` will work correctly. However, this might not be portable to other implementations such as PyPy, IronPython, Jython or MicroPython.


## Recommendation
When you want to compare the value of two literals, use the comparison operator `==` or `!=` in place of `is` or `is not`.

If the uniqueness property or performance are important then use an object that does not redefine equality.


## Example
The function `equals_to_twelve()` relies on CPython interning small integers.

To function correctly for all implementations, change the expression `x is CONSTANT` to `x == CONSTANT`.


```python

CONSTANT = 12

def equals_to_twelve(x):
    return x is CONSTANT

#This works in CPython, but might not for other implementations.
print (equals_to_twelve(5 + 7))

```

## References
* Python Standard Library: [Comparisons](http://docs.python.org/2/library/stdtypes.html#comparisons).
* Stack Overflow: [Python "is" operator behaves unexpectedly with integers](http://stackoverflow.com/questions/306313/python-is-operator-behaves-unexpectedly-with-integers).
