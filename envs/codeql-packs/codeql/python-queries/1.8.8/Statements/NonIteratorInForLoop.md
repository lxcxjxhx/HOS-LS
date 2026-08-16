# Non-iterable used in for loop
The `for` statement is designed to allow you to iterate over the elements of a sequence or other iterable object. If a non-iterable object is used in a `for` statement (`for var in object:`) then a TypeError will be raised.


## Recommendation
Since this defect usually indicates a logical error, it is not possible to give a general method for addressing the defect.


## Example
In this example, the loop may attempt to iterate over `None`, which is not an iterable. It is likely that the programmer forgot to test for `None` before the loop.


```python


def illegal_for_loop(seq = None):
    for x in seq:
        print (x)


```

## References
* Python Language Reference: [The for statement](http://docs.python.org/reference/compound_stmts.html#the-for-statement), [object.__iter__](http://docs.python.org/2.7/reference/datamodel.html#object.__iter__).
* Python Standard Library: [Iterator types](http://docs.python.org/dev/library/stdtypes.html#iterator-types).
* Scipy lecture notes: [Iterators, generator expressions and generators](http://scipy-lectures.github.io/advanced/advanced_python/#iterators).
