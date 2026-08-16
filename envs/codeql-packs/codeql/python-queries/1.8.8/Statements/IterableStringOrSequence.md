# Iterable can be either a string or a sequence
The `for` statement is designed to allow you to iterate over the elements of a sequence or other iterable object. Strings in Python are iterable, and often used as such. However, they are also often considered, not as sequences of characters, but as atomic entities.

One source of defects in Python is mistakenly iterating over a non-iterable object such as an integer. This sort of defect is easily detected as a `TypeError` will be raised. However, if a string is mistakenly used as the iterable in a `for` statement, which also receives other sequences (such as lists) then the code will iterate over the string one character at a time. This is probably not what the programmer intended and results in errors that are hard to find.


## Recommendation
Since this defect usually indicates a logical error, it is not possible to give a general method for addressing the defect. However, adding a guard that checks that the iterator is not a string could be worthwhile.


## Example
In this example, the loop may iterate over `"Hello"` producing one character per line, as well as over `[ "Hello", "World" ]` It is likely that the programmer forgot to wrap the `"Hello"` in brackets.


```python

#Mistakenly mixed list and string
def greeting():
    if is_global():
        greet = [ "Hello", "World" ]
    else:
        greet = "Hello"
    for word in greet:
        print(word)

#Only use list
def fixed_greeting():
    if is_global():
        greet = [ "Hello", "World" ]
    else:
        greet = [ "Hello" ]
    for word in greet:
        print(word)

```

## References
* Python Language Reference: [The for statement](http://docs.python.org/reference/compound_stmts.html#the-for-statement), [object.__iter__](http://docs.python.org/2.7/reference/datamodel.html#object.__iter__).
* Python Standard Library: [Iterator types](http://docs.python.org/dev/library/stdtypes.html#iterator-types).
* Scipy lecture notes: [Iterators, generator expressions and generators](http://scipy-lectures.github.io/advanced/advanced_python/#iterators).
