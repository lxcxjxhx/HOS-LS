# Use of 'return' or 'yield' outside a function
In Python, `return` and `yield` statements and the `yield from` expression can only be used within a function. Using them outside a function or a class method results in a `SyntaxError` at runtime.


## Recommendation
Using these elements outside a function or a class method usually indicates an error in the logic. Consequently, it is not possible to suggest a general fix.


## Example
In this example, a `return` statement is used outside a class method in a class and a `yield` statement is used outside a function in a scope of a module which would result in a `SyntaxError` when running this code. In this example, the invalid class could be corrected by placing the `return` statement in a class method, or by refactoring the class into a function. The invalid `yield` statement could become part of a new generator function containing the `for` loop.


```python
# invalid class with return outside a function
class InvalidClass1(object):
    if [1, 2, 3]:
        return "Exists"

# invalid statement with yield outside a function
for i in [1, 2, 3]:
    yield i

```

## References
* Python reference: [ The return statement](https://docs.python.org/3.7/reference/simple_stmts.html#the-return-statement).
* Python reference: [ The yield statement](https://docs.python.org/3.7/reference/simple_stmts.html#yield).
* Python PEP-380: [ The yield from expression](https://docs.python.org/3/whatsnew/3.3.html#pep-380).
