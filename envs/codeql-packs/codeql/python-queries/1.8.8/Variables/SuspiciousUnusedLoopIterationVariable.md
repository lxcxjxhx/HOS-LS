# Suspicious unused loop iteration variable
A for loop iteration variable is not used in the body of the loop, and the loop does not count the number of items in the sequence. This is suspicious as there is rarely any reason to iterate over a sequence and not use the contents. Not using the loop variable can often indicate a logical error or typo.


## Recommendation
Carefully check that the loop variable should not be used. If the variable is genuinely not being used and the code is correct, then rename the variable to `_` or `unused` to indicate to readers of the code that it is intentionally unused.


## Example
In this example, the `for` loop iteration variable `x` is never used. It appears that the original `test` function was used to test `TypeA` and was subsequently modified to test `TypeB` as well.


```python

#
def test():
    for t in [TypeA, TypeB]:
        x = TypeA()
        run_test(x)

```
It is likely that the change from `x = TypeA()` to `x = t()` was forgotten. The fixed version is shown below.


```python

#
def test():
    for t in [TypeA, TypeB]:
        x = t
        run_test(x)

```

## References
* Python Language Reference: [The for statement](https://docs.python.org/reference/compound_stmts.html#the-for-statement).
* Python Tutorial: [For statements](https://docs.python.org/tutorial/controlflow.html#for-statements).
