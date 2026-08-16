# Non-exception in 'except' clause
If the class specified in an `except` handler (within a `try` statement) is not a legal exception class, then it will never match a raised exception and never be executed

Legal exception classes are:

* Any old-style classes (Python 2 only)
* Any subclass of the builtin class `BaseException`
However, it recommended that you only use subclasses of the builtin class `Exception` (which is itself a subclass of `BaseException`).


## Recommendation
Ensure that the specified class is the one intended. If it is not then replace it with the correct one. Otherwise the entire `except` block can be deleted.


## Example

```python
def handle_int():
    try:
        raise_int()
    #This will not cause an exception, but it will be ignored
    except int:
        print("This will never be printed")


```

## References
* Python Language Reference: [Exceptions](https://docs.python.org/reference/executionmodel.html#exceptions).
* Python Tutorial: [Handling Exceptions](https://docs.python.org/tutorial/errors.html#handling-exceptions).
