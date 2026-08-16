# Unnecessary delete statement in function
Passing a local variable to a `del` statement results in that variable being removed from the local namespace. When exiting a function all local variables are deleted, so it is unnecessary to explicitly delete variables in such cases.


## Recommendation
Remove the `del` statement.


## Example
In the function below, the variable `x` is assigned a value that is used for a calculation, and is then explicitly deleted before the function exits. In this case, the delete statement can be removed without changing the behavior of the function.


```python
def unnecessary_delete():
    x = get_some_object()
    do_calculation(x)
    del x                       # This del statement is unnecessary

```

## References
* Python: [The 'del' statement](https://docs.python.org/2/reference/simple_stmts.html#the-del-statement).
* Python/C API Reference Manual: [Reference counts](https://docs.python.org/2.0/api/refcounts.html).
