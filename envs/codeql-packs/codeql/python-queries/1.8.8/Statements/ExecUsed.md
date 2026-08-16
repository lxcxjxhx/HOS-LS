# 'exec' used
Using `exec` may introduce a security vulnerability into your program unless you ensure that the data passed to the statement is neutralized.


## Recommendation
Review all uses of the `exec` statement (Python 2) or function (Python 3). Where possible, replace the `exec` statement or function with normal python code. Alternatively, ensure that all data passed to the statement is neutralized.


## Example
In the example, the `exec` statement is used and may result in executing code from an attacker.


```python

to_execute = get_untrusted_code()
exec to_execute

```

## References
* Python 2.7 Language Reference: [The exec statement](https://docs.python.org/2.7/reference/simple_stmts.html#the-exec-statement).
* Python 3 Standard Library: [exec](https://docs.python.org/3/library/functions.html#exec).
