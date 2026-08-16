# An assert statement has a side-effect
All code defined in assert statements is ignored when optimization is requested, that is, the program is run with the `-O` flag. If an assert statement has any side-effects then the behavior of the program changes when optimization is requested.


## Recommendation
Move all expressions with side-effects out of assert statements.


## Example
In the example, the exit code from `subprocess.call()` is checked against 0, but the entire expression is called from within an `assert` statement. If the code is ever run, then the not only the assertion itself, but also the external call, will be discarded. It is better to save the result of `subprocess.call()` to a temporary variable, and to assert that variable to be 0.


```python
assert subprocess.call(['run-backup']) == 0

```

## References
* Python Language Reference: [The assert statement](http://docs.python.org/2/reference/simple_stmts.html#assert).
* TutorialsPoint, Python Programming: [Assertions in Python](http://www.tutorialspoint.com/python/assertions_in_python.htm).
