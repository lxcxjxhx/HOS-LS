# Should use a 'with' statement
The `with` statement was introduced by PEP343 to allow standard uses of `try-finally` statements to be factored out. Using this simplification makes code easier to read.


## Recommendation
Review the code and determine whether or not the `try-finally` is used only to ensure that a resource is closed. If the only purpose is to ensure that a resource is closed, then replace the `try-finally` statement with a `with` statement.


## Example
The following code shows examples of different ways of ensuring that a file is always closed, even when an error is generated. In the second example, the `try-finally` block is replaced by a simpler `with` statement.


```python

f = open("filename")
try:                         # Method of ensuring file closure
    f.write(...)
finally:
    f.close()


with open("filename") as f:  # Simpler method of ensuring file closure
    f.write(...)
```

## References
* Python Language Reference: [The with statement](http://docs.python.org/reference/compound_stmts.html#the-with-statement).
* Python Standard Library: [Context manager ](http://docs.python.org/library/stdtypes.html#context-manager-types).
* Python PEP 343: [The "with" Statement](http://www.python.org/dev/peps/pep-0343).
