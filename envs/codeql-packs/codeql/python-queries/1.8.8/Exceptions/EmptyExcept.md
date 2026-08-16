# Empty except
Ignoring exceptions that should be dealt with in some way is almost always a bad idea. The loss of information can lead to hard to debug errors and incomplete log files. It is even possible that ignoring an exception can cause a security vulnerability. An empty `except` block may be an indication that the programmer intended to handle the exception, but never wrote the code to do so.


## Recommendation
Ensure all exceptions are handled correctly.


## Example
In this example, the program keeps running with the same privileges if it fails to drop to lower privileges.


```python
# ...
try:
    security_manager.drop_privileges()
except SecurityError:
    pass
# ...
```

## References
* Common Weakness Enumeration: [CWE-390](https://cwe.mitre.org/data/definitions/390.html).
