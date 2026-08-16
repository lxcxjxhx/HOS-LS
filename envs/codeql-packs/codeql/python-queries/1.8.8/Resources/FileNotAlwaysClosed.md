# File is not always closed
When a file is opened, it should always be closed.

A file opened for writing that is not closed when the application exits may result in data loss, where not all of the data written may be saved to the file. A file opened for reading or writing that is not closed may also use up file descriptors, which is a resource leak that in long running applications could lead to a failure to open additional files.


## Recommendation
Ensure that opened files are always closed, including when an exception could be raised. The best practice is often to use a `with` statement to automatically clean up resources. Otherwise, ensure that `.close()` is called in a `try...except` or `try...finally` block to handle any possible exceptions.


## Example
In the following examples, in the case marked BAD, the file may not be closed if an exception is raised. In the cases marked GOOD, the file is always closed.


```python
def bad():
    f = open("filename", "w")
    f.write("could raise exception") # BAD: This call could raise an exception, leading to the file not being closed.
    f.close()


def good1():
    with open("filename", "w") as f:
        f.write("always closed") # GOOD: The `with` statement ensures the file is always closed.

def good2():
    f = open("filename", "w")
    try:
       f.write("always closed")
    finally:
        f.close() # GOOD: The `finally` block always ensures the file is closed.
   

```

## References
* Python Documentation: [Reading and writing files](https://docs.python.org/3/tutorial/inputoutput.html#reading-and-writing-files).
* Python Language Reference: [The with statement](http://docs.python.org/reference/compound_stmts.html#the-with-statement), [The try statement](http://docs.python.org/reference/compound_stmts.html#the-try-statement).
* Python PEP 343: [The "with" Statement](http://www.python.org/dev/peps/pep-0343).
* Common Weakness Enumeration: [CWE-772](https://cwe.mitre.org/data/definitions/772.html).
