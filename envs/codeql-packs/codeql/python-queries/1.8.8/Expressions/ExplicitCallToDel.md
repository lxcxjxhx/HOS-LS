# `__del__` is called explicitly
The `__del__` special method is designed to be called by the Python virtual machine when an object is no longer reachable, but before it is destroyed. Calling a `__del__` method explicitly may cause an object to enter an unsafe state.


## Recommendation
If explicit clean up of an object is required, a `close()` method should be called or, better still, wrap the use of the object in a `with` statement.


## Example
In the first example, rather than close the zip file in a conventional manner, the programmer has called `__del__`. A safer alternative is shown in the second example.


```python


def extract_bad(zippath, dest):
    zipped = ZipFile(zippath)
    try:
        zipped.extractall(dest)
    finally:
        zipped.__del__()

def extract_good(zippath, dest):
    zipped = ZipFile(zippath)
    try:
        zipped.extractall(dest)
    finally:
        zipped.close()


```

## References
* Python Standard Library: [object.__del__](http://docs.python.org/reference/datamodel.html#object.__del__)
