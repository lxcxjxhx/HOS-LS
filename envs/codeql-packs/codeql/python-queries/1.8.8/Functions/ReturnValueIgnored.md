# Ignored return value
When a function returns a non-trivial value, that value should not be ignored. Doing so may result in errors being ignored or information being thrown away.

A return value is considered to be trivial if it is `None` or it is a parameter (parameters, usually `self` are often returned to assist with method chaining, but can be ignored). A return value is also assumed to be trivial if it is ignored for more than 25% of calls.


## Recommendation
Act upon all non-trivial return values, either propagating each value or recording it. If a return value should be ignored, then ensure that it is ignored consistently.

If you have access to the source code of the called function, then consider modifying it so that it does not return pointless values.


## Example
In the `ignore_error` function the error condition is ignored. Ideally the `Resource.initialize()` function would raise an exception if it failed, but as it does not, the caller must deal with the error. The `do_not_ignore_error` function checks the error condition and raises an exception if `Resource.initialize()` fails.


```python

from third_party import get_resource

def ignore_error(name):
    rsc = get_resource(name)
    rsc.initialize()
    try:
        use_resource(rsc)
    finally:
        rsc.close()

#Fixed
def do_not_ignore_error(name):
    rsc = get_resource(name)
    success = rsc.initialize()
    if not success:
        raise Error("Could not initialize resource")
    try:
        use_resource(rsc)
    finally:
        rsc.close()

```

## References
* Python Language Reference: [Function definitions](http://docs.python.org/2/reference/compound_stmts.html#function).
* Common Weakness Enumeration: [CWE-252](https://cwe.mitre.org/data/definitions/252.html).
