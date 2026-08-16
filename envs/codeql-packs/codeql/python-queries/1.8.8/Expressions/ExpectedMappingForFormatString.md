# Formatted object is not a mapping
If a format string includes conversion specifiers of the form `%(name)s` then the right hand side of the operation must be a mapping. A string is a format string if it appears on the left of a modulo (`%`) operator, the right hand side being the value to be formatted. If the right hand side is not a mapping then a `TypeError` will be raised. Mappings are usually `dict`s but can be any type that implements the mapping protocol.


## Recommendation
Change the format to match the arguments and ensure that the right hand side is always a mapping.


## Example
In the following example the right hand side of the formatting operation can be a `tuple`, which is not a mapping. To fix this example, ensure that `args` is a mapping when `unlike_condition` occurs.


```python

def unsafe_format():
    if unlikely_condition():
        args = (1,2,3)
    else:
        args = {a:1,b:2,c:3}
    return "%(a)s %(b)s %(c)s" % args
```

## References
* Python Library Reference: [String Formatting.](http://docs.python.org/library/stdtypes.html#string-formatting)
