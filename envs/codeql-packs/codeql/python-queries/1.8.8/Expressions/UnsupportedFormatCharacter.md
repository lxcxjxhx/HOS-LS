# Unsupported format character
A printf-style format string (i.e. a string that is used as the left hand side of the `%` operator, such as `fmt % arguments`) must consist of valid conversion specifiers, such as `%s`, `%d`, etc. Otherwise, a `ValueError` will be raised.


## Recommendation
Ensure a valid conversion specifier is used.


## Example
In the following example, `format_as_tuple_incorrect`, `%t` is not a valid conversion specifier.


```python

def format_as_tuple_incorrect(args):
    return "%t" % args

def format_as_tuple_correct(args):
    return "%r" % (args,)

```

## References
* Python Library Reference: [printf-style String Formatting.](https://docs.python.org/3/library/stdtypes.html#printf-style-string-formatting)
