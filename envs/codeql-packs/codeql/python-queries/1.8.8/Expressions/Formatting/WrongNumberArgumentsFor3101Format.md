# Too few arguments in formatting call
A formatting expression, that is an expression of the form `the_format.format(args)` or `format(the_format, args)`, must have sufficient arguments to match the format. Otherwise, an `IndexError` will be raised.


## Recommendation
Either change the format to match the arguments, or ensure that there are sufficient arguments.


## Example
In the following example, only 2 arguments may be provided for the call to the `str.format` method, which is insufficient for the format string used. To fix this a third parameter should be provided on line 4.


```python
def unsafe_format():
    the_format = "{} {} {}"
    if unlikely_condition():
        return the_format.format(1, 2)
    else:
        return the_format.format(1, 2, 3)


```

## References
* Python Library Reference: [String Formatting.](https://docs.python.org/2/library/string.html#string-formatting)
