# Missing named arguments in formatting call
A formatting expression, that is an expression of the form `the_format.format(args)` or `format(the_format, args)`, can use named fields. If it does, then keyword arguments must be supplied for all named fields. If any of the keyword arguments are missing then a `KeyError` will be raised.


## Recommendation
Change the format to match the arguments and ensure that the arguments have the correct names.


## Example
In the following example, if `unlikely_condition()` is true, then a `KeyError` will be raised as the keyword parameter `eggs` is missing. Adding a keyword parameter named `eggs` would fix this.


```python
def unsafe_named_format():
    the_format = "{spam} {eggs}"
    if unlikely_condition():
        return the_format.format(spam="spam", completely_different="eggs")
    else:
        return the_format.format(spam="spam", eggs="eggs")

```

## References
* Python Library Reference: [String Formatting.](https://docs.python.org/2/library/string.html#string-formatting)
