# Unused argument in a formatting call
A formatting expression, that is an expression of the form `the_format.format(args)` or `format(the_format, args)`, can have any number of arguments, provided that there are enough to match the format. However, surplus arguments are redundant and clutter the code, making it harder to read.

It is also possible that surplus arguments indicate a mistake in the format string.


## Recommendation
Check that the format string is correct and then remove any surplus arguments.


## Example
In the following example there are three arguments for the call to the `str.format()` method, but the format string only requires two. The third argument should be deleted.


```python
def surplus_argument():
    the_format = "{} {}" # Used to be "{} {} {}"
    return the_format.format(1, 2, 3)

```

## References
* Python Library Reference: [String Formatting.](https://docs.python.org/2/library/string.html#string-formatting)
