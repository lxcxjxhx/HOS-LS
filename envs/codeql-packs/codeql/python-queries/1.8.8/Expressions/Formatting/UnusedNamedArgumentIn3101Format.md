# Unused named argument in formatting call
A formatting expression, that is an expression of the form `the_format.format(args)` or `format(the_format, args)` can have keyword arguments of any name, as long as all the required names are provided. However, surplus keyword arguments, those with names that are not in the format, are redundant. These surplus arguments clutter the code, making it harder to read.

It is also possible that surplus keyword arguments indicate a mistake in the format string.


## Recommendation
Check that the format string is correct and then remove any surplus keyword arguments.


## Example
In the following example, the comment indicates that the `chips` keyword argument is no longer required and should be deleted.


```python
def surplus_argument():
    the_format = "{spam} {eggs}" # Used to be "{spam} {eggs} {chips}"
    return the_format.format(spam = "spam", eggs="eggs", chips="chips")

```

## References
* Python Library Reference: [String Formatting.](https://docs.python.org/2/library/string.html#string-formatting)
