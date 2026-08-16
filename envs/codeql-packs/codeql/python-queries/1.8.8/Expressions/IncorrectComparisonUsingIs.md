# Comparison using is when operands support `__eq__`
When you compare two values using the `is` or `is not` operator, it is the object identities of the two values that is tested rather than their equality. If the class of either of the values in the comparison redefines equality then the `is` operator may return `False` even though the objects compare as equal. Equality is defined by the `__eq__` or, in Python2, `__cmp__` method. To compare two objects for equality, use the `==` or `!=` operator instead.


## Recommendation
When you want to compare the value of two literals, use the comparison operator `==` or `!=` in place of `is` or `is not`.

If the uniqueness property or performance are important then use an object that does not redefine equality.


## Example
In the first line of the following example the programmer tests the value of `value` against `DEFAULT` using the `is` operator. Unfortunately, this may fail when the function is called with the string `"default"`.

To function correctly, change the expression `value is DEFAULT` to `value == DEFAULT`. Alternatively, if the uniqueness property is desirable, then change the definition of `DEFAULT` to either of the alternatives below.


```python

DEFAULT = "default"

def get_color(name, fallback):
    if name in COLORS:
        return COLORS[name]
    elif fallback is DEFAULT:
        return DEFAULT_COLOR
    else:
        return fallback

#This works
print (get_color("spam", "def" + "ault"))

#But this does not
print (get_color("spam", "default-spam"[:7]))

#To fix the above code change to object
DEFAULT = object()

#Or if you want better repr() output:
class Default(object):

    def __repr__(self):
        return "DEFAULT"

DEFAULT = Default()

```

## References
* Python Standard Library: [Comparisons](http://docs.python.org/3/library/stdtypes.html#comparisons).
