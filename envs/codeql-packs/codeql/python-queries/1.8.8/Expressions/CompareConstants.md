# Comparison of constants
When two constants are compared it is typically an indication of a mistake, since the Boolean value of the comparison will always be the same. In very old code this may be used to initialize `True` and `False`.


## Recommendation
It is never good practice to compare a value with itself. If the constant behavior is indeed required, use the Boolean literals `True` or `False`, rather than encoding them obscurely as `1 == 1` or similar. If there is a mistake, ascertain the desired behavior and correct it.


## Example
In this example, old code uses `1==1` to initialize `__builtins__.True`. This code has been unnecessary on all versions of Python released since 2003 and can be deleted.


```python

#Interoperate with very old versions of Python (pre 2.3)
try:
    True
except NameError:
    __builtins__.True = 1==1

```

## References
* Python Language Reference: [Comparisons](http://docs.python.org/2/reference/expressions.html#not-in).
* Common Weakness Enumeration: [CWE-570](https://cwe.mitre.org/data/definitions/570.html).
* Common Weakness Enumeration: [CWE-571](https://cwe.mitre.org/data/definitions/571.html).
