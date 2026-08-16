# Maybe missing 'self' in comparison
When two identical expressions are compared it is typically an indication of a mistake, since the Boolean value of the comparison will always be the same. Often, it can indicate that `self` has been omitted.


## Recommendation
It is never good practice to compare a value with itself. If `self` has been omitted, then insert it. If the constant behavior is indeed required, use the Boolean literals `True` or `False`, rather than encoding them obscurely as `x == x` or similar.


## Example

```python

class Customer:

    def __init__(self, data):
        self.data = data

    def check_data(self, data):
        if data != data:  # Forgotten 'self'
            raise Exception("Invalid data!")

#Fixed version

class Customer:

    def __init__(self, data):
        self.data = data

    def check_data(self, data):
        if self.data != data:
            raise Exception("Invalid data!")

```

## References
* Python Language Reference: [Comparisons](http://docs.python.org/2/reference/expressions.html#not-in).
* Common Weakness Enumeration: [CWE-570](https://cwe.mitre.org/data/definitions/570.html).
* Common Weakness Enumeration: [CWE-571](https://cwe.mitre.org/data/definitions/571.html).
