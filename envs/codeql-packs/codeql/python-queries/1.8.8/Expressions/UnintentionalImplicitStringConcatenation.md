# Implicit string concatenation in a list
When two string literals abut each other the Python interpreter implicitly concatenates them into a single string. On occasion this can be useful, but is more commonly misleading or incorrect.


## Recommendation
If the concatenation is deliberate, then use `+` to join the strings. This has no runtime overhead, and makes the intention clear.


## Example
In the first function below, `unclear`, implicit string concatenation is used twice; once deliberately and once by accident. In the second function, `clarified`, the first concatenation is made explicit and the second is removed.


```python

def unclear():
    # Returns [ "first part of long string and the second part", "/usr/local/usr/bin" ]
    return [

        "first part of long string"
        " and the second part",
        "/usr/local"
        "/usr/bin"
    ]

def clarified():
    # Returns [ "first part of long string and the second part", "/usr/local", "/usr/bin" ]
    return [
        "first part of long string" +
        " and the second part",
        "/usr/local",
        "/usr/bin"
    ]

```

## References
* Python language reference: [String literal concatenation](https://docs.python.org/3/reference/lexical_analysis.html#string-literal-concatenation).
* Common Weakness Enumeration: [CWE-665](https://cwe.mitre.org/data/definitions/665.html).
