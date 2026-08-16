# Variable defined multiple times
Multiple assignments to a single variable without an intervening usage makes the first assignment redundant. Its value is lost.


## Recommendation
Ensure that the second assignment is in fact correct. Then delete the first assignment (taking care not to delete right hand side if it has side effects).


## Example
In this example, `x` is assigned the value of 42 but then the value is changed to 12 before `x` is used. This makes the first assignment useless.


```python
x = 42
x = 12
print x
```

## References
* Python: [Assignment statements](http://docs.python.org/reference/simple_stmts.html#assignment-statements).
* Common Weakness Enumeration: [CWE-563](https://cwe.mitre.org/data/definitions/563.html).
