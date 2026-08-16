# Redundant assignment
Assigning a variable to itself is redundant and often an indication of a mistake in the code.


## Recommendation
Check the assignment carefully for mistakes. If the assignment is truly redundant and not simply incorrect then remove it.


## Example
In this example the programmer clearly intends to assign to `self.eggs` but made a mistake.


```python
class Spam:

    def __init__(self, eggs):
        eggs = eggs


```

## References
* Python Language Reference: [ The assignment statement](http://docs.python.org/reference/simple_stmts.html#assignment-statements).
* Common Weakness Enumeration: [CWE-563](https://cwe.mitre.org/data/definitions/563.html).
