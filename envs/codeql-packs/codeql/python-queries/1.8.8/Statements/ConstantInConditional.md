# Constant in conditional expression or statement
Using a constant value as a test in a conditional statement renders the statement pointless as only one branch will be run regardless of any other factors.


## Recommendation
If the conditional statement is required for debugging or similar then use a variable instead. Otherwise, remove the conditional statement and any associated dead code.


## Example
In the first example the `if` statement will always be executed and therefore can be removed. The contents of the statement should be kept though.

In the second example the statement `l = 100` is never executed because `1 > 100` is always false. However, it is likely that the intention was `l > 100` (the number '1' being misread as the letter 'l') and that the test should be corrected, rather than deleted.


```python
if True:
    print "True is true!"

def limit(l):
    if l < -100:
        l = -100
    if 1 > 100:
        l = 100
    return l

```

## References
* Python: [The If Statement](http://docs.python.org/reference/compound_stmts.html#the-if-statement).
* Python: [The While Statement](http://docs.python.org/reference/compound_stmts.html#the-while-statement).
* Python: [Literals (constant values)](http://docs.python.org/reference/expressions.html#literals).
* Common Weakness Enumeration: [CWE-561](https://cwe.mitre.org/data/definitions/561.html).
* Common Weakness Enumeration: [CWE-570](https://cwe.mitre.org/data/definitions/570.html).
* Common Weakness Enumeration: [CWE-571](https://cwe.mitre.org/data/definitions/571.html).
