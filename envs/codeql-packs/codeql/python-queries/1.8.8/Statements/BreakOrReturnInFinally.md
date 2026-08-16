# 'break' or 'return' statement in finally
When a `break` or `return` statement is used in a `finally` block this causes the `try-finally` block to exit immediately discarding the exception. This is unlikely to be the intention of the developer and makes the code more difficult to read.


## Recommendation
Either move the `break` or `return` statement to immediately after the `finally` block or use an explicit `except` block to handle the exception.

These modifications are behavior changing so you must take care to ensure that the resulting behavior is correct.


## References
* Python Language Reference: [ The try statement](http://docs.python.org/2.7/reference/compound_stmts.html#the-try-statement), [ The break statement](http://docs.python.org/2/reference/simple_stmts.html#break), [ The return statement](http://docs.python.org/2/reference/simple_stmts.html#return).
* Common Weakness Enumeration: [CWE-584](https://cwe.mitre.org/data/definitions/584.html).
