# Asserting a tuple
When you define an `assert` statement to test a tuple the test will either always succeed (if the tuple is non-empty) or always fail (if the tuple is empty).

This error usually occurs when the programmer writes ` assert (condition, message) ` instead of the correct form` assert condition, message `


## Recommendation
Review the code and determine the purpose of the `assert` statement:

* If the "tuple" has been created in error, then remove the parentheses and correct the statement
* If validation of a tuple is intended, then you should define an `assert` statement for each element of the tuple.

## Example
The statement `assert (xxx, yyy)` attempts to test a "tuple" `(xxx, yyy)`. The original intention may be any of the alternatives listed below:


```python
assert xxx and yyy   # Alternative 1a. Check both expressions are true

assert xxx, yyy      # Alternative 1b. Check 'xxx' is true, 'yyy' is the failure message.

tuple = (xxx, yyy)   # Alternative 2. Check both elements of the tuple match expectations.
assert tuple[0]==xxx
assert tuple[1]==yyy

```
If you want to define a validity check on the values of a tuple then these must be tested individually.


## References
* Python Language Reference: [The assert statement](http://docs.python.org/2.7/reference/simple_stmts.html#the-assert-statement).
* Tutorials Point: [Assertions in Python](http://www.tutorialspoint.com/python/assertions_in_python.htm).
* Common Weakness Enumeration: [CWE-670](https://cwe.mitre.org/data/definitions/670.html).
