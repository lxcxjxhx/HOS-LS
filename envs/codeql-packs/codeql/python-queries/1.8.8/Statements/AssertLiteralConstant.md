# Assert statement tests the truth value of a literal constant
In Python, assertions are not executed when optimizations are enabled. This may lead to unexpected behavior when assertions are used to the check validity of a piece of input.


## Recommendation
If the value being tested is false, replace the `assert` statement with a `raise` statement that raises an appropriate exception. If the value being tested is true, delete the `assert` statement or replace it with a `pass` statement.


## Example
This example shows a function `buy_bananas` that takes a number `n` as input. The function checks that this number is not too big before sending off an order for that number of bananas. Because this is done using an `assert` statement, the check disappears when optimizations are enabled. The second function corrects this error by explicitly raising an `AssertionError`, and checks the value even when optimizations are enabled.


```python
def buy_bananas(n):
    if n > 500:
        assert False, "Too many bananas."
    send_order("bananas", n)

def buy_bananas_correct(n):
    if n > 500:
        raise AssertionError("Too many bananas")
    send_order("bananas", n)

```

## References
* Python Language Reference: [The assert statement](https://docs.python.org/2/reference/simple_stmts.html#the-assert-statement).
* The Python Tutorial: [“Compiled” Python files](https://docs.python.org/2.7/tutorial/modules.html#compiled-python-files).
