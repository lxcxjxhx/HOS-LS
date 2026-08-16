# Unreachable `except` block
When handling an exception, Python searches the except blocks in source code order until it finds a matching `except` block for the exception. An except block, `except E:`, specifies a class `E` and will match any exception that is an instance of `E`.

If a more general except block precedes a more specific except block, then the more general block is always executed and the more specific block is never executed. An except block, `except A:`, is more general than another except block, `except B:`, if `A` is a super class of `B`.

For example: `except Exception:` is more general than `except Error:` as `Exception` is a super class of `Error`.


## Recommendation
Reorganize the `except` blocks so that the more specific `except` is defined first. Alternatively, if the more specific `except` block is no longer required, then it should be deleted.


## Example
In the following example, the `except Exception:` will handle `AttributeError` preventing the subsequent handler from ever executing.


```python


def incorrect_except_order(val):
    try:
        val.attr
    except Exception:
        print ("Exception")
    except AttributeError:
        print ("AttributeError")
        

```

## References
* Python Language Reference: [The try statement](http://docs.python.org/3/reference/compound_stmts.html#try), [Exceptions](http://docs.python.org/3/reference/executionmodel.html#exceptions).
* Common Weakness Enumeration: [CWE-561](https://cwe.mitre.org/data/definitions/561.html).
