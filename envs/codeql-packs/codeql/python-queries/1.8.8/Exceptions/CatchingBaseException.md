# Except block handles 'BaseException'
All exception classes in Python derive from `BaseException`. `BaseException` has three important subclasses, `Exception` from which all errors and normal exceptions derive, `KeyboardInterrupt` which is raised when the user interrupts the program from the keyboard and `SystemExit` which is raised by the `sys.exit()` function to terminate the program.

Since `KeyboardInterrupt` and `SystemExit` are special they should not be grouped together with other `Exception` classes.

Catching `BaseException`, rather than its subclasses may prevent proper handling of `KeyboardInterrupt` or `SystemExit`. It is easy to catch `BaseException` accidentally as it is caught implicitly by an empty `except:` statement.


## Recommendation
Handle `Exception`, `KeyboardInterrupt` and `SystemExit` separately. Do not use the plain `except:` form.


## Example
In these examples, a function `application.main()` is called that might raise `SystemExit`. In the first two functions, `BaseException` is caught, but this will discard `KeyboardInterrupt`. In the third function, `call_main_program_fixed` only `SystemExit` is caught, leaving `KeyboardInterrupt` to propagate.

In these examples `KeyboardInterrupt` is accidentally ignored.


```python

def call_main_program_implicit_handle_base_exception():
    try:
        #application.main calls sys.exit() when done.
        application.main()
    except Exception as ex:
        log(ex)
    except:
        pass

def call_main_program_explicit_handle_base_exception():
    try:
        #application.main calls sys.exit() when done.
        application.main()
    except Exception as ex:
        log(ex)
    except BaseException:
        pass

def call_main_program_fixed():
    try:
        #application.main calls sys.exit() when done.
        application.main()
    except Exception as ex:
        log(ex)
    except SystemExit:
        pass

```

## References
* Python Language Reference: [The try statement](http://docs.python.org/3/reference/compound_stmts.html#try), [Exceptions](http://docs.python.org/3/reference/executionmodel.html#exceptions).
* M. Lutz, Learning Python, Section 35.3: Exception Design Tips and Gotchas, O'Reilly Media, 2013.
* Python Tutorial: [Errors and Exceptions](https://docs.python.org/3/tutorial/errors.html).
* Common Weakness Enumeration: [CWE-396](https://cwe.mitre.org/data/definitions/396.html).
