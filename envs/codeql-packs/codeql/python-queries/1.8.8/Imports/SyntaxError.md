# Syntax error
Syntax errors prevent a module being evaluated and thus imported. An attempt to import a module with invalid syntax will fail; a `SyntaxError` will be raised.

A common cause of syntax errors is the difference in syntax between Python 2 and Python 3. In particular, a syntax error may be alerted if a Python 3 file is assumed to be compatible with Python 2 (or vice versa). Explicitly specifying the expected Python version can help prevent this.

The existence of a syntax error in a module may suggest other problems as well. Either the module is never imported in practice and could be deleted or a `try` statement around the import is mistakenly discarding the `SyntaxError`.


## Recommendation
Fixing the syntax error is the obvious fix. However, it is worth investigating why a module containing a syntax error was able to persist and address that problem as well.

If you suspect that the syntax error is caused by the analysis using the wrong version of Python, consider specifying the version explicitly. When you run code scanning using the CodeQL action, you can configure the Python version to use. For more information, see [Analyzing Python dependencies](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/configuring-code-scanning#analyzing-python-dependencies).


## References
* Python Tutorial: [SyntaxErrors.](http://docs.python.org/tutorial/errors.html#syntax-errors)
