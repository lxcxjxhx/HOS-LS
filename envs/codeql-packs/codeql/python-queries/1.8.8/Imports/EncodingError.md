# Encoding error
Encoding errors prevent a module being evaluated and thus imported. An attempt to import a module with an invalid encoding will fail; a `SyntaxError` will be raised. Note that in Python 2, the default encoding is ASCII.

The existence of an encoding error in a module may suggest other problems as well. Either the module is never imported in practice and could be deleted or a `try` statement around the import is mistakenly discarding the `SyntaxError`.


## Recommendation
Fixing the encoding error is the obvious fix. However, it is worth investigating why a module containing an encoding error was able to persist and address that problem as well.

If a different encoding should be used for the file, specify it explicitly by putting an encoding specification at the top of the file. For instance, to specify UTF-8 encoding, add the line `# coding=utf-8`.


## References
* Python PEPs: [PEP 263 — Defining Python Source Code Encodings.](https://www.python.org/dev/peps/pep-0263/)
* Python Tutorial: [SyntaxErrors.](http://docs.python.org/tutorial/errors.html#syntax-errors)
