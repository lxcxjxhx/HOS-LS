# 'import *' used
Using `from xxx import *` makes it difficult to determine what has been defined by the import statement. This may hide errors and introduce unexpected dependencies.


## Recommendation
Use explicit imports. For example `from xxx import a, b, c`


## References
* Python Language Reference: [The import statement](http://docs.python.org/2/reference/simple_stmts.html#import).
* Python PEP-8: [Imports](http://www.python.org/dev/peps/pep-0008/#imports).
