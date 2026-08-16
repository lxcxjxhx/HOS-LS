# Direct imports per file
This metric measures the number of modules that are directly imported by each module (file). Modules that import many other modules often have too many responsibilities and are not well-focused. This makes it difficult to understand and maintain the module.


## Recommendation
Split and/or refactor files with too many responsibilities to create modules with a single, well-defined role.


## References
* Python Language Reference: [The import statement](http://docs.python.org/2/reference/simple_stmts.html#import).
* M. Fowler, *Refactoring*. Addison-Wesley, 1999.
* Wikipedia: [Code refactoring](https://en.wikipedia.org/wiki/Code_refactoring).
