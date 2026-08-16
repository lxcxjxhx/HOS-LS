# Classes per file
This metric measures the number of classes in each file.

There are advantages and disadvantages associated with defining multiple classes in the same file. However, if you define unrelated classes in one file then the resulting module API is difficult for other developers to understand and use.

The disadvantages of putting multiple classes in the same file include:

* unless the classes are closely related, it can be difficult to understand and maintain the code, even with good support from development tools
* it increases the risk that multiple developers will work on the same file at once, and increases the incidence of merge conflicts
* it may be a symptom of badly designed modules, where many different features are handled by a single file.
Sometimes there are advantages of putting multiple classes in the same file, for example:

* it reduces the proliferation of files containing very few lines of code
* it can be used to group logically-related classes together.

## Recommendation
Each module should have a single, well-defined role. Consequently, only logically-related classes should be grouped together in the same file. If your code defines unrelated classes in the same file then you should refactor the code and create new files, each containing logically related classes.


## References
* Python: [Class Definitions](http://docs.python.org/2/reference/compound_stmts.html#class-definitions).
* M. Fowler, *Refactoring*. Addison-Wesley, 1999.
* Wikipedia: [Code refactoring](https://en.wikipedia.org/wiki/Code_refactoring).
