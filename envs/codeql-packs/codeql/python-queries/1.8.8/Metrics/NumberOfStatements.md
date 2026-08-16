# Number of statements
This metric measures the number of statements that occur in a module.

If there are too many statements in a module, it is generally for one of two reasons:

* One or more individual classes or functions of the module contain too many statements, making them hard to understand, difficult to check and a common source of defects (particularly towards the end of the class or function, since few people ever read that far). These entities typically lack cohesion because they are trying to do too many things.
* The module contains too many functions or classes, which generally indicates that it is trying to do too much, either at the interface or implementation level or both. It can be difficult for readers to understand because there is a confusing list of operations.

## Recommendation
As described above, modules reported as violations by this rule contain one or more classes or functions with too many statements, or the module itself contains too many classes or functions.

* Individual classes or functions of the module that contain too many statements should be refactored into multiple, smaller parts. As a rough guide, functions should be able to fit on a single screen or side of A4. Anything longer than that increases the risk of introducing new defects during routine code changes.
* Modules that contain too many functions or classes often lack cohesion and are prime candidates for refactoring.

## References
* M. Fowler. *Refactoring*. Addison-Wesley, 1999.
