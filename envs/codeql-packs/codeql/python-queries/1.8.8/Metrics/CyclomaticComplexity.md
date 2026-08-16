# Cyclomatic complexity of functions
This metric measures the total cyclomatic complexity for the functions in a file.

Cyclomatic complexity approximates the number of paths that can be taken during the execution of a function (and hence, the minimum number of tests cases necessary to test it thoroughly). Straight-line code has zero cyclomatic complexity, while branches and loops increase cyclomatic complexity.

Files that contain too many complex functions can be difficult to test, understand, and maintain.


## Recommendation
Try to simplify overly-complex code. For example:

* Highly nested conditionals can be simplified by rethinking the requirements that the function fulfills.
* Repeated tests can be refactored into helper functions, which also decreases the risk of introducing defects by copying and pasting code.
* Large complex functions can often be split into smaller more focused functions.

## References
* M. Fowler. *Refactoring*. Addison-Wesley, 1999.
* T. J. McCabe. *A Complexity Measure*. IEEE Transactions on Software Engineering, SE-2(4), December 1976.
* Wikipedia: [Cyclomatic complexity](http://en.wikipedia.org/wiki/Cyclomatic_complexity).
