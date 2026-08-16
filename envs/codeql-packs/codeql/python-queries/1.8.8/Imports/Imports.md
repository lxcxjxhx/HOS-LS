# Multiple imports on one line
Code is easier to read when each import statement is defined on a separate line.


## Recommendation
Update the code so that each import is defined on a separate line. PEP8 notes that it is acceptable to define multiple imports from a subprocess in a single statement.


## Example
The import statement:


```python
import xxx, yyy

```
should be changed to:


```python
import xxx
import yyy

```

## References
* Python Language Reference: [The import statement](http://docs.python.org/2/reference/simple_stmts.html#import).
* Python PEP 8: [Imports](http://www.python.org/dev/peps/pep-0008/#imports).
