# Module is imported more than once
Importing the same module more than once has no effect as each module is only loaded once. It also confuses readers of the code.


## Recommendation
Remove the second import.


## Example

```python
import module1
import module2
import module1 # Duplicate import

```

## References
* Python: [import statement](http://docs.python.org/reference/simple_stmts.html#import).
