# Unreachable code
Unreachable code makes the code more difficult to understand and may slow down loading of modules.


## Recommendation
Deleting the unreachable code will make the code clearer and preserve the meaning of the code. However, it is possible that the original intention was that the code should execute and that it is unreachable signifies some other error.


## Example
In this example the assignment to `remainder` is never reached because there is a ` return` statement on the previous line.


```python
import math

def my_div(x, y):
    return math.floor(x / y)
    remainder = x - math.floor(x / y) * y

```

## References
* Wikipedia: [Unreachable Code](http://en.wikipedia.org/wiki/Unreachable_code).
* Common Weakness Enumeration: [CWE-561](https://cwe.mitre.org/data/definitions/561.html).
