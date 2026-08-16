# Use of a print statement at module level
Using `print` statements in level scope may result in surprising output at import time. This in turn means that other code cannot safely import the module in question if the program may only write real output to standard out.


## Recommendation
Replace the `print` statements with calls to some form of logging function or use the `warnings` module.


## Example
In the example, importing the module may cause a message to be printed, which may interfere with the operation of the program.


```python

try:
    import fast_system as system
except ImportError:
    print ("Cannot import fast system, falling back on slow system")
    import slow_system as system

#Fixed version
import logging

try:
    import fast_system as system
except ImportError:
    logging.info("Cannot import fast system, falling back on slow system")
    import slow_system as system

```

## References
* Python Language Reference: [The print statement](http://docs.python.org/2/reference/simple_stmts.html#the-print-statement).
* Python Standard Library: [The print function](http://docs.python.org/3/library/functions.html#print).
* Python tutorial: [Modules](http://docs.python.org/2/tutorial/modules.html).
