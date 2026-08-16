# Use of an undefined global variable
This global variable may not be defined. If this code is executed and the variable is undefined then a `NameError` will occur.


## Recommendation
Check that the name of the global variable is not a typographic error. If the name is correct then define the variable or import the module that defines the function or method.

If it is expected this variable will be initialized from another module before it is used, then the `NameError` may not occur. Nonetheless, the code will be more robust and clearer if the variable is set to a default value in its own module.


## Example
The following examples show two different examples of undefined "global variables".


```python
import math

angle = 0.01

sin(angle)       # NameError: name 'sin' is not defined (function imported from 'math')

math.sin(angle)  # 'sin' function now correctly defined

math.tan(angel)  # NameError: name 'angel' not defined (typographic error)

math.tan(angle)  # Global variable now correctly defined


```

## References
* Python Standard Library: [NameError](https://docs.python.org/library/exceptions.html#exceptions.NameError).
* The Python Tutorial: [Modules](http://docs.python.org/2/tutorial/modules.html).
