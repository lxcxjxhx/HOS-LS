# Use of an undefined placeholder variable
This place-holder variable may not be defined. If this code is executed and the variable is undefined then a `NameError` will occur.


## Recommendation
Check that the name of the place-holder variable is not a typographic error. If the name is correct, either define a value for the variable, or import the module that defines the function or method that sets the value.

If another module initializes this variable before it is used, then the `NameError` may not occur. However, you can make the code more robust and clearer by setting the variable to a default value in its own module.


## References
* Python Standard Library: [NameError](https://docs.python.org/library/exceptions.html#exceptions.NameError).
