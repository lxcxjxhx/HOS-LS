# Module imports itself
There is no need for a module to import itself. A module importing itself may lead to errors as the module may be in an incomplete state when imported by itself.


## Recommendation
Remove the import statement. Convert all expressions of the form `mod.name` where "mod" is the name of the current module to `name`.


## Example
In this example the module, `ModuleImportsItself` imports itself and has an expression referencing the module it is in as well.


```python
import ModuleImportsItself

def factorial(n):
    if n <= 0:
        return 1
    return n * ModuleImportsItself.factorial(n - 1)
```
The import can be removed and the reference can be corrected.


```python

def factorial(n):
    if n <= 0:
        return 1
    return n * factorial(n - 1)
```

## References
* Python: [Modules](http://docs.python.org/2/tutorial/modules.html).
