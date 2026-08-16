# 'import *' may pollute namespace
When you import a module using `from xxx import *` all public names defined in the module are imported and bound in the local namespace of the `import` statement. The public names are determined by checking the `__all__` variable for the module. If ` __all__` is not defined then all names within the module that do not start with an underscore character are imported. This pollutes the current namespace with names that are not part of the public API for the module.


## Recommendation
There are two ways to address this problem:

* where possible, modify the module being imported *from* and define `__all__ ` to restrict the names to be imported
* otherwise, explicitly import the values that you need.

## Example
The following simple example shows how `__all__` controls the public names for the module `finance`.


```python
# Example module - finance.py

__all__ = ['tax1', 'tax2']  #defines the names to import when '*' is used

tax1 = 5
tax2 = 10
def cost(): return 'cost'

# Imported into code using

from finance import *

print tax1
print tax2
```
If the `finance` module did not include a definition of `__all__`, then you could replace `from finance import *` with `from finance import tax1, tax2`.


## References
* Python Language Reference: [The import statement](http://docs.python.org/2/reference/simple_stmts.html#import).
* Python Tutorial: [Modules](http://docs.python.org/2/tutorial/modules.html).
