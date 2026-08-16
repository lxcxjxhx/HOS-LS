# Explicit export is not defined
When a module is imported using `import *`, all attributes listed in `__all__` are imported. If `__all__` includes attributes that are not defined in the module then an exception is triggered. This usually indicates a typographic error in the attributes in `__all__` or in the name of the object.


## Recommendation
Correct any typographic errors, either in the name of the object or in the string in `__all__`. If there are no typographic errors, either delete the name from `__all__` or add the object to the module.


## Example
In the example, the function name `spam` has been misspelled in the `__all__` list. This will result in `spamm` being highlighted as an undefined export. Correcting the spelling will fix the defect.


```python
__all__ = ['spamm', 'troll', 'paywall']

def spam(): return 'Spam'
def troll(): return 'Troll'
def paywall(): return 'Pay wall'

```

## References
* Python Language Reference: [The import statement](http://docs.python.org/2/reference/simple_stmts.html#import).
* Python Tutorial: [Importing \* from a Package](http://docs.python.org/2/tutorial/modules.html#importing-from-a-package).
