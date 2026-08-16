# Undefined class attribute
A non-existent attribute of `self` is accessed in a method. An attribute is treated as non-existent if it is not a class attribute and it is not set in any method of the class. This may result in an `AttributeError` at run time.


## Recommendation
Ensure that all attributes are initialized in the `__init__` method.


## Example

```python
class Spam:

    def __init__(self):
        self.spam = 'spam, spam, spam'

    def __str__(self):
        return '%s and %s' % (self.spam, self.eggs) # Uninitialized attribute 'eggs'

#Fixed version

class Spam:

    def __init__(self):
        self.spam = 'spam, spam, spam'
        self.eggs = None

    def __str__(self):
        return '%s and %s' % (self.spam, self.eggs) # OK


```

## References
* Python Standard Library: [exception AttributeError](http://docs.python.org/library/exceptions.html#exceptions.AttributeError).
