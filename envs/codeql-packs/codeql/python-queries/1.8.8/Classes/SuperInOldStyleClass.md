# 'super' in old style class
The ability to access inherited methods that have been overridden in a class using `super()` is supported only by new-style classes. When you use the `super()` function in an old-style class it fails.


## Recommendation
If you want to access inherited methods using the `super()` built-in, then ensure that the class is a new-style class. You can convert an old-style class to a new-style class by inheriting from `object`. Alternatively, you can call the `__init__` method of the superclass directly from an old-style class using: `BaseClass.__init__(...)`.


## Example
In the following example, `PythonModule` is an old-style class as it inherits from another old-style class. If the `_ModuleIteratorHelper` class cannot be converted into a new-style class, then the call to `super()` must be replaced. The `PythonModule2` class demonstrates the correct way to call a superclass from an old-style class.


```python
class PythonModule(_ModuleIteratorHelper): # '_ModuleIteratorHelper' and 'PythonModule' are old-style classes

    # class definitions ....

    def walkModules(self, importPackages=False):
        if importPackages and self.isPackage():
            self.load()
        return super(PythonModule, self).walkModules(importPackages=importPackages) # super() will fail


class PythonModule2(_ModuleIteratorHelper): # call to super replaced with direct call to class

    # class definitions ....

    def walkModules(self, importPackages=False):
        if importPackages and self.isPackage():
            self.load()
        return _ModuleIteratorHelper.__init__(PythonModule, self).walkModules(importPackages=importPackages)

```

## References
* Python Glossary: [New-style class](http://docs.python.org/glossary.html#term-new-style-class).
* Python Language Reference: [New-style and classic classes](http://docs.python.org/2/reference/datamodel.html#newstyle).
* Python Standard Library: [super](http://docs.python.org/library/functions.html#super).
