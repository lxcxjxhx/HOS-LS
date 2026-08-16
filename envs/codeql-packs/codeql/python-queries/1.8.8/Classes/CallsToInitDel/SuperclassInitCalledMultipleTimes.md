# Multiple calls to `__init__` during object initialization
Python, unlike some other object-oriented languages such as Java, allows the developer complete freedom in when and how superclass initializers are called during object initialization. However, the developer has responsibility for ensuring that objects are properly initialized.

Calling an `__init__` method more than once during object initialization risks the object being incorrectly initialized, as the method and the rest of the inheritance chain may not have been written with the expectation that it could be called multiple times. For example, it may set attributes to a default value in a way that unexpectedly overwrites values setting those attributes in a subclass.

There are a number of ways that an `__init__` method may be called more than once.

* There may be more than one explicit call to the method in the hierarchy of `__init__` methods.
* In situations involving multiple inheritance, an initialization method may call the initializers of each of its base types, which themselves both call the initializer of a shared base type. (This is an example of the Diamond Inheritance problem)
* Another situation involving multiple inheritance arises when a subclass calls the `__init__` methods of each of its base classes, one of which calls `super().__init__`. This super call resolves to the next class in the Method Resolution Order (MRO) of the subclass, which may be another base class that already has its initializer explicitly called.

## Recommendation
Take care whenever possible not to call an an initializer multiple times. If each `__init__` method in the hierarchy calls `super().__init__()`, then each initializer will be called exactly once according to the MRO of the subclass. When explicitly calling base class initializers (such as to pass different arguments to different initializers), ensure this is done consistently throughout, rather than using `super()` calls in the base classes.

In some cases, it may not be possible to avoid calling a base initializer multiple times without significant refactoring. In this case, carefully check that the initializer does not interfere with subclass initializers when called multiple times (such as by overwriting attributes), and ensure this behavior is documented.


## Example
In the following (BAD) example, the class `D` calls `B.__init__` and `C.__init__`, which each call `A.__init__`. This results in `self.state` being set to `None` as `A.__init__` is called again after `B.__init__` had finished. This may lead to unexpected results.


```python
class A:
    def __init__(self):
        self.state = None 

class B(A):
    def __init__(self):
        A.__init__(self)
        self.state = "B"
        self.b = 3 

class C(A):
    def __init__(self):
        A.__init__(self)
        self.c = 2 

class D(B,C):
    def __init__(self):
        B.__init__(self)
        C.__init__(self) # BAD: This calls A.__init__ a second time, setting self.state to None.
        

```
In the following (GOOD) example, a call to `super().__init__` is made in each class in the inheritance hierarchy, ensuring each initializer is called exactly once.


```python
class A:
    def __init__(self):
        self.state = None 

class B(A):
    def __init__(self):
        super().__init__()
        self.state = "B"
        self.b = 3 

class C(A):
    def __init__(self):
        super().__init__()
        self.c = 2 

class D(B,C):
    def __init__(self): # GOOD: Each method calls super, so each init method runs once. self.state will be set to "B".
        super().__init__()
        self.d = 1
        



```
In the following (BAD) example, explicit base class calls are mixed with `super()` calls, and `C.__init__` is called twice.


```python
class A:
    def __init__(self):
        print("A")
        self.state = None 

class B(A):
    def __init__(self):
        print("B")
        super().__init__() # When called from D, this calls C.__init__
        self.state = "B"
        self.b = 3 

class C(A):
    def __init__(self):
        print("C")
        super().__init__()
        self.c = 2 

class D(B,C):
    def __init__(self): 
        B.__init__(self)
        C.__init__(self) # BAD: C.__init__ is called a second time
```

## References
* Python Reference: [__init__](https://docs.python.org/3/reference/datamodel.html#object.__init__).
* Python Standard Library: [super](https://docs.python.org/3/library/functions.html#super).
* Python Glossary: [Method resolution order](https://docs.python.org/3/glossary.html#term-method-resolution-order).
* Wikipedia: [The Diamond Problem](https://en.wikipedia.org/wiki/Multiple_inheritance#The_diamond_problem).
