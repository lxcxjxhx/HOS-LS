# Missing call to superclass `__init__` during object initialization
Python, unlike some other object-oriented languages such as Java, allows the developer complete freedom in when and how superclass initializers are called during object initialization. However, the developer has responsibility for ensuring that objects are properly initialized, and that all superclass `__init__` methods are called.

If the `__init__` method of a superclass is not called during object initialization, this can lead to errors due to the object not being fully initialized, such as having missing attributes.

A call to the `__init__` method of a superclass during object initialization may be unintentionally skipped:

* If a subclass calls the `__init__` method of the wrong class.
* If a call to the `__init__` method of one its base classes is omitted.
* If a call to `super().__init__` is used, but not all `__init__` methods in the Method Resolution Order (MRO) chain themselves call `super()`. This in particular arises more often in cases of multiple inheritance.

## Recommendation
Ensure that all superclass `__init__` methods are properly called. Either each base class's initialize method should be explicitly called, or `super()` calls should be consistently used throughout the inheritance hierarchy.


## Example
In the following example, explicit calls to `__init__` are used, but `SportsCar` erroneously calls `Vehicle.__init__`. This is fixed in `FixedSportsCar` by calling `Car.__init__`.


```python

class Vehicle(object):
    
    def __init__(self):
        self.mobile = True
        
class Car(Vehicle):
    
    def __init__(self):
        Vehicle.__init__(self)
        self.car_init()
        
# BAD: Car.__init__ is not called.
class SportsCar(Car, Vehicle):
    
    def __init__(self):
        Vehicle.__init__(self)
        self.sports_car_init()
        
# GOOD: Car.__init__ is called correctly.
class FixedSportsCar(Car, Vehicle):
    
    def __init__(self):
        Car.__init__(self)
        self.sports_car_init()
        

```

## References
* Python Reference: [__init__](https://docs.python.org/3/reference/datamodel.html#object.__init__).
* Python Standard Library: [super](https://docs.python.org/3/library/functions.html#super).
* Python Glossary: [Method resolution order](https://docs.python.org/3/glossary.html#term-method-resolution-order).
