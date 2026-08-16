# Missing call to superclass `__del__` during object destruction
Python, unlike some other object-oriented languages such as Java, allows the developer complete freedom in when and how superclass finalizers are called during object finalization. However, the developer has responsibility for ensuring that objects are properly cleaned up, and that all superclass `__del__` methods are called.

Classes with a `__del__` method (a finalizer) typically hold some resource such as a file handle that needs to be cleaned up. If the `__del__` method of a superclass is not called during object finalization, it is likely that resources may be leaked.

A call to the `__del__` method of a superclass during object initialization may be unintentionally skipped:

* If a subclass calls the `__del__` method of the wrong class.
* If a call to the `__del__` method of one its base classes is omitted.
* If a call to `super().__del__` is used, but not all `__del__` methods in the Method Resolution Order (MRO) chain themselves call `super()`. This in particular arises more often in cases of multiple inheritance.

## Recommendation
Ensure that all superclass `__del__` methods are properly called. Either each base class's finalize method should be explicitly called, or `super()` calls should be consistently used throughout the inheritance hierarchy.


## Example
In the following example, explicit calls to `__del__` are used, but `SportsCar` erroneously calls `Vehicle.__del__`. This is fixed in `FixedSportsCar` by calling `Car.__del__`.


```python

class Vehicle(object):
    
    def __del__(self):
        recycle(self.base_parts)
        
class Car(Vehicle):
    
    def __del__(self):
        recycle(self.car_parts)
        Vehicle.__del__(self)
        
#BAD: Car.__del__ is not called.
class SportsCar(Car, Vehicle):
    
    def __del__(self):
        recycle(self.sports_car_parts)
        Vehicle.__del__(self)
        
#GOOD: Car.__del__ is called correctly.
class FixedSportsCar(Car, Vehicle):
    
    def __del__(self):
        recycle(self.sports_car_parts)
        Car.__del__(self)
        

```

## References
* Python Reference: [__del__](https://docs.python.org/3/reference/datamodel.html#object.__del__).
* Python Standard Library: [super](https://docs.python.org/3/library/functions.html#super).
* Python Glossary: [Method resolution order](https://docs.python.org/3/glossary.html#term-method-resolution-order).
