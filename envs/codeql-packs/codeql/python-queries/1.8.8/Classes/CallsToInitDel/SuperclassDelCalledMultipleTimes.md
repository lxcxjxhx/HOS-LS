# Multiple calls to `__del__` during object destruction
Python, unlike some other object-oriented languages such as Java, allows the developer complete freedom in when and how superclass finalizers are called during object finalization. However, the developer has responsibility for ensuring that objects are properly cleaned up.

Objects with a `__del__` method (a finalizer) often hold resources such as file handles that need to be cleaned up. If a superclass finalizer is called multiple times, this may lead to errors such as closing an already closed file, and lead to objects not being cleaned up properly as expected.

There are a number of ways that a `__del__` method may be called more than once.

* There may be more than one explicit call to the method in the hierarchy of `__del__` methods.
* In situations involving multiple inheritance, an finalization method may call the finalizers of each of its base types, which themselves both call the finalizer of a shared base type. (This is an example of the Diamond Inheritance problem)
* Another situation involving multiple inheritance arises when a subclass calls the `__del__` methods of each of its base classes, one of which calls `super().__del__`. This super call resolves to the next class in the Method Resolution Order (MRO) of the subclass, which may be another base class that already has its initializer explicitly called.

## Recommendation
Ensure that each finalizer method is called exactly once during finalization. This can be ensured by calling `super().__del__` for each finalizer method in the inheritance chain.


## Example
In the following example, there is a mixture of explicit calls to `__del__` and calls using `super()`, resulting in `Vehicle.__del__` being called twice. `FixedSportsCar.__del__` fixes this by using `super()` consistently with the other delete methods.


```python

#Calling a method multiple times by using explicit calls when a base uses super()
class Vehicle(object):
     
    def __del__(self):
        recycle(self.base_parts)
        super(Vehicle, self).__del__()
        
class Car(Vehicle):
    
    def __del__(self):
        recycle(self.car_parts)
        super(Car, self).__del__()
        
        
class SportsCar(Car, Vehicle):
    
    # BAD: Vehicle.__del__ will get called twice
    def __del__(self):
        recycle(self.sports_car_parts)
        Car.__del__(self)
        Vehicle.__del__(self)
        
        
# GOOD: super() is used ensuring each del method is called once.
class FixedSportsCar(Car, Vehicle):
    
    def __del__(self):
        recycle(self.sports_car_parts)
        super(SportsCar, self).__del__()
     


```

## References
* Python Reference: [__del__](https://docs.python.org/3/reference/datamodel.html#object.__del__).
* Python Standard Library: [super](https://docs.python.org/3/library/functions.html#super).
* Python Glossary: [Method resolution order](https://docs.python.org/3/glossary.html#term-method-resolution-order).
* Wikipedia: [The Diamond Problem](https://en.wikipedia.org/wiki/Multiple_inheritance#The_diamond_problem).
