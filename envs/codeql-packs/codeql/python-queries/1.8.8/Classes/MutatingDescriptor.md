# Mutation of descriptor in `__get__` or `__set__` method
The descriptor protocol allows user programmable attribute access. The descriptor protocol is what enables class methods, static methods, properties and `super()`.

Descriptor objects are class attributes which control the behavior of instance attributes. Consequently, a single descriptor is common to all instances of a class and should not be mutated when instance attributes are accessed.


## Recommendation
Do not mutate the descriptor object, rather create a new object that contains the necessary state.


## Example
In this example the descriptor class `MutatingDescriptor` stores a reference to `obj` in an attribute.


```python

#This is prone to strange side effects and race conditions.
class MutatingDescriptor(object):
    
    def __init__(self, func):
        self.my_func = func
        
    def __get__(self, obj, obj_type):
        #Modified state is visible to all instances of C that might call "show".
        self.my_obj = obj
        return self
        
    def __call__(self, *args):
        return self.my_func(self.my_obj, *args)
    
def show(obj):
    print (obj)
    
class C(object):
    
    def __init__(self, value):
        self.value = value
        
    def __str__(self):
        return ("C: " + str(self.value))
    
    show = MutatingDescriptor(show)
    
c1 = C(1)
c1.show()
c2 = C(2)
c2.show()
c1_show = c1.show
c2.show
c1_show()

#Outputs:
#C: 1
#C: 2
#C: 2
```
In the following example, the descriptor class `NonMutatingDescriptor` returns a new object every time `__get__` is called.


```python
import types

#Immutable version, which is safe to share.
class NonMutatingDescriptor(object):
    
    def __init__(self, func):
        self.my_func = func
        
    def __get__(self, obj, obj_type):
        #Return a new object to each access.
        return types.MethodType(self.my_func, obj)
    
def show(obj):
    print (obj)
    
class C(object):
    
    def __init__(self, value):
        self.value = value
        
    def __str__(self):
        return ("C: " + str(self.value))
    
    show = NonMutatingDescriptor(show)
    
c1 = C(1)
c1.show()
c2 = C(2)
c2.show()
c1_show = c1.show
c2.show
c1_show()

#Outputs:
#C: 1
#C: 2
#C: 1
```

## References
* Python Language Reference: [Implementing Descriptors.](https://docs.python.org/reference/datamodel.html#descriptors)
* Mark Lutz. *Learning Python*, Section 30.6: Methods Are Objects: Bound or Unbound. O'Reilly 2013.
* A real world example: [NumPy Issue 5247.](https://github.com/numpy/numpy/issues/5247)
