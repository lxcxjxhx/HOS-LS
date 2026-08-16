# Overwriting attribute in super-class or sub-class
Subclasses should not set attributes that are set in the superclass. Doing so may violate invariants in the superclass.


## Recommendation
If you did not intend to override the attribute value set in the superclass, then rename the subclass attribute. If you do want to be able to set a new value for the attribute of the superclass, then convert the superclass attribute to a property. Otherwise the value should be passed as a parameter to the superclass `__init__` method.


## Example

```python

#Attribute set in both superclass and subclass
class C(object):

    def __init__(self):
        self.var = 0

class D(C):

    def __init__(self):
        self.var = 1 # self.var will be overwritten
        C.__init__(self)

class E(object):

    def __init__(self):
        self.var = 0 # self.var will be overwritten

class F(E):

    def __init__(self):
        E.__init__(self)
        self.var = 1

#Fixed version -- Pass explicitly as a parameter
class G(object):

    def __init__(self, var = 0):
        self.var = var

class H(G):

    def __init__(self):
        G.__init__(self, 1)


```
