# Signature mismatch in overriding method
When the signature of a method of a base class and a method of a subclass that overrides it don't match, a call to the base class method may not be a valid call to the subclass method, and thus raise an exception if an instance of the subclass is passed instead. If following the Liskov Substitution Principle, in which an instance of a subclass should be usable in every context as though it were an instance of the base class, this behavior breaks the principle.


## Recommendation
Ensure that the overriding method in the subclass accepts the same parameters as the base method.


## Example
In the following example, `Base.runsource` takes an optional `filename` argument. However, the overriding method `Sub.runsource` does not. This means the `run` function will fail if passed an instance of `Sub`.


```python

class Base:
    def runsource(self, source, filename="<input>"):
        ...
    
    
class Sub(Base):
    def runsource(self, source): # BAD: Does not match the signature of overridden method.
        ... 

def run(obj: Base):
    obj.runsource("source", filename="foo.txt")
```

## References
* Wikipedia: [Liskov Substitution Principle](http://en.wikipedia.org/wiki/Liskov_substitution_principle), [Method overriding](http://en.wikipedia.org/wiki/Method_overriding#Python).
