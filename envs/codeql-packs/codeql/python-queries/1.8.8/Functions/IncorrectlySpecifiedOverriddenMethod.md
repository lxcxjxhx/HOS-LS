# Mismatch between signature and use of an overridden method
There is a call to the overriding method, and potentially the overridden method, with arguments that are not legal for the overridden method. This will cause an error if the overridden method is called and is a violation of the Liskov substitution principle.


## Recommendation
Ensure that the overridden method accepts all the parameters that are legal for overriding method(s).


## Example
In this example there is a mismatch between the legal parameters for the base class method `(self, source, filename)` and the extension method `(self, source)`. Since there is a call that uses the signature of the extension method then it can be inferred that the base signature is erroneous and should be updated to match that of the extension method.


```python

class BaseClass(object):

    def run(self, source, filename, symbol="single"):
        ... # Definition

    def load_and_run(self, filename):
        source = self.load(filename)
        self.run(source) # Matches signature in derived class, but not in this class.

class DerivedClass(BaseClass):

    def run(self, source):
        ... # Definition

```
The base method should be updated to either remove the `filename` parameters, or add a default value for it.


## References
* Wikipedia: [Liskov Substitution Principle](http://en.wikipedia.org/wiki/Liskov_substitution_principle), [Method overriding](http://en.wikipedia.org/wiki/Method_overriding#Python).
