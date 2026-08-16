# Mismatch between signature and use of an overriding method
There is a call to the overridden method, and potentially the overriding method, with arguments that are not legal for the overriding method. This will cause an error if the overriding method is called and is a violation of the Liskov substitution principle.


## Recommendation
Ensure that the overriding method accepts all the parameters that are legal for the overridden method.


## Example
In this example there is a mismatch between the legal parameters for the base class method `(self, source, filename, symbol)` and the extension method `(self, source)`. The extension method can be used to override the base method as long as values are not specified for the `filename` and (optional) `symbol` parameters. If the extension method was passed the additional parameters accepted by the base method then an error would occur.


```python

class BaseClass(object):

    def run(self, source, filename, symbol="single"):
        ... # Definition

    def load_and_run(self, filename):
        source = self.load(filename)
        self.run(source, filename) # Matches signature in this class, but not in the derived class.

class DerivedClass(BaseClass):

    def run(self, source):
        ... # Definition

```
The extension method should be updated to support the `filename` and `symbol` parameters supported by the overridden method.


## References
* Wikipedia: [Liskov Substitution Principle](http://en.wikipedia.org/wiki/Liskov_substitution_principle), [Method overriding](http://en.wikipedia.org/wiki/Method_overriding#Python).
