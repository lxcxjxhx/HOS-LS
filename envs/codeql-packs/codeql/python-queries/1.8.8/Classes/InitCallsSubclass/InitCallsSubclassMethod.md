# `__init__` method calls overridden method
When initializing an instance of the class in the class' `__init__` method, calls tha are made using the instance may receive an instance of the class that is not yet fully initialized. When a method called in an initializer is overridden in a subclass, the subclass method receives the instance in a potentially unexpected state. Fields that would be initialized after the call, including potentially in the subclass' `__init__` method, will not be initialized. This may lead to runtime errors, as well as make the code more difficult to maintain, as future changes may not be aware of which fields would not be initialized.


## Recommendation
If possible, refactor the initializer method such that initialization is complete before calling any overridden methods. For helper methods used as part of initialization, avoid overriding them, and instead call any additional logic required in the subclass' `__init__` method.

If the overridden method does not depend on the instance `self`, and only on its class, consider making it a `@classmethod` or `@staticmethod` instead.

If calling an overridden method is absolutely required, consider marking it as an internal method (by using an `_` prefix) to discourage external users of the library from overriding it and observing partially initialized state, and ensure that the fact it is called during initialization is mentioned in the documentation.


## Example
In the following case, the `__init__` method of `Super` calls the `set_up` method that is overridden by `Sub`. This results in `Sub.set_up` being called with a partially initialized instance of `Super` which may be unexpected.


```python
class Super(object):

    def __init__(self, arg):
        self._state = "Not OK"
        self.set_up(arg) # BAD: This method is overridden, so `Sub.set_up` receives a partially initialized instance.
        self._state = "OK"

    def set_up(self, arg):
        "Do some setup"
        self.a = 2

class Sub(Super):

    def __init__(self, arg):
        super().__init__(arg)
        self.important_state = "OK"

    def set_up(self, arg):
        super().set_up(arg)
        "Do some more setup"
        # BAD: at this point `self._state` is set to `"Not OK"`, and `self.important_state` is not initialized.
        if self._state == "OK":
            self.b = self.a + 2

```
In the following case, the initialization methods are separate between the superclass and the subclass.


```python
class Super(object):

    def __init__(self, arg):
        self._state = "Not OK"
        self.super_set_up(arg) # GOOD: This isn't overriden. Instead, additional setup the subclass needs is called by the subclass' `__init__ method.`
        self._state = "OK"

    def super_set_up(self, arg):
        "Do some setup"
        self.a = 2


class Sub(Super):

    def __init__(self, arg):
        super().__init__(arg)
        self.sub_set_up(self, arg)
        self.important_state = "OK"


    def sub_set_up(self, arg):
        "Do some more setup"
        if self._state == "OK":
            self.b = self.a + 2
```

## References
* CERT Secure Coding: [ Rule MET05-J](https://www.securecoding.cert.org/confluence/display/java/MET05-J.+Ensure+that+constructors+do+not+call+overridable+methods). Reference discusses Java but is applicable to object oriented programming in many languages.
* StackOverflow: [Overridable method calls in constructors](https://stackoverflow.com/questions/3404301/whats-wrong-with-overridable-method-calls-in-constructors).
* Python documentation: [@classmethod](https://docs.python.org/3/library/functions.html#classmethod).
