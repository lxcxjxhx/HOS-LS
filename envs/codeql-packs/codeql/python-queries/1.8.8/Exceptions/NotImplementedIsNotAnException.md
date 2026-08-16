# Raising `NotImplemented`
The constant `NotImplemented` is not an `Exception`, but is often confused for `NotImplementedError`. If it is used as an exception, such as in `raise NotImplemented` or `raise NotImplemented("message")`, a `TypeError` will be raised rather than the expected `NotImplemented`. This may make debugging more difficult.

`NotImplemented` should only be used as a special return value for implementing special methods such as `__lt__`. Code that is not intended to be called should raise `NotImplementedError`.


## Recommendation
If a `NotImplementedError` is intended to be raised, replace the use of `NotImplemented` with that. If `NotImplemented` is intended to be returned rather than raised, replace the `raise` with `return NotImplemented`.


## Example
In the following example, the method `wrong` will incorrectly raise a `TypeError` when called. The method `right` will raise a `NotImplementedError`.


```python

class Abstract(object):

    def wrong(self):
        # Will raise a TypeError
        raise NotImplemented()

    def right(self):
        raise NotImplementedError()

```

## References
* Python Language Reference: [The NotImplementedError exception](https://docs.python.org/library/exceptions.html#NotImplementedError).
* Python Language Reference: [The NotImplemented constant](https://docs.python.org/3/library/constants.html#NotImplemented).
* Python Language Reference: [Emulating numeric types](https://docs.python.org/3/reference/datamodel.html#emulating-numeric-types).
