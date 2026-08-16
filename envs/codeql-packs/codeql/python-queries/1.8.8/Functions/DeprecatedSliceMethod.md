# Deprecated slice method
The `__getslice__`, `__setslice__` and `__delslice__` methods have been deprecated since Python 2.0. In general, no class should implement these methods.

The only exceptions to this rule are classes that inherit from `list` and override `__getitem__`, `__setitem__` or `__delitem__`. Since `list` implements the slicing methods any class inheriting from `list` must implement the the slicing methods to ensure correct behavior of `__getitem__`, `__setitem__` and `__delitem__`. These exceptions to the rule will not be treated as violations.


## Recommendation
Delete the slicing method. Any functionality should be moved to the equivalent `__xxxitem__` method:

* `__getslice__` should be replaced with `__getitem__`
* `__setslice__` should be replaced with `__setitem__`
* `__delslice__` should be replaced with `__delitem__`

## References
* Python Language Reference: [ Additional methods for emulation of sequence types](https://docs.python.org/2/reference/datamodel.html#additional-methods-for-emulation-of-sequence-types).
