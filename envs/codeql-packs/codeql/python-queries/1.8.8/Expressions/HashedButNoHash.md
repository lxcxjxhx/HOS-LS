# Unhashable object hashed
If an object is used as a key in a dictionary or as a member of a set then it must be hashable, that is it must define a `__hash__` method. All built-in immutable types are hashable, but mutable ones are not. Common hashable types include all numbers, strings (both `unicode` and `bytes`) and `tuple`. Common unhashable types include `list`, `dict` and `set`.

In order to store a key in a `dict` or `set` a hash value is needed. To determine this value the built-in function `hash()` is called which in turn calls the `__hash__` method on the object. If the object's class does not have the `__hash__` method, then a `TypeError` will be raised.


## Recommendation
Since this problem usually indicates a logical error, it is not possible to give a general recipe for fixing it. Mutable collections can be converted into immutable equivalents where appropriate. For example sets can be hashed by converting any instances of `set` into `frozenset` instances.


## Example
`list`s are not hashable. In this example, an attempt is made to use a `list` as a key in a mapping which will fail with a `TypeError`.


```python

def lookup_with_default_key(mapping, key=None):
    if key is None:
        key = [] # Should be key = ()
    return mapping[key]

```

## References
* Python Standard Library: [hash](http://docs.python.org/library/functions.html#hash).
* Python Language Reference: [object.__hash__](http://docs.python.org/reference/datamodel.html#object.__hash__).
* Python Standard Library: [Mapping Types &mdash; dict](http://docs.python.org/library/stdtypes.html#mapping-types-dict).
* Python Standard Library: [Set Types &mdash; set, frozenset](http://docs.python.org/2/library/stdtypes.html#set-types-set-frozenset).
