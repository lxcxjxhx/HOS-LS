# Wrong number of arguments in a class instantiation
A call to the `__init__` method of a class must supply an argument for each parameter that does not have a default value defined, so:

* The minimum number of arguments is the number of parameters without default values.
* The maximum number of arguments is the total number of parameters, unless the class `__init__` method takes a varargs (starred) parameter in which case there is no limit.

## Recommendation
If there are too few arguments then check to see which arguments have been omitted and supply values for those.

If there are too many arguments then check to see if any have been added by mistake and remove those.

Also check where a comma has been inserted instead of an operator or a dot. For example, the code is `obj,attr` when it should be `obj.attr`.

If it is not clear which are the missing or surplus arguments, then this suggests a logical error. The fix will then depend on the nature of the error.


## Example

```python
class Point(object):
    def __init__(self, x, y):
        self.x = x
        self.y = y

p = Point(1)      # TypeError: too few arguments
p = Point(1,2,3)  # TypeError: too many arguments

```

## References
* Python Glossary: [Arguments](https://docs.python.org/2/glossary.html#term-argument).
* Python Glossary: [Parameters](https://docs.python.org/glossary.html#term-parameter).
* Python Programming FAQ: [ What is the difference between arguments and parameters?](https://docs.python.org/2/faq/programming.html#faq-argument-vs-parameter).
* The Python Language Reference: [Data model: object.__init__](https://docs.python.org/3/reference/datamodel.html#object.__init__)
* The Python Tutorial: [Classes](https://docs.python.org/3/tutorial/classes.html)
* Common Weakness Enumeration: [CWE-685](https://cwe.mitre.org/data/definitions/685.html).
