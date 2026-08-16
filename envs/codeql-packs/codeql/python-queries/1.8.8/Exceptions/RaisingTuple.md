# Raising a tuple
In Python 2, if a tuple is raised then all elements but the first are ignored and only the first part is raised. If the first element is itself a tuple, then the first element of that is used and so on. This unlikely to be the intended effect and will most likely indicate some sort of error.

It is important to note that the exception in `raise Exception, message` is *not* a tuple, whereas the exception in `ex = Exception, message; raise ex` *is* a tuple.

In Python 3, raising a tuple is an error.


## Recommendation
Given that all but the first element of the tuple is ignored, the tuple should be replaced with its first element in order to improve the clarity of the code. If the subsequent parts of the tuple were intended to form the message, then they should be passed as an argument when creating the exception.


## Example
In the following example the intended error message is mistakenly used to form a tuple.


```python


def raise_tuple():
    ex = Exception, "Important diagnostic information"
    raise ex

```
This can be fixed, either by using the message to create the exception or using the message in the raise statement, as shown below.


```python


def fixed_raise_tuple1():
    ex = Exception("Important diagnostic information")
    raise ex


def fixed_raise_tuple2():
    raise Exception, "Important diagnostic information"

```

## References
* Python Language Reference: [Exceptions](https://docs.python.org/reference/executionmodel.html#exceptions).
* Python Tutorial: [Handling Exceptions](https://docs.python.org/tutorial/errors.html#handling-exceptions).
