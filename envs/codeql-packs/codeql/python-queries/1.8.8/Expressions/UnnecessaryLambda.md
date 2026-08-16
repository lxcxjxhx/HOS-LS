# Unnecessary lambda
A lambda that calls a function without modifying any of its parameters is unnecessary. Python functions are first class objects and can be passed around in the same way as the resulting lambda.


## Recommendation
Remove the lambda, use the function directly.


## Example
In this example a lambda is used unnecessarily in order to pass a method as an argument to ` call_with_x_squared`.


```python
import math

def call_with_x_squared(x, function):
    x = x*x
    return function(x)

print call_with_x_squared(2, lambda x: math.factorial(x))
```
This is not necessary as methods can be passed directly. They behave as callable objects.


```python
import math

def call_with_x_squared(x, function):
    x = x*x
    return function(x)

print call_with_x_squared(2, math.factorial)
```

## References
* Python: [lambdas](http://docs.python.org/2.7/reference/expressions.html#lambda).
