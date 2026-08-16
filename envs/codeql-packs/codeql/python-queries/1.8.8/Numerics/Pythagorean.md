# Pythagorean calculation with sub-optimal numerics
Calculating the length of the hypotenuse using the standard formula `c = sqrt(a**2 + b**2)` may lead to overflow if the two other sides are both very large. Even though `c` will not be much bigger than `max(a, b)`, either `a**2` or `b**2` (or both) will. Thus, the calculation could overflow, even though the result is well within representable range.


## Recommendation
Rather than `sqrt(a**2 + b**2)`, use the built-in function `hypot(a,b)` from the `math` library.


## Example
The following code shows two different ways of computing the hypotenuse. The first is a direct rewrite of the Pythagorean theorem, the second uses the built-in function.


```python
# We know that a^2 + b^2 = c^2, and wish to use this to compute c
from math import sqrt, hypot

a = 3e154 # a^2 > 1e308
b = 4e154 # b^2 > 1e308
# with these, c = 5e154 which is less that 1e308

def longSideDirect():
    return sqrt(a**2 + b**2) # this will overflow

def longSideBuiltin():
    return hypot(a, b) # better to use built-in function
```

## References
* Python Language Reference: [The hypot function](https://docs.python.org/library/math.html#math.hypot)
* Wikipedia: [Hypot](https://en.wikipedia.org/wiki/Hypot).
