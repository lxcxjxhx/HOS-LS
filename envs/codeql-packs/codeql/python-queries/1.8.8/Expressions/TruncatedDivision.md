# Result of integer division may be truncated
In Python 2, the result of dividing two integers is silently truncated into an integer. This may lead to unexpected behavior.


## Recommendation
If the division should never be truncated, add `from __future__ import division` to the beginning of the file. If the division should always be truncated, replace the division operator `/` with the truncated division operator `//`.


## Example
The first example shows a function for calculating the average of a sequence of numbers. When the function runs under Python 2, and the sequence contains only integers, an incorrect result may be returned because the result is truncated. The second example corrects this error by following the recommendation listed above.


```python
# Incorrect:

def average(l):
    return sum(l) / len(l)

print average([1.0, 2.0])  # Prints "1.5".
print average([1, 2])      # Prints "1", which is incorrect.

```

```python
# Correct:
from __future__ import division

def average(l):
    return sum(l) / len(l)

print average([1.0, 2.0])  # Prints "1.5".
print average([1, 2])      # Prints "1.5".

```

## References
* Python Language Reference: [Binary arithmetic operations](https://docs.python.org/2/reference/expressions.html#binary-arithmetic-operations).
* PEP 238: [Changing the Division Operator](https://www.python.org/dev/peps/pep-0238/).
* PEP 236: [Back to the __future__](https://www.python.org/dev/peps/pep-0236/).
