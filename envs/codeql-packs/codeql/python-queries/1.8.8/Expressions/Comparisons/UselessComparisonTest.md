# Redundant comparison
The result of certain comparisons can sometimes be inferred from their context and the results of other comparisons. This can be an indication of faulty logic and may result in dead code or infinite loops if, for example, a loop condition never changes its value.


## Recommendation
Inspect the code to check whether the logic is correct, and consider simplifying the logical expression.


## Example
In the following (real world) example the test `obj1 < obj2` is repeated and thus the second test will always be false, and the function `_compare` will only ever return `0` or `-1`.


```python
  class KeySorter:

      def __init__(self, obj):
          self.obj = obj

      def __lt__(self, other):
          return self._compare(self.obj, other.obj) < 0

      def _compare(self, obj1, obj2):
          if obj1 < obj2:
              return -1
          elif obj1 < obj2:
              return 1
          else:
              return 0

```

## References
* Python Language Reference: [Comparisons](http://docs.python.org/2/reference/expressions.html#not-in).
* Common Weakness Enumeration: [CWE-561](https://cwe.mitre.org/data/definitions/561.html).
* Common Weakness Enumeration: [CWE-570](https://cwe.mitre.org/data/definitions/570.html).
* Common Weakness Enumeration: [CWE-571](https://cwe.mitre.org/data/definitions/571.html).
