# Unmatchable dollar in regular expression
A dollar assertion `$` in a regular expression only matches at the end of the input, or (for multi-line regular expressions) at the end of a line. If it is followed by a pattern that must match a non-empty sequence of (non-newline) input characters, it cannot possibly match, rendering the entire regular expression unmatchable.


## Recommendation
Examine the regular expression to find and correct any typos.


## Example
In the following example, the regular expression `r"\.\(\w+$\)"` cannot match any string, since it contains a dollar assertion followed by an escape sequence that matches a closing parenthesis.

The second regular expression, `r"\.\(\w+\)$"`, has the dollar at the end and will work as expected.


```python
import re
#Regular expression that includes a dollar, but not at the end.
matcher = re.compile(r"\.\(\w+$\)")

def find_it(filename):
    if matcher.match(filename):
        print("Found it!")

#Regular expression anchored to end of input.
fixed_matcher = re.compile(r"\.\(\w+\)$")
```

## References
* Python Standard Library: [Regular expression operations](https://docs.python.org/library/re.html).
* Regular-Expressions.info: [Start of String and End of String Anchors](http://www.regular-expressions.info/anchors.html).
