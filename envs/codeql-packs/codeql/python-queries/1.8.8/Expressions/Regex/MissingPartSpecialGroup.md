# Missing part of special group in regular expression
One of the problems with using regular expressions is that almost any sequence of characters is a valid pattern. This means that it is easy to omit a necessary character and still have a valid regular expression. Omitting a character in a named capturing group is a specific case which can dramatically change the meaning of a regular expression.


## Recommendation
Examine the regular expression to find and correct any typos.


## Example
In the following example, the regular expression for `matcher`, `r"(P<name>[\w]+)"`, is missing a "?" and will match only strings of letters that start with "P&lt;name&gt;", instead of matching any sequence of letters and placing the result in a named group. The fixed version, `fixed_matcher`, includes the "?" and will work as expected.


```python
import re
matcher = re.compile(r'(P<name>[\w]+)')

def only_letters(text):
    m = matcher.match(text)
    if m:
        print("Letters are: " + m.group('name'))

#Fix the pattern by adding the missing '?'
fixed_matcher = re.compile(r'(?P<name>[\w]+)')
```

## References
* Python Standard Library: [Regular expression operations](https://docs.python.org/library/re.html).
* Regular-Expressions.info: [Named Capturing Groups](http://www.regular-expressions.info/named.html).
