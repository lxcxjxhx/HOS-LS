# Unmatchable caret in regular expression
The caret character `^` anchors a regular expression to the beginning of the input, or (for multi-line regular expressions) to the beginning of a line. If it is preceded by a pattern that must match a non-empty sequence of (non-newline) input characters, then the entire regular expression cannot match anything.


## Recommendation
Examine the regular expression to find and correct any typos.


## Example
In the following example, the regular expression `r"\[^.]*\.css"` cannot match any string, since it contains a caret assertion preceded by an escape sequence that matches an opening bracket.

In the second regular expression, `r"[^.]*\.css"`, the caret is part of a character class, and will not match the start of the string.


```python
import re
#Regular expression includes a caret, but not at the start.
matcher = re.compile(r"\[^.]*\.css")

def find_css(filename):
    if matcher.match(filename):
        print("Found it!")
        
#Regular expression for a css file name
fixed_matcher_css = re.compile(r"[^.]*\.css")


```

## References
* Python Standard Library: [Regular expression operations](https://docs.python.org/library/re.html).
* Regular-Expressions.info: [Start of String and End of String Anchors](http://www.regular-expressions.info/anchors.html).
