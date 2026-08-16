# Backspace escape in regular expression
The meaning of the `\b` escape sequence inside a regular expression depends on its syntactic context: inside a character class, it matches the backspace character; outside of a character class, it matches a word boundary. This context dependency makes regular expressions hard to read, so the `\b` escape sequence should not be used inside character classes.


## Recommendation
Replace `\b` in character classes with the semantically identical escape sequence `\x08`.


## Example
In the following example, the regular expression contains two uses of `\b`: in the first case, it matches a word boundary, in the second case it matches a backspace character.


```python
import re
matcher = re.compile(r"\b[\t\b]")

def match_data(data):
    return bool(matcher.match(data))

```
You can make the regular expression easier for other developers to interpret, by rewriting it as `r"\b[\t\x08]"`.


## References
* Python Standard Library: [Regular expression operations](https://docs.python.org/library/re.html).
