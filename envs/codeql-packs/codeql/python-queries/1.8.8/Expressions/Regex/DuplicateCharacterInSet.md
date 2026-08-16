# Duplication in regular expression character class
Character classes in regular expressions represent sets of characters, so there is no need to specify the same character twice in one character class. Duplicate characters in character classes are at best useless, and may even indicate a latent bug.


## Recommendation
Determine whether a character is simply duplicated or whether the character class was in fact meant as a group. If it is just a duplicate, then remove the duplicate character. If was supposed to be a group, then replace the square brackets with parentheses.


## Example
In the following example, the character class `[password|pwd]` contains two instances each of the characters `d`, `p`, `s`, and `w`. The programmer most likely meant to write `(password|pwd)` (a pattern that matches either the string `"password"` or the string `"pwd"`), and accidentally mistyped the enclosing brackets.


```python
import re
matcher = re.compile(r"[password|pwd]")

def find_password(data):
    if matcher.match(data):
        print("Found password!")

```
To fix this problem, the regular expression should be rewritten to `r"(password|pwd)"`.


## References
* Python Standard Library: [Regular expression operations](https://docs.python.org/library/re.html).
* Regular-Expressions.info: [Character Classes or Character Sets](http://www.regular-expressions.info/charclass.html).
