# Overly permissive regular expression range
It's easy to write a regular expression range that matches a wider range of characters than you intended. For example, `/[a-zA-z]/` matches all lowercase and all uppercase letters, as you would expect, but it also matches the characters: `` [ \ ] ^ _ ` ``.

Another common problem is failing to escape the dash character in a regular expression. An unescaped dash is interpreted as part of a range. For example, in the character class `[a-zA-Z0-9%=.,-_]` the last character range matches the 55 characters between `,` and `_` (both included), which overlaps with the range `[0-9]` and is clearly not intended by the writer.


## Recommendation
Avoid any confusion about which characters are included in the range by writing unambiguous regular expressions. Always check that character ranges match only the expected characters.


## Example
The following example code is intended to check whether a string is a valid 6 digit hex color.

```python

import re
def is_valid_hex_color(color):
    return re.match(r'^#[0-9a-fA-f]{6}$', color) is not None

```
However, the `A-f` range is overly large and matches every uppercase character. It would parse a "color" like `#XXYYZZ` as valid.

The fix is to use an uppercase `A-F` range instead.

```python

import re
def is_valid_hex_color(color):
    return re.match(r'^#[0-9a-fA-F]{6}$', color) is not None

```

## References
* GitHub Advisory Database: [CVE-2021-42740: Improper Neutralization of Special Elements used in a Command in Shell-quote](https://github.com/advisories/GHSA-g4rg-993r-mgx7)
* wh0.github.io: [Exploiting CVE-2021-42740](https://wh0.github.io/2021/10/28/shell-quote-rce-exploiting.html)
* Yosuke Ota: [no-obscure-range](https://ota-meshi.github.io/eslint-plugin-regexp/rules/no-obscure-range.html)
* Paul Boyd: [The regex \[,-.\]](https://pboyd.io/posts/comma-dash-dot/)
* Common Weakness Enumeration: [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
