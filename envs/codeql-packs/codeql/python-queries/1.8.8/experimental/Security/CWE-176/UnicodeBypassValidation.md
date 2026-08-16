# Bypass Logical Validation Using Unicode Characters
Security checks bypass due to a Unicode transformation

If security checks or logical validation is performed before unicode normalization, the security checks or logical validation could be bypassed due to a potential Unicode character collision. The validation we consider are: any character escaping, any regex validation, or any string manipulation (such as `str.split`).


## Recommendation
Perform Unicode normalization before the logical validation.


## Example
The following example showcases the bypass of all checks performed by ` flask.escape()` due to a post-unicode normalization.

For instance: the character U+FE64 (`﹤`) is not filtered-out by the flask escape function. But due to the Unicode normalization, the character is transformed and would become U+003C (` < ` ).


```python
import unicodedata
from flask import Flask, request, escape, render_template

app = Flask(__name__)


@app.route("/unsafe1")
def unsafe1():
    user_input = escape(request.args.get("ui"))
    normalized_user_input = unicodedata.normalize("NFKC", user_input)
    return render_template("result.html", normalized_user_input=normalized_user_input)

```

## References
* Research study: [ Unicode vulnerabilities that could bYte you ](https://gosecure.github.io/presentations/2021-02-unicode-owasp-toronto/philippe_arteau_owasp_unicode_v4.pdf) and [Unicode pentest cheatsheet](https://gosecure.github.io/unicode-pentester-cheatsheet/).
* Common Weakness Enumeration: [CWE-176](https://cwe.mitre.org/data/definitions/176.html).
* Common Weakness Enumeration: [CWE-179](https://cwe.mitre.org/data/definitions/179.html).
* Common Weakness Enumeration: [CWE-180](https://cwe.mitre.org/data/definitions/180.html).
