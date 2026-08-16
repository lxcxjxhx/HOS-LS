# Denial of Service using Unicode Characters
When a remote user-controlled data can reach a costly Unicode normalization with either form, NFKC or NFKD, an attack such as the One Million Unicode Characters, could lead to a denial of service on Windows OS.

And, with the use of special Unicode characters, like U+2100 (℀) or U+2105 (℅), the payload size could be tripled after the compatibility normalization.


## Recommendation
Ensure limiting the size of any incoming data that would go through a costly operations, including a Windows Unicode normalization with NFKC or NFKD. Such a recommandation would avoid a potential denial of service.


## Example
In this example a simple user-controlled data reaches a Unicode normalization with the form "NFKC".


```python
from flask import Flask, jsonify, request
import unicodedata

app = Flask(__name__)


@app.route("/bad_1")
def bad_1():
    # User controlled data
    file_path = request.args.get("file_path", "")

    # Normalize the file path using NFKC Unicode normalization
    return (
        unicodedata.normalize("NFKC", file_path),
        200,
        {"Content-Type": "application/octet-stream"},
    )

```
To fix this vulnerability, we need restrain the size of the user input.

For example, we can use the `len()` builtin function to limit the size of the user input.


```python
from flask import Flask, jsonify, request
import unicodedata

app = Flask(__name__)


@app.route("/good_1")
def good_1():
    r = request.args.get("file_path", "")

    if len(r) <= 1_000:
        # Normalize the r using NFKD Unicode normalization
        r = unicodedata.normalize("NFKD", r)
        return r, 200, {"Content-Type": "application/octet-stream"}
    else:
        return jsonify({"error": "File not found"}), 404

```

## References
* [CVE-2023-46695: Potential denial of service vulnerability in Django UsernameField on Windows.](https://hackerone.com/reports/2258758)
* Common Weakness Enumeration: [CWE-770](https://cwe.mitre.org/data/definitions/770.html).
