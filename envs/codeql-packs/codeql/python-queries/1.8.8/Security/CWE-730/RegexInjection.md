# Regular expression injection
Constructing a regular expression with unsanitized user input is dangerous as a malicious user may be able to modify the meaning of the expression. In particular, such a user may be able to provide a regular expression fragment that takes exponential time in the worst case, and use that to perform a Denial of Service attack.


## Recommendation
Before embedding user input into a regular expression, use a sanitization function such as `re.escape` to escape meta-characters that have a special meaning regarding regular expressions' syntax.


## Example
The following examples are based on a simple Flask web server environment.

The following example shows a HTTP request parameter that is used to construct a regular expression without sanitizing it first:


```python
from flask import request, Flask
import re


@app.route("/direct")
def direct():
    unsafe_pattern = request.args["pattern"]
    re.search(unsafe_pattern, "")


@app.route("/compile")
def compile():
    unsafe_pattern = request.args["pattern"]
    compiled_pattern = re.compile(unsafe_pattern)
    compiled_pattern.search("")

```
Instead, the request parameter should be sanitized first, for example using the function `re.escape`. This ensures that the user cannot insert characters which have a special meaning in regular expressions.


```python
from flask import request, Flask
import re


@app.route("/direct")
def direct():
    unsafe_pattern = request.args['pattern']
    safe_pattern = re.escape(unsafe_pattern)
    re.search(safe_pattern, "")


@app.route("/compile")
def compile():
    unsafe_pattern = request.args['pattern']
    safe_pattern = re.escape(unsafe_pattern)
    compiled_pattern = re.compile(safe_pattern)
    compiled_pattern.search("")

```

## References
* OWASP: [Regular expression Denial of Service - ReDoS](https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS).
* Wikipedia: [ReDoS](https://en.wikipedia.org/wiki/ReDoS).
* Python docs: [re](https://docs.python.org/3/library/re.html).
* SonarSource: [RSPEC-2631](https://rules.sonarsource.com/python/type/Vulnerability/RSPEC-2631).
* Common Weakness Enumeration: [CWE-730](https://cwe.mitre.org/data/definitions/730.html).
* Common Weakness Enumeration: [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
