# Sensitive cookie missing `HttpOnly` attribute
Cookies without the `HttpOnly` flag set are accessible to JavaScript running in the same origin. In case of a Cross-Site Scripting (XSS) vulnerability, the cookie can be stolen by a malicious script. If a sensitive cookie does not need to be accessed directly by client-side JS, the `HttpOnly` flag should be set.


## Recommendation
Set `httponly` to `True`, or add `; HttpOnly;` to the cookie's raw header value, to ensure that the cookie is not accessible via JavaScript.


## Example
In the following examples, the cases marked GOOD show secure cookie attributes being set; whereas in the case marked BAD they are not set.


```python
from flask import Flask, request, make_response, Response


@app.route("/good1")
def good1():
    resp = make_response()
    resp.set_cookie("sessionid", value="value", secure=True, httponly=True, samesite='Strict') # GOOD: Attributes are securely set
    return resp


@app.route("/good2")
def good2():
    resp = make_response()
    resp.headers['Set-Cookie'] = "sessionid=value; Secure; HttpOnly; SameSite=Strict" # GOOD: Attributes are securely set 
    return resp

@app.route("/bad1")
def bad1():
    resp = make_response()
    resp.set_cookie("sessionid", value="value", samesite='None') # BAD: the SameSite attribute is set to 'None' and the 'Secure' and 'HttpOnly' attributes are set to False by default.
    return resp
```

## References
* PortSwigger: [Cookie without HttpOnly flag set](https://portswigger.net/kb/issues/00500600_cookie-without-httponly-flag-set)
* MDN: [Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie).
* Common Weakness Enumeration: [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html).
