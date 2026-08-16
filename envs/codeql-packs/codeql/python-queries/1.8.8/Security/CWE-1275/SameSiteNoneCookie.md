# Sensitive cookie with `SameSite` attribute set to `None`
Cookies with the `SameSite` attribute set to `'None'` will be sent with cross-origin requests. This can sometimes allow for Cross-Site Request Forgery (CSRF) attacks, in which a third-party site could perform actions on behalf of a user, if the cookie is used for authentication.


## Recommendation
Set the `samesite` to `Lax` or `Strict`, or add `; SameSite=Lax;`, or `; SameSite=Strict;` to the cookie's raw header value. The default value in most cases is `Lax`.


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
* MDN: [Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie).
* OWASP: [SameSite](https://owasp.org/www-community/SameSite).
* Common Weakness Enumeration: [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html).
