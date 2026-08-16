# Failure to use secure cookies
Cookies without the `Secure` flag set may be transmitted using HTTP instead of HTTPS. This leaves them vulnerable to being read by a third party attacker. If a sensitive cookie such as a session key is intercepted this way, it would allow the attacker to perform actions on a user's behalf.


## Recommendation
Always set `secure` to `True`, or add `; Secure;` to the cookie's raw header value, to ensure SSL is used to transmit the cookie with encryption.


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
* Detectify: [Cookie lack Secure flag](https://support.detectify.com/support/solutions/articles/48001048982-cookie-lack-secure-flag).
* PortSwigger: [TLS cookie without secure flag set](https://portswigger.net/kb/issues/00500200_tls-cookie-without-secure-flag-set).
* MDN: [Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie).
* Common Weakness Enumeration: [CWE-614](https://cwe.mitre.org/data/definitions/614.html).
