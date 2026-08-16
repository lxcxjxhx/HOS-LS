# Construction of a cookie using user-supplied input
Constructing cookies from user input can allow an attacker to control a user's cookie. This may lead to a session fixation attack. Additionally, client code may not expect a cookie to contain attacker-controlled data, and fail to sanitize it for common vulnerabilities such as Cross Site Scripting (XSS). An attacker manipulating the raw cookie header may additionally be able to set cookie attributes such as `HttpOnly` to insecure values.


## Recommendation
Do not use raw user input to construct cookies.


## Example
In the following cases, a cookie is constructed for a Flask response using user input. The first uses `set_cookie`, and the second sets a cookie's raw value through the `set-cookie` header.


```python
from flask import request, make_response


@app.route("/1")
def set_cookie():
    resp = make_response()
    resp.set_cookie(request.args["name"], # BAD: User input is used to set the cookie's name and value
                    value=request.args["name"])
    return resp


@app.route("/2")
def set_cookie_header():
    resp = make_response()
    resp.headers['Set-Cookie'] = f"{request.args['name']}={request.args['name']};" # BAD: User input is used to set the raw cookie header.
    return resp

```

## References
* Wikipedia - [Session Fixation](https://en.wikipedia.org/wiki/Session_fixation).
* Common Weakness Enumeration: [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
