# Full server-side request forgery
Directly incorporating user input into an HTTP request without validating the input can facilitate server-side request forgery (SSRF) attacks. In these attacks, the request may be changed, directed at a different server, or via a different protocol. This can allow the attacker to obtain sensitive information or perform actions with escalated privilege.

We make a distinctions between how much of the URL an attacker can control:

* **Full SSRF**: where the full URL can be controlled.
* **Partial SSRF**: where only part of the URL can be controlled, such as the path component of a URL to a hardcoded domain.


Partial control of a URL is often much harder to exploit. Therefore we have created a separate query for each of these.

This query covers full SSRF, to find partial SSRF use the `py/partial-ssrf` query.


## Recommendation
To guard against SSRF attacks you should avoid putting user-provided input directly into a request URL. On the application level, maintain a list of authorized URLs on the server and choose from that list based on the input provided. If that is not possible, one should verify the IP address for all user-controlled requests to ensure they are not private. This requires saving the verified IP address of each domain, then utilizing a custom HTTP adapter to ensure that future requests to that domain use the verified IP address. On the network level, you can segment the vulnerable application into its own LAN or block access to specific devices.


## Example
The following example shows code vulnerable to a full SSRF attack, because it uses untrusted input (HTTP request parameter) directly to construct a URL. By using `evil.com#` as the `target` value, the requested URL will be `https://evil.com#.example.com/data/`. It also shows how to remedy the problem by using the user input select a known fixed string.


```python
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route("/full_ssrf")
def full_ssrf():
    target = request.args["target"]

    # BAD: user has full control of URL
    resp = requests.get("https://" + target + ".example.com/data/")

    # GOOD: `subdomain` is controlled by the server.
    subdomain = "europe" if target == "EU" else "world"
    resp = requests.get("https://" + subdomain + ".example.com/data/")

```

## Example
The following example shows code vulnerable to a partial SSRF attack, because it uses untrusted input (HTTP request parameter) directly to construct a URL. By using `../transfer-funds-to/123?amount=456` as the `user_id` value, the requested URL will be `https://api.example.com/transfer-funds-to/123?amount=456`. It also shows how to remedy the problem by validating the input.


```python
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route("/partial_ssrf")
def partial_ssrf():
    user_id = request.args["user_id"]

    # BAD: user can fully control the path component of the URL
    resp = requests.get("https://api.example.com/user_info/" + user_id)

    if user_id.isalnum():
        # GOOD: user_id is restricted to be alpha-numeric, and cannot alter path component of URL
        resp = requests.get("https://api.example.com/user_info/" + user_id)

```

## References
* [OWASP SSRF article](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
* [PortSwigger SSRF article](https://portswigger.net/web-security/ssrf)
* Common Weakness Enumeration: [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
