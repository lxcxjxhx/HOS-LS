# CSRF protection weakened or disabled
Cross-site request forgery (CSRF) is a type of vulnerability in which an attacker is able to force a user to carry out an action that the user did not intend.

The attacker tricks an authenticated user into submitting a request to the web application. Typically this request will result in a state change on the server, such as changing the user's password. The request can be initiated when the user visits a site controlled by the attacker. If the web application relies only on cookies for authentication, or on other credentials that are automatically included in the request, then this request will appear as legitimate to the server.

A common countermeasure for CSRF is to generate a unique token to be included in the HTML sent from the server to a user. This token can be used as a hidden field to be sent back with requests to the server, where the server can then check that the token is valid and associated with the relevant user session.


## Recommendation
In many web frameworks, CSRF protection is enabled by default. In these cases, using the default configuration is sufficient to guard against most CSRF attacks.


## Example
The following example shows a case where CSRF protection is disabled by overriding the default middleware stack and not including the one protecting against CSRF.


```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

```
The protecting middleware was probably commented out during a testing phase, when server-side token generation was not set up. Simply commenting it back in will enable CSRF protection.


## References
* Wikipedia: [Cross-site request forgery](https://en.wikipedia.org/wiki/Cross-site_request_forgery)
* OWASP: [Cross-site request forgery](https://owasp.org/www-community/attacks/csrf)
* Common Weakness Enumeration: [CWE-352](https://cwe.mitre.org/data/definitions/352.html).
