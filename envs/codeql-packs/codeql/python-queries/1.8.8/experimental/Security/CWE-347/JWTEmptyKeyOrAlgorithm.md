# JWT encoding using empty key or algorithm
Applications encoding a JSON Web Token (JWT) may be vulnerable when the applied key or algorithm is empty or `None`.


## Recommendation
Use non-empty nor `None` values while encoding JWT payloads.


## Example
This example shows two PyJWT encoding calls. In the first place, the encoding process use a None algorithm whereas the second example uses an empty key. Both examples leave the payload insecurely encoded.


```python
import jwt

# algorithm set to None
jwt.encode(payload, "somekey", None)

# empty key
jwt.encode(payload, key="", algorithm="HS256")

```

## References
* PyJWT: [Documentation](https://pyjwt.readthedocs.io/en/stable/).
* Authlib JWT: [Documentation](https://docs.authlib.org/en/latest/specs/rfc7519.html).
* Python-Jose: [Documentation](https://github.com/mpdavis/python-jose).
* Auth0 Blog: [Meet the "None" Algorithm](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/#Meet-the--None--Algorithm).
