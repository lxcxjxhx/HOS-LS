# Timing attack against header value
A constant-time algorithm should be used for checking the value of sensitive headers. In other words, the comparison time should not depend on the content of the input. Otherwise timing information could be used to infer the header's expected, secret value.


## Recommendation
Two types of countermeasures can be applied against timing attacks. The first one consists in eliminating timing variations whereas the second renders these variations useless for an attacker. The only absolute way to prevent timing attacks is to make the computation strictly constant time, independent of the input. Use `hmac.compare_digest()` method to securely check the secret value. If this method is used, then the calculation time depends only on the length of input byte arrays, and does not depend on the contents of the arrays. Unlike `==` is a fail fast check, If the first byte is not equal, it will return immediately.


## Example
The following example uses `==` which is a fail fast check for validating the value of sensitive headers.


```python
#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""
@Desc   ：preventing timing attack against header value
"""

from flask import Flask
from flask import request

@app.route('/bad')
def bad():
    secret = request.headers.get('X-Auth-Token')    
    if secret == "token":
        raise Exception('bad token')
    return 'bad'

if __name__ == '__main__':
    app.debug = True
    app.run() 

```
The next example use a safe constant-time algorithm for validating the value of sensitive headers:


```python
#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""
@Desc   ：preventing timing attack against header value
"""

from flask import Flask
from flask import request
import hmac

@app.route('/good')
def good():
    secret = request.headers.get('X-Auth-Token')    
    if not hmac.compare_digest(secret, "token"):
        raise Exception('bad token')
    return 'good'

if __name__ == '__main__':
    app.debug = True
    app.run() 

```

## References
* Wikipedia: [Timing attack](https://en.wikipedia.org/wiki/Timing_attack).
* [hmac.compare_digest() method](https://docs.python.org/3/library/hmac.html#hmac.compare_digest)
* Common Weakness Enumeration: [CWE-208](https://cwe.mitre.org/data/definitions/208.html).
