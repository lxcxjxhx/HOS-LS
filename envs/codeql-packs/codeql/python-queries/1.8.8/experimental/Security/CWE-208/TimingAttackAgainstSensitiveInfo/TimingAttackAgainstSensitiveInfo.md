# Timing attack against secret
Timing Attack is based on the leakage of information of secret parameters by studying how long it takes the system to respond to different inputs. it can be circumvented by using a constant-time algorithm for checking the value of sensitive info, more precisely, the comparison time should not depend on the content of the input. Otherwise the attacker gains information that is indirectly leaked by the application. This information is then used for malicious purposes.


## Recommendation
Two types of countermeasures can be applied against timing attacks. The first one consists in eliminating timing variations whereas the second renders these variations useless for an attacker. The only absolute way to prevent timing attacks is to make the computation strictly constant time, independent of the input. Use `hmac.compare_digest()` method to securely check the value of sensitive info. If this method is used, then the calculation time depends only on the length of input byte arrays, and does not depend on the contents of the arrays. Unlike `==` is a fail fast check, If the first byte is not equal, it will return immediately.


## Example
The following example uses `==` which is a fail fast check for validating a secret.


```python
#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Desc   ：timing attack against sensitive info
"""

from flask import Flask
from flask import request

@app.route('/bad', methods = ['POST', 'GET'])
def bad():
    if request.method == 'POST':
        password = request.form['pwd']
        return password == "test"
    
if __name__ == '__main__':
    app.debug = True
    app.run() 

```
The next example use a safe constant-time algorithm for validating a secret:


```python
#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""
@Desc   ：preventing timing attack sensitive info
"""
from flask import Flask
from flask import request
import hmac

app = Flask(__name__)

@app.route('/bad', methods = ['POST', 'GET'])
def bad():
    if request.method == 'POST':
        password = request.form['pwd']
        return hmac.compare_digest(password, "1234")
    
if __name__ == '__main__':
    app.debug = True
    app.run() 

```

## References
* Wikipedia: [Timing attack](https://en.wikipedia.org/wiki/Timing_attack).
* [hmac.compare_digest() method](https://docs.python.org/3/library/hmac.html#hmac.compare_digest)
* Common Weakness Enumeration: [CWE-208](https://cwe.mitre.org/data/definitions/208.html).
