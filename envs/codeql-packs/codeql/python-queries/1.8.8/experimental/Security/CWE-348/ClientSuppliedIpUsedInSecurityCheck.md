# IP address spoofing
An original client IP address is retrieved from an http header (`X-Forwarded-For` or `X-Real-IP` or `Proxy-Client-IP` etc.), which is used to ensure security. Attackers can forge the value of these identifiers to bypass a ban-list, for example.


## Recommendation
Do not trust the values of HTTP headers allegedly identifying the originating IP. If you are aware your application will run behind some reverse proxies then the last entry of a `X-Forwarded-For` header value may be more trustworthy than the rest of it because some reverse proxies append the IP address they observed to the end of any remote-supplied header.


## Example
The following examples show the bad case and the good case respectively. In `bad1` method and `bad2` method, the client ip the `X-Forwarded-For` is split into comma-separated values, but the less-trustworthy first one is used. Both of these examples could be deceived by providing a forged HTTP header. The method `good1` similarly splits an `X-Forwarded-For` value, but uses the last, more-trustworthy entry.


```python
#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Desc   ：ip address spoofing
"""
from flask import Flask
from flask import request

app = Flask(__name__)

@app.route('/bad1')
def bad1():
    client_ip = request.headers.get('x-forwarded-for')
    if not client_ip.startswith('192.168.'):
        raise Exception('ip illegal')
    return 'bad1'

@app.route('/bad2')
def bad2():
    client_ip = request.headers.get('x-forwarded-for')
    if not client_ip == '127.0.0.1':
        raise Exception('ip illegal')
    return 'bad2'

@app.route('/good1')
def good1():
    client_ip = request.headers.get('x-forwarded-for')
    client_ip = client_ip.split(',')[client_ip.split(',').length - 1]
    if not client_ip == '127.0.0.1':
        raise Exception('ip illegal')
    return 'good1'

if __name__ == '__main__':
    app.debug = True
    app.run()
```

## References
* Dennis Schneider: [ Prevent IP address spoofing with X-Forwarded-For header when using AWS ELB and Clojure Ring](https://www.dennis-schneider.com/blog/prevent-ip-address-spoofing-with-x-forwarded-for-header-and-aws-elb-in-clojure-ring/)
* Security Rule Zero: [A Warning about X-Forwarded-For](https://www.f5.com/company/blog/security-rule-zero-a-warning-about-x-forwarded-for)
* Common Weakness Enumeration: [CWE-348](https://cwe.mitre.org/data/definitions/348.html).
