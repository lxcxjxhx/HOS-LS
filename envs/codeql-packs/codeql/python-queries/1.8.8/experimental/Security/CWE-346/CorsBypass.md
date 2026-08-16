# Cross Origin Resource Sharing(CORS) Policy Bypass
Cross-origin resource sharing policy may be bypassed due to incorrect checks like the `string.startswith` call.


## Recommendation
Use a more stronger check to test for CORS policy bypass.


## Example
Most Python frameworks provide a mechanism for testing origins and performing CORS checks. For example, consider the code snippet below, `origin` is compared using a ` startswith` call against a list of whitelisted origins. This check can be bypassed easily by origin like `domain.com.baddomain.com`


```python
import cherrypy

def bad():
    request = cherrypy.request
    validCors = "domain.com"
    if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
        origin = request.headers.get('Origin', None)
        if origin.startswith(validCors):
            print("Origin Valid")
```
This can be prevented by comparing the origin in a manner shown below.


```python
import cherrypy

def good():
    request = cherrypy.request
    validOrigin = "domain.com"
    if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
        origin = request.headers.get('Origin', None)
        if origin == validOrigin:
            print("Origin Valid")
```

## References
* PortsSwigger : [](https://portswigger.net/web-security/cors)Cross-origin resource sharing (CORS)
* Related CVE: [CVE-2022-3457](https://github.com/advisories/GHSA-824x-jcxf-hpfg).
