# HTTP Response Splitting
Directly writing user input (for example, an HTTP request parameter) to an HTTP header can lead to an HTTP response-splitting vulnerability.

If user-controlled input is used in an HTTP header that allows line break characters, an attacker can inject additional headers or control the response body, leading to vulnerabilities such as XSS or cache poisoning.


## Recommendation
Ensure that user input containing line break characters is not written to an HTTP header.


## Example
In the following example, the case marked BAD writes user input to the header name. In the GOOD case, input is first escaped to not contain any line break characters.


```python
@app.route("/example_bad")
def example_bad():
    rfs_header = request.args["rfs_header"]
    response = Response()
    custom_header = "X-MyHeader-" + rfs_header
    # BAD: User input is used as part of the header name.
    response.headers[custom_header] = "HeaderValue" 
    return response

@app.route("/example_good")
def example_bad():
    rfs_header = request.args["rfs_header"]
    response = Response()
    custom_header = "X-MyHeader-" + rfs_header.replace("\n", "").replace("\r","").replace(":","")
    # GOOD: Line break characters are removed from the input.
    response.headers[custom_header] = "HeaderValue" 
    return response
```

## References
* SecLists.org: [HTTP response splitting](https://seclists.org/bugtraq/2005/Apr/187).
* OWASP: [HTTP Response Splitting](https://www.owasp.org/index.php/HTTP_Response_Splitting).
* Wikipedia: [HTTP response splitting](http://en.wikipedia.org/wiki/HTTP_response_splitting).
* CAPEC: [CAPEC-105: HTTP Request Splitting](https://capec.mitre.org/data/definitions/105.html)
* Common Weakness Enumeration: [CWE-113](https://cwe.mitre.org/data/definitions/113.html).
* Common Weakness Enumeration: [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
