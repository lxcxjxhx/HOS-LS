# Default version of SSL/TLS may be insecure
The `ssl.wrap_socket` function defaults to an insecure version of SSL/TLS when no specific protocol version is specified. This may leave the connection vulnerable to attack.


## Recommendation
Ensure that a modern, strong protocol is used. All versions of SSL, and TLS 1.0 and 1.1 are known to be vulnerable to attacks. Using TLS 1.2 or above is strongly recommended. If no explicit `ssl_version` is specified, the default `PROTOCOL_TLS` is chosen. This protocol is insecure because it allows TLS 1.0 and TLS 1.1 and so should not be used.


## Example
The following code shows two different ways of setting up a connection using SSL or TLS. They are both potentially insecure because the default version is used.


```python
import ssl
import socket

# Using the deprecated ssl.wrap_socket method
ssl.wrap_socket(socket.socket())

# Using SSLContext
context = ssl.SSLContext()

```
Both of the cases above should be updated to use a secure protocol instead, for instance by specifying `ssl_version=PROTOCOL_TLSv1_2` as a keyword argument.

The latter example can also be made secure by modifying the created context before it is used to create a connection. Therefore it will not be flagged by this query. However, if a connection is created before the context has been secured (for example, by setting the value of `minimum_version`), then the code should be flagged by the query `py/insecure-protocol`.

Note that `ssl.wrap_socket` has been deprecated in Python 3.7. The recommended alternatives are:

* `ssl.SSLContext` - supported in Python 2.7.9, 3.2, and later versions
* `ssl.create_default_context` - a convenience function, supported in Python 3.4 and later versions.
Even when you use these alternatives, you should ensure that a safe protocol is used. The following code illustrates how to use flags (available since Python 3.2) or the \`minimum_version\` field (favored since Python 3.7) to restrict the protocols accepted when creating a connection.


```python
import ssl

# Using flags to restrict the protocol
context = ssl.SSLContext()
context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

# Declaring a minimum version to restrict the protocol
context = ssl.create_default_context()
context.minimum_version = ssl.TLSVersion.TLSv1_2

```

## References
* Wikipedia: [ Transport Layer Security](https://en.wikipedia.org/wiki/Transport_Layer_Security).
* Python 3 documentation: [ class ssl.SSLContext](https://docs.python.org/3/library/ssl.html#ssl.SSLContext).
* Python 3 documentation: [ ssl.wrap_socket](https://docs.python.org/3/library/ssl.html#ssl.wrap_socket).
* Python 3 documentation: [ notes on context creation](https://docs.python.org/3/library/ssl.html#functions-constants-and-exceptions).
* Python 3 documentation: [ notes on security considerations](https://docs.python.org/3/library/ssl.html#ssl-security).
* Common Weakness Enumeration: [CWE-327](https://cwe.mitre.org/data/definitions/327.html).
