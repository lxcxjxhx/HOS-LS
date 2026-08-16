# LDAP query built from user-controlled sources
If an LDAP query or DN is built using string concatenation or string formatting, and the components of the concatenation include user input without any proper sanitization, a user is likely to be able to run malicious LDAP queries.


## Recommendation
If user input must be included in an LDAP query or DN, it should be escaped to avoid a malicious user providing special characters that change the meaning of the query. In Python2, user input should be escaped with `ldap.dn.escape_dn_chars` or `ldap.filter.escape_filter_chars`, while in Python3, user input should be escaped with `ldap3.utils.dn.escape_rdn` or `ldap3.utils.conv.escape_filter_chars` depending on the component tainted by the user. A good practice is to escape filter characters that could change the meaning of the query (https://tools.ietf.org/search/rfc4515\#section-3).


## Example
In the following examples, the code accepts both `username` and `dc` from the user, which it then uses to build a LDAP query and DN.

The first and the second example uses the unsanitized user input directly in the search filter and DN for the LDAP query. A malicious user could provide special characters to change the meaning of these components, and search for a completely different set of values.


```python
from flask import request, Flask
import ldap


@app.route("/normal")
def normal():
    unsafe_dc = request.args['dc']
    unsafe_filter = request.args['username']

    dn = "dc={}".format(unsafe_dc)
    search_filter = "(user={})".format(unsafe_filter)

    ldap_connection = ldap.initialize("ldap://127.0.0.1")
    user = ldap_connection.search_s(
        dn, ldap.SCOPE_SUBTREE, search_filter)

```

```python
from flask import request, Flask
import ldap3


@app.route("/normal")
def normal():
    unsafe_dc = request.args['dc']
    unsafe_filter = request.args['username']

    dn = "dc={}".format(unsafe_dc)
    search_filter = "(user={})".format(unsafe_filter)

    srv = ldap3.Server('ldap://127.0.0.1')
    conn = ldap3.Connection(srv, user=dn, auto_bind=True)
    conn.search(dn, search_filter)

```
In the third and fourth example, the input provided by the user is sanitized before it is included in the search filter or DN. This ensures the meaning of the query cannot be changed by a malicious user.


```python
from flask import request, Flask
import ldap
import ldap.filter
import ldap.dn


@app.route("/normal")
def normal():
    unsafe_dc = request.args['dc']
    unsafe_filter = request.args['username']

    safe_dc = ldap.dn.escape_dn_chars(unsafe_dc)
    safe_filter = ldap.filter.escape_filter_chars(unsafe_filter)

    dn = "dc={}".format(safe_dc)
    search_filter = "(user={})".format(safe_filter)

    ldap_connection = ldap.initialize("ldap://127.0.0.1")
    user = ldap_connection.search_s(
        dn, ldap.SCOPE_SUBTREE, search_filter)

```

```python
from flask import request, Flask
import ldap3
from ldap3.utils.dn import escape_rdn
from ldap3.utils.conv import escape_filter_chars


@app.route("/normal")
def normal():
    unsafe_dc = request.args['dc']
    unsafe_filter = request.args['username']

    safe_dc = escape_rdn(unsafe_dc)
    safe_filter = escape_filter_chars(unsafe_filter)

    dn = "dc={}".format(safe_dc)
    search_filter = "(user={})".format(safe_filter)

    srv = ldap3.Server('ldap://127.0.0.1')
    conn = ldap3.Connection(srv, user=dn, auto_bind=True)
    conn.search(dn, search_filter)

```

## References
* OWASP: [LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html).
* OWASP: [LDAP Injection](https://owasp.org/www-community/attacks/LDAP_Injection).
* SonarSource: [RSPEC-2078](https://rules.sonarsource.com/python/RSPEC-2078).
* Python2: [LDAP Documentation](https://www.python-ldap.org/en/python-ldap-3.3.0/reference/ldap.html).
* Python3: [LDAP Documentation](https://ldap3.readthedocs.io/en/latest/).
* Wikipedia: [LDAP injection](https://en.wikipedia.org/wiki/LDAP_injection).
* BlackHat: [LDAP Injection and Blind LDAP Injection](https://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf).
* LDAP: [Understanding and Defending Against LDAP Injection Attacks](https://ldap.com/2018/05/04/understanding-and-defending-against-ldap-injection-attacks/).
* Common Weakness Enumeration: [CWE-90](https://cwe.mitre.org/data/definitions/90.html).
