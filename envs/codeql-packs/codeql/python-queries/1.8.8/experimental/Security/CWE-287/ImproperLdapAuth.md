# Improper LDAP Authentication
If an LDAP query doesn't carry any kind of authentication, anonymous binds causes an empty or None-set password to result in a successful authentication.


## Recommendation
Use a non-empty password while establishing an LDAP connection.


## Example
In the following examples, the code builds a LDAP query whose execution carries no authentication or binds anonymously.


```python
from flask import request, Flask
import ldap
import ldap.filter
import ldap.dn


@app.route("/bind_example")
def bind_example():
    dn = "dc={}".format(ldap.dn.escape_dn_chars(request.args['dc']))
    search_filter = "(user={})".format(ldap.filter.escape_filter_chars(request.args['search']))

    ldap_connection = ldap.initialize("ldap://127.0.0.1:1337")
    ldap_connection.bind('cn=root', "")
    user = ldap_connection.search_s(dn, ldap.SCOPE_SUBTREE, search_filter)

```

```python
from ldap3 import Server, Connection, ALL
from flask import request, Flask
from ldap3.utils.dn import escape_rdn
from ldap3.utils.conv import escape_filter_chars

@app.route("/passwordNone")
def passwordNone():
    dn = "dc={}".format(escape_rdn(request.args['dc']))
    search_filter = "(user={})".format(escape_filter_chars(request.args['search']))

    srv = Server('servername', get_info=ALL)
    conn = Connection(srv, user='user_dn', password=None)
    status, result, response, _ = conn.search(dn, search_filter)

```
In the third and fourth examples, the authentication is established using a password.


```python
from flask import request, Flask
import ldap
import ldap.filter
import ldap.dn


@app.route("/bind_example")
def bind_example():
    dn = "dc={}".format(ldap.dn.escape_dn_chars(request.args['dc']))
    search_filter = "(user={})".format(ldap.filter.escape_filter_chars(request.args['search']))

    ldap_connection = ldap.initialize("ldap://127.0.0.1:1337")
    ldap_connection.bind('cn=root', "SecurePa$$!")
    user = ldap_connection.search_s(dn, ldap.SCOPE_SUBTREE, search_filter)

```

```python
from ldap3 import Server, Connection, ALL
from flask import request, Flask
from ldap3.utils.dn import escape_rdn
from ldap3.utils.conv import escape_filter_chars

@app.route("/passwordFromEnv")
def passwordFromEnv():
    dn = "dc={}".format(escape_rdn(request.args['dc']))
    search_filter = "(user={})".format(escape_filter_chars(request.args['search']))

    srv = Server('servername', get_info=ALL)
    conn = Connection(srv, user='user_dn',
                      password="SecurePa$$!")
    status, result, response, _ = conn.search(dn, search_filter)

```

## References
* SonarSource: [RSPEC-4433](https://rules.sonarsource.com/python/type/Vulnerability/RSPEC-4433).
* Python2: [LDAP Documentation](https://www.python-ldap.org/en/python-ldap-3.3.0/reference/ldap.html).
* Python3: [LDAP Documentation](https://ldap3.readthedocs.io/en/latest/).
* Common Weakness Enumeration: [CWE-287](https://cwe.mitre.org/data/definitions/287.html).
