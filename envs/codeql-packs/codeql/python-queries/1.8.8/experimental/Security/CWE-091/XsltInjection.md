# XSLT query built from user-controlled sources
Processing an unvalidated XSL stylesheet can allow an attacker to change the structure and contents of the resultant XML, include arbitrary files from the file system, or execute arbitrary code.


## Recommendation
This vulnerability can be prevented by not allowing untrusted user input to be passed as an XSL stylesheet. If the application logic necessitates processing untrusted XSL stylesheets, the input should be properly filtered and sanitized before use.


## Example
In the example below, the XSL stylesheet is controlled by the user and hence leads to a vulnerability.


```python
from lxml import etree
from io import StringIO
from flask import Flask, request

app = Flask(__name__)


@app.route("/xslt")
def bad():
    xsltQuery = request.args.get('xml', '')
    xslt_root = etree.XML(xsltQuery)
    f = StringIO('<foo><bar></bar></foo>')
    tree = etree.parse(f)
    result_tree = tree.xslt(xslt_root)  # Not OK

```
