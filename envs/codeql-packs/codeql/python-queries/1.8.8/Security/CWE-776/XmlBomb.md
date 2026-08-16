# XML internal entity expansion
Parsing untrusted XML files with a weakly configured XML parser may be vulnerable to denial-of-service (DoS) attacks exploiting uncontrolled internal entity expansion.

In XML, so-called *internal entities* are a mechanism for introducing an abbreviation for a piece of text or part of a document. When a parser that has been configured to expand entities encounters a reference to an internal entity, it replaces the entity by the data it represents. The replacement text may itself contain other entity references, which are expanded recursively. This means that entity expansion can increase document size dramatically.

If untrusted XML is parsed with entity expansion enabled, a malicious attacker could submit a document that contains very deeply nested entity definitions, causing the parser to take a very long time or use large amounts of memory. This is sometimes called an *XML bomb* attack.


## Recommendation
The safest way to prevent XML bomb attacks is to disable entity expansion when parsing untrusted data. Whether this can be done depends on the library being used. Note that some libraries, such as `lxml`, have measures enabled by default to prevent such DoS XML attacks, so unless you have explicitly set `huge_tree` to `True`, no further action is needed.

We recommend using the [defusedxml](https://pypi.org/project/defusedxml/) PyPI package, which has been created to prevent XML attacks (both XXE and XML bombs).


## Example
The following example uses the `xml.etree` XML parser provided by the Python standard library to parse a string `xml_src`. That string is from an untrusted source, so this code is vulnerable to a DoS attack, since the `xml.etree` XML parser expands internal entities by default:


```python
from flask import Flask, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

@app.post("/upload")
def upload():
    xml_src = request.get_data()
    doc = ET.fromstring(xml_src)
    return ET.tostring(doc)

```
It is not possible to guard against internal entity expansion with `xml.etree`, so to guard against these attacks, the following example uses the [defusedxml](https://pypi.org/project/defusedxml/) PyPI package instead, which is not exposed to such internal entity expansion attacks.


```python
from flask import Flask, request
import defusedxml.ElementTree as ET

app = Flask(__name__)

@app.post("/upload")
def upload():
    xml_src = request.get_data()
    doc = ET.fromstring(xml_src)
    return ET.tostring(doc)

```

## References
* Wikipedia: [Billion Laughs](https://en.wikipedia.org/wiki/Billion_laughs).
* Bryan Sullivan: [Security Briefs - XML Denial of Service Attacks and Defenses](https://msdn.microsoft.com/en-us/magazine/ee335713.aspx).
* Python 3 standard library: [XML Vulnerabilities](https://docs.python.org/3/library/xml.html#xml-vulnerabilities).
* Python 2 standard library: [XML Vulnerabilities](https://docs.python.org/2/library/xml.html#xml-vulnerabilities).
* Common Weakness Enumeration: [CWE-776](https://cwe.mitre.org/data/definitions/776.html).
* Common Weakness Enumeration: [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
