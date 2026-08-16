# XML external entity expansion
Parsing untrusted XML files with a weakly configured XML parser may lead to an XML External Entity (XXE) attack. This type of attack uses external entity references to access arbitrary files on a system, carry out denial-of-service (DoS) attacks, or server-side request forgery. Even when the result of parsing is not returned to the user, DoS attacks are still possible and out-of-band data retrieval techniques may allow attackers to steal sensitive data.


## Recommendation
The easiest way to prevent XXE attacks is to disable external entity handling when parsing untrusted data. How this is done depends on the library being used. Note that some libraries, such as recent versions of the XML libraries in the standard library of Python 3, disable entity expansion by default, so unless you have explicitly enabled entity expansion, no further action needs to be taken.

We recommend using the [defusedxml](https://pypi.org/project/defusedxml/) PyPI package, which has been created to prevent XML attacks (both XXE and XML bombs).


## Example
The following example uses the `lxml` XML parser to parse a string `xml_src`. That string is from an untrusted source, so this code is vulnerable to an XXE attack, since the [ default parser](https://lxml.de/apidoc/lxml.etree.html#lxml.etree.XMLParser) from `lxml.etree` allows local external entities to be resolved.


```python
from flask import Flask, request
import lxml.etree

app = Flask(__name__)

@app.post("/upload")
def upload():
    xml_src = request.get_data()
    doc = lxml.etree.fromstring(xml_src)
    return lxml.etree.tostring(doc)

```
To guard against XXE attacks with the `lxml` library, you should create a parser with `resolve_entities` set to `false`. This means that no entity expansion is undertaken, although standard predefined entities such as `&gt;`, for writing `>` inside the text of an XML element, are still allowed.


```python
from flask import Flask, request
import lxml.etree

app = Flask(__name__)

@app.post("/upload")
def upload():
    xml_src = request.get_data()
    parser = lxml.etree.XMLParser(resolve_entities=False)
    doc = lxml.etree.fromstring(xml_src, parser=parser)
    return lxml.etree.tostring(doc)

```

## References
* OWASP: [XML External Entity (XXE) Processing](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing).
* Timothy Morgen: [XML Schema, DTD, and Entity Attacks](https://research.nccgroup.com/2014/05/19/xml-schema-dtd-and-entity-attacks-a-compendium-of-known-techniques/).
* Timur Yunusov, Alexey Osipov: [XML Out-Of-Band Data Retrieval](https://www.slideshare.net/qqlan/bh-ready-v4).
* Python 3 standard library: [XML Vulnerabilities](https://docs.python.org/3/library/xml.html#xml-vulnerabilities).
* Python 2 standard library: [XML Vulnerabilities](https://docs.python.org/2/library/xml.html#xml-vulnerabilities).
* PortSwigger: [XML external entity (XXE) injection](https://portswigger.net/web-security/xxe).
* Common Weakness Enumeration: [CWE-611](https://cwe.mitre.org/data/definitions/611.html).
* Common Weakness Enumeration: [CWE-827](https://cwe.mitre.org/data/definitions/827.html).
