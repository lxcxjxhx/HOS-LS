# XPath query built from user-controlled sources
If an XPath expression is built using string concatenation, and the components of the concatenation include user input, it makes it very easy for a user to create a malicious XPath expression.


## Recommendation
If user input must be included in an XPath expression, either sanitize the data or use variable references to safely embed it without altering the structure of the expression.


## Example
In the example below, the xpath query is controlled by the user and hence leads to a vulnerability.


```python
from lxml import etree
from io import StringIO

from django.urls import path
from django.http import HttpResponse
from django.template import Template, Context, Engine, engines


def a(request):
    value = request.GET['xpath']
    f = StringIO('<foo><bar></bar></foo>')
    tree = etree.parse(f)
    r = tree.xpath("/tag[@id='%s']" % value)


urlpatterns = [
    path('a', a)
]

```
This can be fixed by using a parameterized query as shown below.


```python
from lxml import etree
from io import StringIO

from django.urls import path
from django.http import HttpResponse
from django.template import Template, Context, Engine, engines


def a(request):
    value = request.GET['xpath']
    f = StringIO('<foo><bar></bar></foo>')
    tree = etree.parse(f)
    r = tree.xpath("/tag[@id=$tagid]", tagid=value)


urlpatterns = [
    path('a', a)
]

```

## References
* OWASP XPath injection : [](https://owasp.org/www-community/attacks/XPATH_Injection)/&gt;&gt;
* Common Weakness Enumeration: [CWE-643](https://cwe.mitre.org/data/definitions/643.html).
