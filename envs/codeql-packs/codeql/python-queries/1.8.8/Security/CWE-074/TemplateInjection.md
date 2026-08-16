# Server Side Template Injection
A template from a server templating engine such as Jinja constructed from user input can allow the user to execute arbitrary code using certain template features. It can also allow for cross-site scripting.


## Recommendation
Ensure that an untrusted value is not used to directly construct a template. Jinja also provides `SandboxedEnvironment` that prohibits access to unsafe methods and attributes. This can be used if constructing a template from user input is absolutely necessary.


## Example
In the following case, `template` is used to generate a Jinja2 template string. This can lead to remote code execution.


```python
from django.urls import path
from django.http import HttpResponse
from jinja2 import Template, escape


def a(request):
    template = request.GET['template']

    # BAD: Template is constructed from user input. 
    t = Template(template)

    name = request.GET['name']
    html = t.render(name=escape(name))
    return HttpResponse(html)


urlpatterns = [
    path('a', a),
]
```
The following is an example of a string that could be used to cause remote code execution when interpreted as a template:


```txt
{% for s in ().__class__.__base__.__subclasses__() %}{% if "warning" in s.__name__ %}{{s()._module.__builtins__['__import__']('os').system('cat /etc/passwd') }}{% endif %}{% endfor %}

```
In the following case, user input is not used to construct the template. Instead, it is only used as the parameters to render the template, which is safe.


```python
from django.urls import path
from django.http import HttpResponse
from jinja2 import Template, escape


def a(request):
    # GOOD: Template is a constant, not constructed from user input
    t = Template("Hello, {{name}}!")

    name = request.GET['name']
    html = t.render(name=escape(name))
    return HttpResponse(html)


urlpatterns = [
    path('a', a),
]
```
In the following case, a `SandboxedEnvironment` is used, preventing remote code execution.


```python
from django.urls import path
from django.http import HttpResponse
from jinja2 import escape
from jinja2.sandbox import SandboxedEnvironment


def a(request):
    env = SandboxedEnvironment()
    template = request.GET['template']

    # GOOD: A sandboxed environment is used to construct the template. 
    t = env.from_string(template)

    name = request.GET['name']
    html = t.render(name=escape(name))
    return HttpResponse(html)


urlpatterns = [
    path('a', a),
]
```

## References
* Portswigger: [Server-Side Template Injection](https://portswigger.net/web-security/server-side-template-injection).
* Common Weakness Enumeration: [CWE-74](https://cwe.mitre.org/data/definitions/74.html).
