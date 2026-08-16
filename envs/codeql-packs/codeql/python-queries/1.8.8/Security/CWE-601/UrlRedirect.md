# URL redirection from remote source
Directly incorporating user input into a URL redirect request without validating the input can facilitate phishing attacks. In these attacks, unsuspecting users can be redirected to a malicious site that looks very similar to the real site they intend to visit, but which is controlled by the attacker.


## Recommendation
To guard against untrusted URL redirection, it is advisable to avoid putting user input directly into a redirect URL. Instead, maintain a list of authorized redirects on the server; then choose from that list based on the user input provided.

If this is not possible, then the user input should be validated in some other way, for example, by verifying that the target URL does not include an explicit host name.


## Example
The following example shows an HTTP request parameter being used directly in a URL redirect without validating the input, which facilitates phishing attacks:


```python
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/')
def hello():
    target = request.args.get('target', '')
    return redirect(target, code=302)

```
If you know the set of valid redirect targets, you can maintain a list of them on the server and check that the user input is in that list:


```python
from flask import Flask, request, redirect

VALID_REDIRECT = "http://cwe.mitre.org/data/definitions/601.html"

app = Flask(__name__)

@app.route('/')
def hello():
    target = request.args.get('target', '')
    if target == VALID_REDIRECT:
        return redirect(target, code=302)
    else:
        # ignore the target and redirect to the home page
        return redirect('/', code=302)

```
Often this is not possible, so an alternative is to check that the target URL does not specify an explicit host name. For example, you can use the `urlparse` function from the Python standard library to parse the URL and check that the `netloc` attribute is empty.

Note, however, that some cases are not handled as we desire out-of-the-box by `urlparse`, so we need to adjust two things, as shown in the example below:

* Many browsers accept backslash characters (`\`) as equivalent to forward slash characters (`/`) in URLs, but the `urlparse` function does not.
* Mistyped URLs such as `https:/example.com` or `https:///example.com` are parsed as having an empty `netloc` attribute, while browsers will still redirect to the correct site.

```python
from flask import Flask, request, redirect
from urllib.parse import urlparse

app = Flask(__name__)

@app.route('/')
def hello():
    target = request.args.get('target', '')
    target = target.replace('\\', '')
    if not urlparse(target).netloc and not urlparse(target).scheme:
        # relative path, safe to redirect
        return redirect(target, code=302)
    # ignore the target and redirect to the home page
    return redirect('/', code=302)

```
For Django application, you can use the function `url_has_allowed_host_and_scheme` to check that a URL is safe to redirect to, as shown in the following example:


```python
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View

class RedirectView(View):
    def get(self, request, *args, **kwargs):
        target = request.GET.get('target', '')
        if url_has_allowed_host_and_scheme(target, allowed_hosts=None):
            return HttpResponseRedirect(target)
        else:
            # ignore the target and redirect to the home page
            return redirect('/')
```
Note that `url_has_allowed_host_and_scheme` handles backslashes correctly, so no additional processing is required.


## References
* OWASP: [ XSS Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html).
* Python standard library: [ urllib.parse](https://docs.python.org/3/library/urllib.parse.html).
* Common Weakness Enumeration: [CWE-601](https://cwe.mitre.org/data/definitions/601.html).
