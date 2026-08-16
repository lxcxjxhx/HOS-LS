# JavaScript code execution
Passing untrusted inputs to a JavaScript interpreter like \`Js2Py\` can lead to arbitrary code execution.


## Recommendation
This vulnerability can be prevented either by preventing an untrusted user input to flow to an `eval_js` call. Or, the impact of this vulnerability can be significantly reduced by disabling imports from the interepreted code (note that in a [ comment](https://github.com/PiotrDabkowski/Js2Py/issues/45#issuecomment-258724406) the author of the library highlights that Js2Py is still insecure with this option).


## Example
In the example below, the Javascript code being evaluated is controlled by the user and hence leads to arbitrary code execution.


```python
@bp.route("/bad")
def bad():
    jk = flask.request.form["jk"]
    jk = eval_js(f"{jk} f()")

```
This can be fixed by disabling imports before evaluating the user passed buffer.


```python
@bp.route("/good")
def good():
    # disable python imports to prevent execution of malicious code 
    js2py.disable_pyimport()
    jk = flask.request.form["jk"]
    jk = eval_js(f"{jk} f()")

```
