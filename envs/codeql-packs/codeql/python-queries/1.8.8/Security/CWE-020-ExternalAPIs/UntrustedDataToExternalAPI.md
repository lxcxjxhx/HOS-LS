# Untrusted data passed to external API
Using unsanitized untrusted data in an external API can cause a variety of security issues. This query reports external APIs that use untrusted data. The results are not filtered so that you can audit all examples. The query provides data for security reviews of the application and you can also use it to identify external APIs that should be modeled as either taint steps, or sinks for specific problems.

An external API is defined as a call to a method that is not defined in the source code, and is not modeled as a taint step in the default taint library. External APIs may be from the Python standard library or dependencies. The query will report the fully qualified name, along with `[position index]` or `[keyword name]`, to indicate the argument passing the untrusted data.

Note that an excepted sink might not be included in the results, if it also defines a taint step. This is the case for `pickle.loads` which is a sink for the Unsafe Deserialization query, but is also a taint step for other queries.

Note: Compared to the Java version of this query, we currently do not give special care to methods that are overridden in the source code.


## Recommendation
For each result:

* If the result highlights a known sink, confirm that the result is reported by the relevant query, or that the result is a false positive because this data is sanitized.
* If the result highlights an unknown sink for a problem, then add modeling for the sink to the relevant query, and confirm that the result is either found, or is safe due to appropriate sanitization.
* If the result represents a call to an external API that transfers taint, add the appropriate modeling, and re-run the query to determine what new results have appeared due to this additional modeling.
Otherwise, the result is likely uninteresting. Custom versions of this query can extend the `SafeExternalAPI` class and specify `getSafeCallable` to exclude known safe external APIs from future analysis.


## Example
In this first example, a request parameter is read from the Flask `request` and then ultimately used in a call to the `flask.make_response` external API:


```python
from flask import Flask, request, make_response
app = Flask(__name__)

@app.route("/xss")
def xss():
    username = request.args.get("username")
    return make_response("Hello {}".format(username))

```
This is an XSS sink. The XSS query should therefore be reviewed to confirm that this sink is appropriately modeled, and if it is, to confirm that the query reports this particular result, or that the result is a false positive due to some existing sanitization.

In this second example, again a request parameter is read from the Flask `request`.


```python
import base64
import pickle

from flask import Flask, request, make_response
app = Flask(__name__)

@app.route("/example")
def profile():
    raw_data = request.args.get("data").encode('utf-8')
    data = base64.decodebytes(raw_data)
    obj = pickle.loads(data)
    ...

```
If the query reported the call to `base64.decodebytes` on line 10, this would suggest that this external API is not currently modeled as a taint step in the taint tracking library. The next step would be to model this as a taint step, then re-run the query to determine what additional results might be found. In this example, the result of the Base64 decoding is pickled, which can result in remote code execution due to unsafe deserialization.

Note that both examples are correctly handled by the standard taint tracking library and Unsafe Deserialization query.


## References
* Common Weakness Enumeration: [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
