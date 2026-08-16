# NoSQL Injection
Passing user-controlled sources into NoSQL queries can result in a NoSQL injection flaw. This tainted NoSQL query containing a user-controlled source can then execute a malicious query in a NoSQL database such as MongoDB. In order for the user-controlled source to taint the NoSQL query, the user-controller source must be converted into a Python object using something like `json.loads` or `xmltodict.parse`.

Because a user-controlled source is passed into the query, the malicious user can have complete control over the query itself. When the tainted query is executed, the malicious user can commit malicious actions such as bypassing role restrictions or accessing and modifying restricted data in the NoSQL database.


## Recommendation
NoSQL injections can be prevented by escaping user-input's special characters that are passed into the NoSQL query from the user-supplied source. Alternatively, using a sanitize library such as MongoSanitizer will ensure that user-supplied sources can not act as a malicious query.


## Example
In the example below, the user-supplied source is passed to a MongoDB function that queries the MongoDB database.


```python
from flask import Flask, request
from flask_pymongo import PyMongo
import json

mongo = PyMongo(app)


@app.route("/")
def home_page():
    unsanitized_search = request.args['search']
    json_search = json.loads(unsanitized_search)

    result = mongo.db.user.find({'name': json_search})

```
This can be fixed by using a sanitizer library like MongoSanitizer as shown in this annotated code version below.


```python
from flask import Flask, request
from flask_pymongo import PyMongo
from mongosanitizer.sanitizer import sanitize
import json

mongo = PyMongo(app)


@app.route("/")
def home_page():
    unsafe_search = request.args['search']
    json_search = json.loads(unsafe_search)
    safe_search = sanitize(unsanitized_search)

    result = client.db.collection.find_one({'data': safe_search})

```

## References
* Mongoengine: [Documentation](http://mongoengine.org/).
* Flask-Mongoengine: [Documentation](http://docs.mongoengine.org/projects/flask-mongoengine/en/latest/).
* PyMongo: [Documentation](https://pypi.org/project/pymongo/).
* Flask-PyMongo: [Documentation](https://flask-pymongo.readthedocs.io/en/latest/).
* OWASP: [NoSQL Injection](https://owasp.org/www-pdf-archive/GOD16-NOSQL.pdf).
* Security Stack Exchange Discussion: [Question 83231](https://security.stackexchange.com/questions/83231/mongodb-nosql-injection-in-python-code).
* Common Weakness Enumeration: [CWE-943](https://cwe.mitre.org/data/definitions/943.html).
