# Uncontrolled data used in path expression
Accessing files using paths constructed from user-controlled data can allow an attacker to access unexpected resources. This can result in sensitive information being revealed or deleted, or an attacker being able to influence behavior by modifying unexpected files.


## Recommendation
Validate paths constructed from untrusted user input before using them to access files.

The choice of validation depends on the use case.

If you want to allow paths spanning multiple folders, a common strategy is to make sure that the constructed file path is contained within a safe root folder. First, normalize the path using `os.path.normpath` or `os.path.realpath` (make sure to use the latter if symlinks are a consideration) to remove any internal ".." segments and/or follow links. Then check that the normalized path starts with the root folder. Note that the normalization step is important, since otherwise even a path that starts with the root folder could be used to access files outside the root folder.

More restrictive options include using a library function like `werkzeug.utils.secure_filename` to eliminate any special characters from the file path, or restricting the path to a known list of safe paths. These options are safe, but can only be used in particular circumstances.


## Example
In the first example, a file name is read from an HTTP request and then used to access a file. However, a malicious user could enter a file name that is an absolute path, such as `"/etc/passwd"`.

In the second example, it appears that the user is restricted to opening a file within the `"user"` home directory. However, a malicious user could enter a file name containing special characters. For example, the string `"../../../etc/passwd"` will result in the code reading the file located at `"/server/static/images/../../../etc/passwd"`, which is the system's password file. This file would then be sent back to the user, giving them access to all the system's passwords. Note that a user could also use an absolute path here, since the result of `os.path.join("/server/static/images/", "/etc/passwd")` is `"/etc/passwd"`.

In the third example, the path used to access the file system is normalized *before* being checked against a known prefix. This ensures that regardless of the user input, the resulting path is safe.


```python
import os.path
from flask import Flask, request, abort

app = Flask(__name__)

@app.route("/user_picture1")
def user_picture1():
    filename = request.args.get('p')
    # BAD: This could read any file on the file system
    data = open(filename, 'rb').read()
    return data

@app.route("/user_picture2")
def user_picture2():
    base_path = '/server/static/images'
    filename = request.args.get('p')
    # BAD: This could still read any file on the file system
    data = open(os.path.join(base_path, filename), 'rb').read()
    return data

@app.route("/user_picture3")
def user_picture3():
    base_path = '/server/static/images'
    filename = request.args.get('p')
    #GOOD -- Verify with normalised version of path
    fullpath = os.path.normpath(os.path.join(base_path, filename))
    if not fullpath.startswith(base_path):
        raise Exception("not allowed")
    data = open(fullpath, 'rb').read()
    return data

```

## References
* OWASP: [Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal).
* npm: [werkzeug.utils.secure_filename](http://werkzeug.pocoo.org/docs/utils/#werkzeug.utils.secure_filename).
* Common Weakness Enumeration: [CWE-22](https://cwe.mitre.org/data/definitions/22.html).
* Common Weakness Enumeration: [CWE-23](https://cwe.mitre.org/data/definitions/23.html).
* Common Weakness Enumeration: [CWE-36](https://cwe.mitre.org/data/definitions/36.html).
* Common Weakness Enumeration: [CWE-73](https://cwe.mitre.org/data/definitions/73.html).
* Common Weakness Enumeration: [CWE-99](https://cwe.mitre.org/data/definitions/99.html).
