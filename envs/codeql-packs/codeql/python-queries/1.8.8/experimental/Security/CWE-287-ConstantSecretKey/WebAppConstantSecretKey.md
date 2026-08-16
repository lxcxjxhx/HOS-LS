# Initializing SECRET_KEY of Flask application with Constant value
Flask and Django require a Securely signed key for singing the session cookies. most of the time developers rely on load hardcoded secret keys from a config file or python code. this proves that the way of hardcoded secret can make problems when you forgot to change the constant secret keys.


## Recommendation
In Flask Consider using a secure random generator with [Python standard secrets library](https://docs.python.org/3/library/secrets.html#secrets.token_hex)

In Django Consider using a secure random generator with "get_random_secret_key()"" method from "django.core.management.utils".


## Example
Safe Django SECRET_KEY


```python
import sys

from django.conf import settings
from django.conf import global_settings
from django.urls import path
from django.http import HttpResponse
from django.core.management.utils import get_random_secret_key

settings.configure(
    DEBUG=True,
    SECRET_KEY=get_random_secret_key(),
    ROOT_URLCONF=__name__,
)
global_settings.SECRET_KEY = get_random_secret_key()
settings.SECRET_KEY = get_random_secret_key()


def home(request):
    return HttpResponse(settings.SECRET_KEY)


urlpatterns = [
    path("", home),
]

if __name__ == "__main__":
    from django.core.management import execute_from_command_line

    if len(sys.argv) == 1:
        sys.argv.append("runserver")
        sys.argv.append("8080")
    execute_from_command_line(sys.argv)

```
Unsafe Django SECRET_KEY Example:


```python
import sys
import environ
from django.conf import settings
from django.conf import global_settings
from django.urls import path
from django.http import HttpResponse

env = environ.Env(
    SECRET_KEY=(str, "AConstantKey")
)
env.read_env(env_file='.env')
# following is not safe if there is default value in Env(..)
settings.SECRET_KEY = env('SECRET_KEY')

settings.configure(
    DEBUG=True,
    SECRET_KEY="constant1",
    ROOT_URLCONF=__name__,
)
global_settings.SECRET_KEY = "constant2"
settings.SECRET_KEY = "constant3"


def home(request):
    return HttpResponse(settings.SECRET_KEY)


urlpatterns = [
    path("", home),
]

if __name__ == "__main__":
    from django.core.management import execute_from_command_line

    if len(sys.argv) == 1:
        sys.argv.append("runserver")
        sys.argv.append("8080")
    execute_from_command_line(sys.argv)

```
Safe Flask SECRET_KEY Example:


```python
from flask import Flask, session
from secrets import token_hex

app = Flask(__name__)
app.secret_key = token_hex(16)
app.config.from_pyfile("config3.py")


@app.route('/')
def CheckForSecretKeyValue():
    # debugging whether secret_key is secure or not
    return app.secret_key, session.get('logged_in')


if __name__ == '__main__':
    app.run()

```

```python
from flask import Flask, session

app = Flask(__name__)
aConstant = 'CHANGEME1'
app.config['SECRET_KEY'] = aConstant
app.secret_key = aConstant
app.config.update(SECRET_KEY=aConstant)
app.config.from_mapping(SECRET_KEY=aConstant)
app.config.from_pyfile("config.py")
app.config.from_pyfile("config2.py")
app.config.from_object('config.Config')
app.config.from_object('config2.Config')
app.config.from_object('settings')


@app.route('/')
def CheckForSecretKeyValue():
    # debugging whether secret_key is secure or not
    return app.secret_key, session.get('logged_in')


if __name__ == '__main__':
    app.run()

```
Unsafe Flask SECRET_KEY Example:


```python
from flask import Flask, session

app = Flask(__name__)
aConstant = 'CHANGEME1'
SECRET_KEY = aConstant
app.config.from_object(__name__)


@app.route('/')
def DEB_EX():
    if 'logged_in' not in session:
        session['logged_in'] = 'value'
    # debugging whether secret_key is secure or not
    return app.secret_key, session.__str__()


if __name__ == '__main__':
    app.run()

```
config1.py


```python
"""Flask App configuration."""
from os import environ
import os
import random
import configparser

FLASK_DEBUG = True
aConstant = 'CHANGEME2'
config = configparser.ConfigParser()


class Config:
    SECRET_KEY = config["a"]["Secret"]
    SECRET_KEY = config.get("key", "value")
    SECRET_KEY = environ.get("envKey")
    SECRET_KEY = aConstant
    SECRET_KEY = os.getenv('envKey')
    SECRET_KEY = os.environ.get('envKey')
    SECRET_KEY = os.environ.get('envKey', random.randint)
    SECRET_KEY = os.getenv('envKey', random.randint)
    SECRET_KEY = os.getenv('envKey', aConstant)
    SECRET_KEY = os.environ.get('envKey', aConstant)
    SECRET_KEY = os.environ['envKey']

```
config2.py


```python
"""Flask App configuration."""

aConstant = 'CHANGEME2'

SECRET_KEY = aConstant


class Config:
    SECRET_KEY = aConstant

```
config3.py


```python
"""Flask App configuration."""
import os

# General Config
FLASK_DEBUG = True
# if we are loading SECRET_KEY from config files then
# it is good to check default value always, maybe
# the user responsible for setup the application make a mistake
# and has not changed the default SECRET_KEY value
SECRET_KEY = os.getenv('envKey', "A_CONSTANT_SECRET")  # A_CONSTANT_SECRET
if SECRET_KEY == "A_CONSTANT_SECRET":
    raise "not possible"

```
__init__.py


```python
import os

SECRET_KEY = "REDASH_COOKIE_SECRET"

```

## References
* [Flask Documentation](https://flask.palletsprojects.com/en/2.3.x/config/#SECRET_KEY)
* [Django Documentation](https://docs.djangoproject.com/en/4.2/ref/settings/#secret-key)
* [Flask-JWT-Extended Documentation](https://flask-jwt-extended.readthedocs.io/en/stable/basic_usage.html#basic-usage)
* [CVE-2023-27524 - Apache Superset had multiple CVEs related to this kind of Vulnerability](https://www.horizon3.ai/cve-2023-27524-insecure-default-configuration-in-apache-superset-leads-to-remote-code-execution/)
* [CVE-2020-17526 - Apache Airflow had multiple CVEs related to this kind of Vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2020-17526)
* [CVE-2021-41192 - Redash was assigning a environment variable with a default value which it was assigning the default secrect if the environment variable does not exists](https://nvd.nist.gov/vuln/detail/CVE-2021-41192)
* Common Weakness Enumeration: [CWE-287](https://cwe.mitre.org/data/definitions/287.html).
