# Log Injection
If unsanitized user input is written to a log entry, a malicious user may be able to forge new log entries.

Forgery can occur if a user provides some input with characters that are interpreted when the log output is displayed. If the log is displayed as a plain text file, then new line characters can be used by a malicious user to create the appearance of multiple log entries. If the log is displayed as HTML, then arbitrary HTML may be included to spoof log entries.


## Recommendation
User input should be suitably sanitized before it is logged.

If the log entries are plain text then line breaks should be removed from user input, using for example `replace(old, new)` or similar. Care should also be taken that user input is clearly marked in log entries, and that a malicious user cannot cause confusion in other ways.

For log entries that will be displayed in HTML, user input should be HTML encoded before being logged, to prevent forgery and other forms of HTML injection.


## Example
In the example, the name provided by the user is recorded using the log output function (`logging.info` or `app.logger.info`, etc.). In these four cases, the name provided by the user is not provided The processing is recorded. If a malicious user provides `Guest%0D%0AUser name: Admin` as a parameter, the log entry will be divided into two lines, the first line is `User name: Guest` code&gt;, the second line is `User name: Admin`.


```python
#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Desc   ：Log Injection
"""
from flask import Flask
from flask import request
from django.utils.log import request_logger
import logging

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

@app.route('/bad1')
def bad1():
    name = request.args.get('name')
    app.logger.info('User name: ' + name) # Bad
    return 'bad1'

@app.route('/bad2')
def bad2():
    name = request.args.get('name')
    logging.info('User name: ' + name) # Bad
    return 'bad2'

@app.route('/bad3')
def bad3():
    name = request.args.get('name')
    request_logger.warn('User name: ' + name) # Bad
    return 'bad3'

@app.route('/bad4')
def bad4():
    name = request.args.get('name')
    logtest = logging.getLogger('test')
    logtest.debug('User name: ' + name) # Bad
    return 'bad4'

if __name__ == '__main__':
    app.debug = True
    handler = logging.FileHandler('log')
    app.logger.addHandler(handler)
    app.run()

```
In a good example, the program uses the `replace` function to provide parameter processing to the user, and replace `\r\n` and `\n` with empty characters. To a certain extent, the occurrence of log injection vulnerabilities is reduced.


```python
#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Desc   ：Log Injection
"""
from flask import Flask
from flask import request
import logging

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

@app.route('/good1')
def good1():
    name = request.args.get('name')
    name = name.replace('\r\n','').replace('\n','')
    logging.info('User name: ' + name) # Good
    return 'good1'

if __name__ == '__main__':
    app.debug = True
    handler = logging.FileHandler('log')
    app.logger.addHandler(handler)
    app.run()

```

## References
* OWASP: [Log Injection](https://owasp.org/www-community/attacks/Log_Injection).
* Common Weakness Enumeration: [CWE-117](https://cwe.mitre.org/data/definitions/117.html).
