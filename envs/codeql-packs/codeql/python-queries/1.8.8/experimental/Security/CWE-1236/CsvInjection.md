# Csv Injection
CSV Injection, also known as Formula Injection, occurs when websites embed untrusted input inside CSV files.

When a CSV format file is opened with a spreadsheet program such as Microsoft Excel or LibreOffice Calc. this software interprets entries beginning with `=` as formulas, which may attempt information exfiltration or other malicious activity when automatically executed by the spreadsheet software.


## Recommendation
When generating CSV output, ensure that formula-sensitive metacharacters are effectively escaped or removed from all data before storage in the resultant CSV. Risky characters include `=`(equal), `+`(plus), `-`(minus), and `@`(at).


## Example
The following examples show the bad case and the good case respectively. In `bad1` method, the data provided by the user is directly stored in the CSV file, which may be attacked. But in the `good1` method, the program will check the data provided by the user, and process the data starting with `=`(equal), `+`(plus), `-`(minus), and `@`(at) characters safely.


```python
#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Desc   ：csv injection
"""
import copy
import csv
from flask import Flask
from flask import request
from typing import List

app = Flask(__name__)

@app.route('/bad1')
def bad1():
    csv_data = request.args.get('csv')
    csvWriter = csv.writer(open("test.csv", "wt"))
    csvWriter.writerow(csv_data)
    return "bad1"

@app.route('/good1')
def good1():
    csv_data = request.args.get('csv')
    csvWriter = csv.writer(open("test.csv", "wt"))
    csvWriter.writerow(sanitize_for_csv(csv_data))
    return "good1"

def sanitize_for_csv(data: str| List[str] | List[List[str]]):
    def sanitize(item):
        return "'" + item

    unsafe_prefixes = ("+", "=", "-", "@")
    if isinstance(data, str):
        if data.startswith(unsafe_prefixes):
            return sanitize(data)
        return data
    elif isinstance(data, list) and isinstance(data[0], str):
        sanitized_data = copy.deepcopy(data)
        for index, item in enumerate(data):
            if item.startswith(unsafe_prefixes):
                sanitized_data[index] = sanitize(item)
        return sanitized_data
    elif isinstance(data[0], list) and isinstance(data[0][0], str):
        sanitized_data = copy.deepcopy(data)
        for outer_index, sublist in enumerate(data):
            for inner_index, item in enumerate(sublist):
                if item.startswith(unsafe_prefixes):
                    sanitized_data[outer_index][inner_index] = sanitize(item)
        return sanitized_data
    else:
        raise ValueError("Unsupported data type: " + str(type(data)))


if __name__ == '__main__':
    app.debug = True
    app.run()
```

## References
* OWASP: [CSV Injection](https://owasp.org/www-community/attacks/CSV_Injection).
* Common Weakness Enumeration: [CWE-1236](https://cwe.mitre.org/data/definitions/1236.html).
