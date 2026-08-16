# 'input' function used in Python 2
In Python 2, a call to the `input()` function, `input(prompt)` is equivalent to `eval(raw_input(prompt))`. Evaluating user input without any checking can be a serious security flaw.


## Recommendation
Get user input with `raw_input(prompt)` and then validate that input before evaluating. If the expected input is a number or string, then `ast.literal_eval()` can always be used safely.


## References
* Python Standard Library: [input](http://docs.python.org/2/library/functions.html#input), [ast.literal_eval](http://docs.python.org/2/library/ast.html#ast.literal_eval).
* Wikipedia: [Data validation](http://en.wikipedia.org/wiki/Data_validation).
* Common Weakness Enumeration: [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
* Common Weakness Enumeration: [CWE-95](https://cwe.mitre.org/data/definitions/95.html).
