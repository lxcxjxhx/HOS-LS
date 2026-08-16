# Wrong name for an argument in a call
Using a named argument whose name does not correspond to a parameter of the called function (or method), will result in a `TypeError` at runtime.


## Recommendation
Check for typos in the name of the arguments and fix those. If the name is clearly different, then this suggests a logical error. The change required to correct the error will depend on whether the wrong argument has been specified or whether the wrong function (or method) has been specified.


## References
* Python Glossary: [Arguments](https://docs.python.org/2/glossary.html#term-argument).
* Python Glossary: [Parameters](https://docs.python.org/glossary.html#term-parameter).
* Python Programming FAQ: [ What is the difference between arguments and parameters?](https://docs.python.org/2/faq/programming.html#faq-argument-vs-parameter).
* Common Weakness Enumeration: [CWE-628](https://cwe.mitre.org/data/definitions/628.html).
