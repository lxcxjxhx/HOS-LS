# Modification of parameter with default
The default value of a parameter is computed once when the function is created, not for every invocation. The "pre-computed" value is then used for every subsequent call to the function. Consequently, if you modify the default value for a parameter this "modified" default value is used for the parameter in future calls to the function. This means that the function may not behave as expected in future calls and also makes the function more difficult to understand.


## Recommendation
If a parameter has a default value, do not modify the default value. When you use a mutable object as a default value, you should use a placeholder value instead of modifying the default value. This is a particular problem when you work with lists and dictionaries but there are standard methods of avoiding modifying the default parameter (see References).


## Example
In the following example, the `default` parameter is set with a default value of an empty list. Other commands in the function then append values to the list. The next time the function is called, the list will contain values, which may not have been intended.


```python

    def __init__(self, name, choices=[], default=[], shortDesc=None,
                 longDesc=None, hints=None, allowNone=1):   # 'default' parameter assigned a value
        self.choices = choices
        if choices and not default:
            default.append(choices[0][1])                   # value of 'default' parameter modified
        Argument.__init__(self, name, default, shortDesc, longDesc, hints, allowNone=allowNone)
```
The recommended workaround is use a placeholder value. That is, define the function with a default of `default=None`, check if the parameter is `None` and then set the parameter to a list.


## References
* Effbot: [Default Parameter Values in Python](https://web.archive.org/web/20201112004749/http://effbot.org/zone/default-values.htm).
* Python Language Reference: [Function definitions](http://docs.python.org/3/reference/compound_stmts.html#function-definitions).
