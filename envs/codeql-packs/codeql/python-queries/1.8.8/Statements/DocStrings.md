# Missing docstring
PEP8 mandates that all public modules, classes, functions and methods should have a documentation string. Ensuring that every public module, class, function and method is documented makes it easier for other developers to maintain the code.


## Recommendation
If a module, class, function or method needs to be public then add a documentation string that describes the purpose or use of the object (see PEP 257 for guidelines). If the object does not need to be public then make it "private" by changing its name from `xxx` to `_xxx`.


## Example
The following simple, public function should be updated to include a documentation string immediately after the `def` line.


```python
def add(x, y):
    return x + y
```
You might insert the documentation string: `"""Return the sum of x and y."""` on line 2.


## References
* Python PEP 8: [Documentation strings](http://www.python.org/dev/peps/pep-0008/#documentation-strings).
* Python PEP 257: [Documentation string conventions ](http://www.python.org/dev/peps/pep-0257).
