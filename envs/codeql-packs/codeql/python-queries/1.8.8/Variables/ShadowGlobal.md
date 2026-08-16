# Global shadowed by local variable
Python statements can access variables in both the local namespace and in the global namespace. When a local and a global variable have the same name, the local variable "shadows" or "hides" the global variable. When the variable is referenced, the variable with local scope is used unless you explicitly use the `global` statement to reference the global variable. This can lead to confusion as a reader of the code may expect the variable to refer to a global.


## Recommendation
Avoid using the same name for variables in local and global namespaces.


## Example
The following simple example shows how a local variable can "shadow" a global variable. The local variable should be renamed to make the code easier to interpret.


```python
var = 2              # Global variable

def test2():
    def print_var():
        var = 3 
        print var    # Local variable which "shadows" the global variable
    print_var()      # making it more difficult to determine which "var"
    print var        # is referenced

test2()

```

## References
* J. Lusth, *The Art and Craft of Programming - Python Edition*, Section: Scope. University of Alabama, 2012. ([Published online](https://web.archive.org/web/20190919091129/http://troll.cs.ua.edu/ACP-PY/index_13.html)).
* Python Language Reference: [The global statement](http://docs.python.org/reference/simple_stmts.html#the-global-statement).
