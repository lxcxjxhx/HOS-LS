# Importing value of mutable attribute
Explicitly importing an attribute from a module into the current namespace means that the value of that attribute will not be updated if the value in the original module changes.

This can mean that changes in global state are not observed locally, which may lead to inconsistencies and possible errors.


## Recommendation
Instead of using `from module import attr`, simply import the module using `import module` and replace all uses of `attr` with `module.attr`.


## Example
In the first of the two modules shown below, `from sys import stdout` is used to import the `stdout` attribute, rather than using `import sys` to import the module. Then `stdout` is used in the `main()` function.


```python
from sys import stdout

def main():
    stdout.write("Hello World!")
    

```
In the second module, below, a function, `redirect_to_file` is defined to collect the output from `sys.stdout` and save it to a file. However, `redirect_to_file` will not work correctly when passed the `main()` function. This is because the `main()` function will not see the change to `sys.stdout`, as it uses its own version of `stdout` that was defined when the module was loaded.


```python
import sys

def redirect_to_file(function, args, kwargs, filename):
    with open(filename) as out:
        orig_stdout = sys.stdout
        sys.stdout = out
        try:
            function(*args, **kwargs)
        finally:
            sys.stdout = orig_stdout


```
The problem can be fixed by rewriting the first module to import the `sys` module and write to `sys.stdout`, as shown below.


```python
import sys

def main():
    sys.stdout.write("Hello World!")

```

## References
* Python Language Reference: [The import statement](http://docs.python.org/2/reference/simple_stmts.html#import).
* Python Tutorial: [Modules](http://docs.python.org/2/tutorial/modules.html).
