# Potentially uninitialized local variable
This local variable may be used before it is defined. If a variable is assigned to in a function and not explicitly declared `global` or `nonlocal` then it is assumed to be a local variable. If it is used before it is defined then an `UnboundLocalError` will be raised.


## Recommendation
Review the code and consider the intended scope of the variable. Determine whether the variable should be global or local in scope. If a global variable is required then add a `global` statement, or in Python 3 you can use a `nonlocal` statement if the variable occurs in an enclosing function. Otherwise, ensure that the variable is defined before it is used.


## Example
The following code includes different functions that use variables. `test1()` fails with an `UnboundLocalError` because the local variable `var` is used before it is initialized.


```python
def test():
    var = 1 
    def print_var():
        print var      # Use variable from outer scope
    print_var()
    print var 


def test1():
    var = 2 
    def print_var():
        print var       # Attempt to use variable from local scope. 
        var = 3         # Since this is not initialized yet, this results
    print_var()         # in an UnboundLocalError
    print var 


def test2():
    var = 2 
    def print_var():
        var = 3         # Initialize local version of the variable
        print var       # Use variable from local scope.
    print_var()         # Note that this local variable "shadows" the variable from
    print var           # outer scope which makes code more difficult to interpret.


def test3():
    var = 4
    def print_var():
        nonlocal var    # Use non-local variable from outer scope.
        print var
    print_var()
    print var
```

## References
* Python Standard Library: [Built-in Exceptions: UnboundLocalError](http://docs.python.org/library/exceptions.html#exceptions.UnboundLocalError).
* Python Frequently Asked Questions: [Why am I getting an UnboundLocalError when the variable has a value?](http://docs.python.org/2/faq/programming.html#why-am-i-getting-an-unboundlocalerror-when-the-variable-has-a-value).
* Python Course: [Global and Local Variables](http://www.python-course.eu/global_vs_local_variables.php).
* Python Language Reference: [The global statement](http://docs.python.org/2.7/reference/simple_stmts.html#index-54), [The nonlocal statement](http://docs.python.org/3.3/reference/simple_stmts.html#index-43).
