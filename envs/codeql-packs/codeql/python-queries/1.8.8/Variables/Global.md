# Use of the 'global' statement
The use of the `global` keyword enables functions to modify variables outside of their scope. These functions may then include side effects that may not be apparent to users of that function, making the code harder to understand.


## Recommendation
Remove the `global` statement, if possible.


## References
* Python Language Reference: [The global statement](http://docs.python.org/reference/simple_stmts.html#the-global-statement).
