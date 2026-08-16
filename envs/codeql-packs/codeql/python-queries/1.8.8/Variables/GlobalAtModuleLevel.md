# Use of 'global' at module level
The `global` statement is used to specify that assignments to that name are assignments to the variable in the global (module) scope, rather than in the local scope. At the module level, this statement is redundant because the local scope and global scope are the same.


## Recommendation
Remove the `global` statement.


## References
* Python Language Reference: [The global statement](http://docs.python.org/reference/simple_stmts.html#the-global-statement).
