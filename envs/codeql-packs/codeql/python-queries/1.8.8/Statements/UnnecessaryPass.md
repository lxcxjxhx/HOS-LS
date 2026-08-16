# Unnecessary pass
A `pass` statement is only necessary when it is the only statement in a block (the list of statements forming part of a compound statement). This is because the purpose of the ` pass` statement is to allow empty blocks where they would otherwise be syntactically invalid. If the block already contains other statements then the `pass` statement is unnecessary.


## Recommendation
Remove the `pass` statement.


## References
* Python: [pass](http://docs.python.org/2/tutorial/controlflow.html#pass-statements).
