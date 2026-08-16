# Similar lines in files
A file that contains many lines that are similar to other code within the code base is problematic for the same reasons as a file that contains a lot of (exactly) duplicated code.

Duplicated code increases overall code size, making the code base harder to maintain and harder to understand. It also becomes harder to fix bugs, since a programmer applying a fix to one copy has to always remember to update other copies accordingly. Finally, code duplication is generally an indication of a poorly designed or hastily written code base, which typically suffers from other problems as well.


## Recommendation
Refactor similar code snippets by extracting common functionality into functions that can be reused across modules.


## References
* Wikipedia: [Duplicate code](http://en.wikipedia.org/wiki/Duplicate_code).
* M. Fowler, *Refactoring*. Addison-Wesley, 1999.
