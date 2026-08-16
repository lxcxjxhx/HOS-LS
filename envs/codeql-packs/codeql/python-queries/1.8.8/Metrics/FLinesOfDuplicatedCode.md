# Duplicated lines in files
This metric measures the number of lines in a file that are contained within a block that is duplicated elsewhere. These lines may include code, comments and whitespace, and the duplicate block may be in this file or in another file.

A file that contains many lines that are duplicated within the code base is problematic for a number of reasons.

Duplicated code increases overall code size, making the code base harder to maintain and harder to understand. It also becomes harder to fix bugs, since a programmer applying a fix to one copy has to always remember to update other copies accordingly. Finally, code duplication is generally an indication of a poorly designed or hastily written code base, which typically suffers from other problems as well.


## Recommendation
Refactor files with lots of duplicated code to extract the common code into a shared library or module.


## References
* Wikipedia: [Duplicate code](http://en.wikipedia.org/wiki/Duplicate_code).
* M. Fowler, *Refactoring*. Addison-Wesley, 1999.
