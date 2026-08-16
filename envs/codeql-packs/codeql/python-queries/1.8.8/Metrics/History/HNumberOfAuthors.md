# Number of authors
This metric measures the number of different authors (by examining the version control history) for files below this location in the tree. (This is a better version of the metric that counts the number of different authors using Javadoc tags.)

Files that have been changed by a large number of different authors are by definition the product of many minds. New authors working on a file may be less familiar with the design and implementation of the code than the original authors, which can be a potential source of bugs. Furthermore, code that has been worked on by many people, if not carefully maintained, often ends up lacking conceptual integrity. For both of these reasons, any code that has been worked on by an unusually high number of different people merits careful inspection in code reviews.


## Recommendation
There is clearly no way to reduce the number of authors that have worked on a file - it is impossible to rewrite history. However, files highlighted by this metric should be given special attention in a code review, and may ultimately be good candidates for refactoring/rewriting by an individual, experienced developer.


## References
* F. P. Brooks Jr. *The Mythical Man-Month*, Chapter 4. Addison-Wesley, 1974.
