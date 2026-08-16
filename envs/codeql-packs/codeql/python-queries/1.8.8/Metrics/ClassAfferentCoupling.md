# Incoming class dependencies
This metric measures the number of incoming dependencies for each class, that is the number of other classes that depend on it.

Classes that are depended upon by many other classes typically require a lot of effort to change, because changing them will force their dependents to change as well. This is not necessarily a bad thing -- indeed, most systems will have some such classes (one example might be a string class). However, classes with a high number of incoming dependencies and a high number of outgoing dependencies are hard to maintain. A class with both high afferent coupling *and* high efferent coupling is referred to as a hub class. Such classes can be problematic, because on the one hand they are hard to change (high afferent coupling), yet on the other they have many reasons to change (high efferent coupling). This contradiction yields code that is very hard to maintain or test.

Conversely, some classes may only be depended on by very few other classes. Again, this is not necessarily a problem -- we would expect, for example, that the top-level classes of a system would meet this criterion. When lower-level classes have very few incoming dependencies, however, it can be an indication that a class is not pulling its weight. In extreme cases, classes may even have an afferent coupling of `0`, indicating that they are dead code.


## Recommendation
It is unwise to refactor a class based purely on its high or low number of incoming dependencies -- a class's afferent coupling value only makes sense in the context of its role in the system as a whole. However, when combined with other metrics such as efferent coupling, it is possible to make some general recommendations:

* Classes with high numbers of incoming *and* outgoing dependencies are hub classes that are prime candidates for refactoring (although this will not always be easy). The general strategy is to split the class into smaller classes that each have fewer responsibilities, and refactor the code that previously used the hub class accordingly.
* Classes that have very few incoming dependencies and are not at the top level of a system may not be pulling their weight and should be refactored, e.g. using the 'Collapse Hierarchy' or 'Inline Class' techniques in \[Fowler\] (see the section entitled 'Lazy Class' on p.68).
* Classes that have an afferent coupling of `0` may be dead code -- in this situation, they can often be deleted.

## References
* M. Fowler. *Refactoring*. Addison-Wesley, 1999.
