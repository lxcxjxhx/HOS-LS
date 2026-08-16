# Lack of Cohesion in a Class (HM)
A cohesive class is one in which most methods access the same fields. A class that lacks cohesion is usually one that has multiple responsibilities.

Various measures of lack of cohesion have been proposed. A measure proposed by Hitz and Montazeri counts the number of strongly connected components, that is disjoint subgraphs, in the graph of method and attribute dependencies. This can be thought of as the number of possible classes that a single class could be split into.

Values of LCOM above 1 indicate a lack of cohesion in that there are several disjoint subgraphs in a graph of intra-class dependencies.


## Recommendation
Classes generally lack cohesion because they have more responsibilities than they should (see \[Martin\]). In general, the solution is to identify each of the different responsibilities that the class has, and split them into multiple classes, using the 'Extract Class' refactoring from \[Fowler\], for example.


## References
* [ Measuring coupling and cohesion in object-oriented systems by Martin Hitz, Behzad Montazeri (1995).](http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.409.4862) Proceedings of International Symposium on Applied Corporate Computing
* M. Fowler, *Refactoring*, pp. 65, 122-5. Addison-Wesley, 1999.
* Wikipedia: [The Single Responsibility Principle](https://en.wikipedia.org/wiki/Single_responsibility_principle).
* Wikipedia: [Strongly connected component](http://en.wikipedia.org/wiki/Glossary_of_graph_theory#Strongly_connected_component).
