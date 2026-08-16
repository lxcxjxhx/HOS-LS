# Lack of Cohesion in Methods (CK)
A cohesive class is one in which most methods access the same fields. A class that lacks cohesion is usually one that has multiple responsibilities.

Various measures of lack of cohesion have been proposed. The Chidamber and Kemerer version of lack of cohesion inspects pairs of methods. If there are many pairs that access the same data, the class is cohesive. If there are many pairs that do not access any common data, the class is not cohesive. More precisely, if:

* `n1` is the number of pairs of distinct methods in a class that *do not have* at least one commonly-accessed field, and
* `n2` is the number of pairs of distinct methods in a class that *do have* at least one commonly-accessed field,
the lack of cohesion measure (LCOM) can be defined as:

LCOM = max((n1 - n2) / 2, 0)

High values of LCOM indicate a significant lack of cohesion. As a rough indication, an LCOM of 500 or more may give you cause for concern.


## Recommendation
Classes generally lack cohesion because they have more responsibilities than they should (see \[Martin\]). In general, the solution is to identify each of the different responsibilities that the class has, and split them into multiple classes, using the 'Extract Class' refactoring from \[Fowler\], for example.


## References
* S. R. Chidamber and C. F. Kemerer, *A metrics suite for object-oriented design*. IEEE Transactions on Software Engineering, 20(6):476-493, 1994.
* M. Fowler, *Refactoring*, pp. 65, 122-5. Addison-Wesley, 1999.
* Wikipedia: [The Single Responsibility Principle](https://en.wikipedia.org/wiki/Single_responsibility_principle).
* O. de Moor et al, *Keynote Address: .QL for Source Code Analysis*. Proceedings of the 7th IEEE International Working Conference on Source Code Analysis and Manipulation, 2007.
