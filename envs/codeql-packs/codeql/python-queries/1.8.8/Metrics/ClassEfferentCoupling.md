# Outgoing class dependencies
Efferent coupling is the number of outgoing dependencies for each class. In other words, it is the number of other classes on which each class depends.

A class that depends on many other classes is quite brittle, because if any of its dependencies change, the class itself may have to change as well. Furthermore, the reason for the high number of dependencies is often that different parts of the class depend on different groups of other classes, so it is common to find that classes with high efferent coupling also lack cohesion.


## Recommendation
You can reduce efferent coupling by splitting up a class so that each part depends on fewer classes.


## Example
In the following example, class `X` depends on both `Y` and `Z`.


```python
class X:
    
    def iUseY(y):
        y.doStuff()

    def soDoY():
        return Y()

    def iUseZ(z1, z2):
        return z1.combine(z2)

```
However, the methods that use `Y` do not use `Z`, and the methods that use `Z` do not use `Y`. Therefore, the class can be split into two classes, one of which depends only on `Y` and the other only on `Z`


```python
class YX:

    def iUseY(y):
        y.doStuff()

    def soDoY():
        return Y()

class ZX:

    def iUseZ(z1, z2):
        return z1.combine(z2)

```
Although this is a slightly artificial example, this sort of situation does tend to occur in more complicated classes, so the general technique is quite widely applicable.


## References
* IBM developerWorks: [Evolutionary architecture and emergent design: Emergent design through metrics](https://web.archive.org/web/20190919085934/https://www.ibm.com/developerworks/library/j-eaed6/).
* R. Martin, *Agile Software Development: Principles, Patterns and Practices*. Pearson, 2011.
