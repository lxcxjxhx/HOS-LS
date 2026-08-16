# Outgoing module dependencies
Efferent coupling is the number of outgoing dependencies for each module. In other words, it is the number of other modules on which each module depends.

A module that depends on many other modules is quite brittle, because if any of its dependencies change, the module itself may have to change as well. Furthermore, the reason for the high number of dependencies is often that different parts of the module depend on different groups of other modules, so it is common to find that modules with high efferent coupling also lack cohesion.


## Recommendation
You can reduce efferent coupling by splitting up a module so that each part depends on fewer modules.


## References
* IBM developerWorks: [Evolutionary architecture and emergent design: Emergent design through metrics](https://web.archive.org/web/20190919085934/https://www.ibm.com/developerworks/library/j-eaed6/).
* R. Martin, *Agile Software Development: Principles, Patterns and Practices*. Pearson, 2011.
