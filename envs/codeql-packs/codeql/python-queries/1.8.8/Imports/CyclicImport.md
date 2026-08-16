# Cyclic import
A cyclic import is an `import` which imports another module and that module imports (possibly indirectly) the module which contains the `import` statement.

Cyclic imports indicate that two modules are circularly dependent. This means that the modules cannot be tested independently, and it makes it harder to understand the architecture of the system.


## Recommendation
The cycle may be broken by removing any one import. If only one function or method requires the import, then consider moving that to the other module and deleting the import. If the two modules are more intimately connected, then move the inter-dependent parts into a third module and have both the original modules import that.


## References
* Python Language Reference: [The import statement](http://docs.python.org/2/reference/simple_stmts.html#import).
* Python: [Modules](http://docs.python.org/2/tutorial/modules.html).
* Effbot: [Import Confusion](https://web.archive.org/web/20200917011425/https://effbot.org/zone/import-confusion.htm).
