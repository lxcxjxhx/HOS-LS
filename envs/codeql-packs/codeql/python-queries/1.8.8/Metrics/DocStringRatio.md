# Percentage of docstrings
This metric measures the percentage of lines in a file that contain a docstring. Note that this metric ignores comments.

Docstrings are a good way to associate documentation with a specific object in Python. For public modules, functions, classes and methods docstrings are the preferred method of documentation because the information can be inspected by the program at runtime, for example, as an interactive help system or as metadata for a function.

Having a low percentage of docstrings is often an indication that a file has insufficient documentation. However, the value for the related metric "Percentage of comments" should also be considered because packages and non-public methods may be documented using comments. Undocumented code is difficult to understand, modify, and reuse.


## Recommendation
Add documentation to files with a low docstring ratio. It is most useful to start documenting the public functions first.


## References
* Python for Beginners: [ Python Docstrings](http://www.pythonforbeginners.com/basics/python-docstrings/).
* Python PEP 8: [Documentation Strings](http://www.python.org/dev/peps/pep-0008/#documentation-strings).
* Python PEP 257: [Docstring Conventions](http://www.python.org/dev/peps/pep-0257/).
