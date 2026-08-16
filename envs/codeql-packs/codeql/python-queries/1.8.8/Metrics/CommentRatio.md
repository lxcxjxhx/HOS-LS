# Percentage of comments
This metric measures the percentage of lines in a file that contain a comment or are part of a multi-line comment. Note that this metric ignores docstrings.

The percentage of comment lines should always be considered with the value for the related metric "Percentage of docstrings". For public modules, functions, classes and methods docstrings are the preferred method of documentation because the information can be inspected by the program at runtime, for example, as an interactive help system or as metadata for a function.

Having a low percentage of comments and docstrings is an indication that a file does not have sufficient documentation. Undocumented code is difficult to understand, modify, and reuse.


## Recommendation
Add documentation to files with a low comment and docstring ratio. Use docstrings to document public modules, functions, classes and methods.


## References
* Wikipedia: [ Need for comments](http://en.wikipedia.org/wiki/Comment_%28computer_programming%29#Need_for_comments).
* Python PEP 8: [Comments](http://www.python.org/dev/peps/pep-0008/#comments).
* Python for Beginners: [ Python Docstrings](http://www.pythonforbeginners.com/basics/python-docstrings/).
* Python PEP 257: [Docstring Conventions](http://www.python.org/dev/peps/pep-0257/).
