# String concatenation in loop
If you concatenate strings in a loop then the time taken by the loop is quadratic in the number of iterations.


## Recommendation
Initialize an empty list before the start of the loop. During the loop append the substrings to the list. At the end of the loop, convert the list to a string by using `''.join(list)`.


## References
* Python Standard Library: [The str.join method](http://docs.python.org/library/string.html#string.join).
* Python Frequently Asked Questions: [ What is the most efficient way to concatenate many strings together?](http://docs.python.org/3/faq/programming.html#what-is-the-most-efficient-way-to-concatenate-many-strings-together).
