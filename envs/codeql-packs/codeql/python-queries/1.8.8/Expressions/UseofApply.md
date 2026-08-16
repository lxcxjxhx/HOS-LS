# 'apply' function used
The 'apply' function is deprecated and makes code harder to read as most Python programmers will not be familiar with it (it has been deprecated since 2003).


## Recommendation
Replace `apply(function, args)` with `function(*args)`.

Replace `apply(function, args, keywords)` with `function(*args, **keywords)`.


## References
* Python Standard Library: [apply](http://docs.python.org/2/library/functions.html#apply).
* Python PEP-290: [Code Migration and Modernization](http://www.python.org/dev/peps/pep-0290/).
