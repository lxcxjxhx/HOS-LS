# Unused local variable
A local variable is defined (by an assignment) but never used.

It is sometimes necessary to have a variable which is not used. These unused variables should have distinctive names, to make it clear to readers of the code that they are deliberately not used. The most common conventions for indicating this are to name the variable `_` or to start the name of the variable with `unused` or `_unused`.

The query accepts the following names for variables that are intended to be unused:

* Any name consisting entirely of underscores.
* Any name containing `unused`.
* The names `dummy` or `empty`.
* Any "special" name of the form `__xxx__`.
Variables that are defined in a group, for example `x, y = func()` are handled collectively. If they are all unused, then this is reported. Otherwise they are all treated as used.


## Recommendation
If the variable is included for documentation purposes or is otherwise intentionally unused, then change its name to indicate that it is unused, otherwise delete the assignment (taking care not to delete right hand side if it has side effects).


## Example
In this example, the `random_no` variable is never read but its assignment has a side effect. Because of this it is important to remove only the left hand side of the assignment in line 10.


```python
import random

def write_random_to_file():
    no = random.randint(1, 10)
    with open("random.txt", "w") as file:
        file.write(str(no))
    return no

def write_random():
    random_no = write_random_to_file()
    print "A random number was written to random.txt"
```

## References
* Python: [Assignment statements](http://docs.python.org/2/reference/simple_stmts.html#assignment-statements).
* Common Weakness Enumeration: [CWE-563](https://cwe.mitre.org/data/definitions/563.html).
