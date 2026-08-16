# Unused parameter
A parameter is never used.

It is sometimes necessary to have a variable which is not used. These unused variables should have distinctive names, to make it clear to readers of the code that they are deliberately not used. The most common conventions for indicating this are to name the variable `_` or to start the name of the variable with `unused` or `_unused`.

The query accepts the following names for variables that are intended to be unused:

* Any name consisting entirely of underscores.
* Any name containing `unused`.
* The names `dummy` or `empty`.
* Any "special" name of the form `__xxx__`.

## Recommendation
Delete the parameter from the relevant function or method. If that is not possible (due to overriding or similar) rename the parameter as described above.


## Example
In this example the parameter `filename` is ignored which is misleading.


```python
import random

def write_to_file(text, filename):
    with open("log.txt", "w") as file:
        file.write(text)

```
