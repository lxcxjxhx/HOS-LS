# Use of exit() or quit()
The `exit` and `quit` "functions" are actually `site.Quitter` objects and are loaded, at interpreter start up, from `site.py`. However, if the interpreter is started with the `-S` flag, or a custom `site.py` is used then `exit` and `quit` may not be present.


## Recommendation
Replace uses of `exit()` and `quit()` with `sys.exit()` which is built into the interpreter and is guaranteed to be present.


## Example
In this example, `exit()` is used and will fail if the interpreter is passed the `-S` option.


```python

def main():
    try:
        process()
    except Exception as ex:
        print(ex)
        exit(1)

```
In this example, `sys.exit()` is used and will behave the same regardless of the interpreter options.


```python
import sys

def main():
    try:
        process()
    except Exception as ex:
        print(ex)
        sys.exit(1)

```

## References
* Python Documentation: [Command line and environment](https://docs.python.org/using/cmdline.html#cmdoption-S).
* Python Documentation: [Site-specific configuration hook](https://docs.python.org/library/site.html#module-site).
