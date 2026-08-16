# Unguarded next in generator
The function `next()` will raise a `StopIteration` exception if the underlying iterator is exhausted. Normally this is fine, but in a generator may cause problems. Since the `StopIteration` is an exception it will be propagated out of the generator causing termination of the generator. This is unlikely to be the expected behavior and may mask errors.

This problem is considered sufficiently serious that [PEP 479](https://www.python.org/dev/peps/pep-0479) has been accepted to modify the handling of `StopIteration` in generators. Consequently, code that does not handle `StopIteration` properly is likely to fail in future versions of Python.


## Recommendation
Each call to `next()` should be wrapped in a `try-except` to explicitly handle `StopIteration` exceptions.


## Example
In the following example, an empty file part way through iteration will silently truncate the output as the `StopIteration` exception propagates to the top level.


```python

test_files = [
    ["header1", "text10", "text11", "text12"],
    ["header2", "text20", "text21", "text22"],
    [],
    ["header4", "text40", "text41", "text42"],
]

def separate_headers(files):
    for file in files:
        lines = iter(file)
        header = next(lines) # Will raise StopIteration if lines is exhausted
        body = [ l for l in lines ]
        yield header, body

def process_files(files):
    for header, body in separate_headers(files):
        print(format_page(header, body))


```
In the following example `StopIteration` exception is explicitly handled, allowing all the files to be processed.


```python

def separate_headers(files):
    for file in files:
        lines = iter(file)
        try:
            header = next(lines) # Will raise StopIteration if lines is exhausted
        except StopIteration:
            #Empty file -- Just ignore
            continue
        body = [ l for l in lines ]
        yield header, body

```

## References
* Python PEP index: [PEP 479](https://www.python.org/dev/peps/pep-0479).
