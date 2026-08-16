# Unused exception object
Creating a new exception object is no different from creating any other object. The exception needs to be raised to have an effect.


## Recommendation
Insert a `raise` before the exception.


## Example
In this example, the first function `do_action_forgotten_raise()` silently ignores any erroneous input. Whereas, the second function `do_action` correctly raises an exception if the 'action' is not understood.


```python

def do_action_forgotten_raise(action):
    if action == "go":
        start()
    elif action == "stop":
        stop()
    else:
        ValueError(action)

def do_action(action):
    if action == "go":
        start()
    elif action == "stop":
        stop()
    else:
        raise ValueError(action)

```
