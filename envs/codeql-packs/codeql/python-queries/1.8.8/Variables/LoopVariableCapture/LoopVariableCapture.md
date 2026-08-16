# Loop variable capture
In Python, a nested function or lambda expression that captures a variable from its surrounding scope is a *late-binding* closure, meaning that the value of the variable is determined when the closure is called, not when it is created.

Care must be taken when the captured variable is a loop variable. If the closure is called after the loop ends, it will use the value of the variable on the last iteration of the loop, rather than the value at the iteration at which it was created.


## Recommendation
Ensure that closures that capture loop variables aren't used outside of a single iteration of the loop. To capture the value of a loop variable at the time the closure is created, use a default parameter, or `functools.partial`.


## Example
In the following (BAD) example, a `tasks` list is created, but each task captures the loop variable `i`, and reads the same value when run.


```python
# BAD: The loop variable `i` is captured.
tasks = []
for i in range(5):
    tasks.append(lambda: print(i))

# This will print `4,4,4,4,4`, rather than `0,1,2,3,4` as likely intended.
for t in tasks:
    t() 
```
In the following (GOOD) example, each closure has an `i` default parameter, shadowing the outer `i` variable, the default value of which is determined as the value of the loop variable `i` at the time the closure is created.


```python
# GOOD: A default parameter is used, so the variable `i` is not being captured.
tasks = []
for i in range(5):
    tasks.append(lambda i=i: print(i))

# This will print `0,1,2,3,4``.
for t in tasks:
    t() 
```
In the following (GOOD) example, `functools.partial` is used to partially evaluate the lambda expression with the value of `i`.


```python
import functools
# GOOD: `functools.partial` takes care of capturing the _value_ of `i`.
tasks = []
for i in range(5):
    tasks.append(functools.partial(lambda i: print(i), i))

# This will print `0,1,2,3,4``.
for t in tasks:
    t() 
```

## References
* The Hitchhiker's Guide to Python: [Late Binding Closures](http://docs.python-guide.org/en/latest/writing/gotchas/#late-binding-closures).
* Python Language Reference: [Naming and binding](https://docs.python.org/reference/executionmodel.html#naming-and-binding).
* Stack Overflow: [Creating functions (or lambdas) in a loop (or comprehension)](https://stackoverflow.com/questions/3431676/creating-functions-or-lambdas-in-a-loop-or-comprehension).
* Python Language Reference: [functools.partial](https://docs.python.org/3/library/functools.html#functools.partial).
