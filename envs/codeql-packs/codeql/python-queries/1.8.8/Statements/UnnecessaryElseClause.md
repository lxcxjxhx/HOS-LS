# Unnecessary 'else' clause in loop
The `else` clause of a loop (either a `for` or a `while` statement) executes immediately after the loop terminates normally. If there is a `break` statement in the loop body, then the `else` clause is skipped. If there is no `break` statement, then the `else` clause will always be executed after the loop, unless it exits with a `return` or `raise`. Therefore, if there is no `break` statement in the loop body then the `else` clause can be replaced with unindented code.

Generally the use of `else` clauses should be avoided where possible, as they are likely to be misunderstood.


## Recommendation
Replace the `else` clause with unindented code.


## Example
In this example, the `pointless_else` function contains a redundant `else` clause. The `else` clause can be simplified, as shown in the `no_else` function, which has the same semantics, but has no `else` clause. The third example function, `with_break`, shows a version where the `else` clause is necessary, as the `break` statement skips the `else` clause.


```python
def pointless_else(container):
    for item in container:
        if of_interest(item):
            return item
    else:
        raise NotFoundException()

def no_else(container):
    for item in container:
        if of_interest(item):
            return item
    raise NotFoundException()

def with_break(container):
    for item in container:
        if of_interest(item):
            found = item
            break
    else:
        raise NotFoundException()
    return found

```

## References
* Python Language Reference: [The while statement](http://docs.python.org/2/reference/compound_stmts.html#the-while-statement).
* Python Tutorial: [Break and continue statements, and else clauses on loops](http://docs.python.org/2/tutorial/controlflow.html#break-and-continue-statements-and-else-clauses-on-loops).
