# Commented-out code
Commented-out code is distracting and confusing for developers who read the surrounding code, and its significance is often unclear. It will not get compiled or tested when the code around it changes, so it's likely to break over time. For these reasons, commented-out code should be avoided.


## Recommendation
Remove or reinstate the commented-out code. If you want to include a snippet of example code in a comment, consider enclosing it in quotes or marking it up as appropriate for the source language.


## Example
In the following example, a `print` statement, originally used for debugging, is left in the code, but commented out. It should be removed altogether.


```python
def area(r):
    #if DEBUG:
    #   print("Computing area of %r" % r)
    return r.length * r.width

```

## References
* Mark Needham: [The danger of commenting out code](http://www.markhneedham.com/blog/2009/01/17/the-danger-of-commenting-out-code/).
* Los Techies: [Commented Code == Technical Debt](http://lostechies.com/rodpaddock/2010/12/29/commented-code-technical-debt).
* High Integrity C++ Coding Standard: [2.3.2 Do not comment out code](http://www.codingstandard.com/rule/2-3-2-do-not-comment-out-code/).
