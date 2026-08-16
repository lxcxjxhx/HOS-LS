# Lines of commented-out code in files
This metric counts the number of lines of commented-out code in each file. Large amounts of commented-out code often indicate poorly maintained code.


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
