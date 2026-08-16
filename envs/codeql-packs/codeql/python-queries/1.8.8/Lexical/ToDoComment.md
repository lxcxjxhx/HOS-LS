# 'To Do' comment
A comment that includes the word `TODO` often marks a part of the code that is incomplete or broken, or highlights ambiguities in the software's specification.

For example, this list of comments is typical of those found in real programs:

* `TODO: move this code somewhere else`
* `TODO: find a better solution to this workaround`
* `TODO: test this`

## Recommendation
It is very important that `TODO` comments are not just removed from the code. Each of them must be addressed in some way.

Simpler comments can usually be immediately addressed by fixing the code, adding a test, doing some refactoring, or clarifying the intended behavior of a feature.

In contrast, larger issues may require discussion, and a significant amount of work to address. In these cases it is a good idea to move the comment to an issue-tracking system, so that the issue can be tracked and prioritized relative to other defects and feature requests.


## Example
The following example shows a function where a TODO comment indicates a known limitation in the existing implementation. The function should be reviewed, the limitation addressed and then the comment deleted.


```python
def realpath(path):
    '''
    Returns the true, canonical file system path equivalent to the given
    path.
    '''
    # TODO: There may be a more clever way to do this that also handles other,
    # less common file systems.
    return os.path.normpath(normcase(os.path.realpath(path)))
```

## References
* Wikipedia: [ Comment tags](http://en.wikipedia.org/wiki/Comment_%28computer_programming%29#Tags).
* Common Weakness Enumeration: [CWE-546](https://cwe.mitre.org/data/definitions/546.html).
