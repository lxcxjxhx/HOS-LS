# Explicit returns mixed with implicit (fall through) returns
When a function contains both explicit returns (`return value`) and implicit returns (where code falls off the end of a function), this often indicates that a return statement has been forgotten. It is best to return an explicit return value even when returning `None` because this makes it easier for other developers to read your code.


## Recommendation
Add an explicit return at the end of the function.


## Example
In the `check_state1` function, the developer probably did intend to use an implicit return value of `None` as this equates to `False`. However, the function in `check_state2` is easier to read.


```python
    def check_state1(state, interactive=True):
        if not state['good'] or not state['bad']:
            if (good or bad or skip or reset) and interactive:
                return                                          # implicitly return None
            if not state['good']:
                raise util.Abort(_('cannot bisect (no known good revisions)'))
            else:
                raise util.Abort(_('cannot bisect (no known bad revisions)')) 
        return True  							                              
           
    def check_state2(state, interactive=True):
        if not state['good'] or not state['bad']:
            if (good or bad or skip or reset) and interactive:
                return False                                    # return an explicit value
            if not state['good']:
                raise util.Abort(_('cannot bisect (no known good revisions)'))
            else:
                raise util.Abort(_('cannot bisect (no known bad revisions)'))
        return True

```

## References
* Python Language Reference: [Function definitions](http://docs.python.org/3/reference/compound_stmts.html#function).
