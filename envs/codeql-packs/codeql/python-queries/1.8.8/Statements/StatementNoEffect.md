# Statement has no effect
An expression statement without side effects is just clutter. It confuses the reader and may have a slight impact on performance.


## Recommendation
First determine what the intention of the code was, if there is no intention of a side effect, then just delete the statement. However, it is probable that there is a mistake in the code and some effect was intended.

This query will not flag a statement consisting solely of a string as having no side effect, as these are often used as comments. If you want to use strings as comments, the most common convention is to use triple quoted strings rather than single quoted ones. Although consistency is more important than conforming to any particular style.


## Example
In this example neither line of the `increment_and_show()` function has any effect.

The first line, `++x`, has no effect as it applies the unary plus operator twice. Probably the programmer intended `x += 1`

The second line, `x.show`, has no observable effect, but it is likely that `x.show()` was intended.


```python

def increment_and_show(x):
    ++x
    x.show

```
