# Nested loops with same variable
In Python variables have function-wide scope which means that if two variables have the same name in the same scope, they are in fact one variable. Consequently, nested loops in which the target variables have the same name in fact share a single variable. Such loops are difficult to understand as the inner loop will modify the target variable of the outer loop; this may be a typographical error.


## Recommendation
Carefully examine the code and check for possible errors, particularly considering what would happen if the inner or outer variable were renamed.


## Example

```python

for var in range(3):
    for var in range(3):
        pass
    print (var) # Prints 2 2 2 not 0 1 2 as might be expected


```

## References
* Python Language Reference: [The for statement](http://docs.python.org/2/reference/compound_stmts.html#the-for-statement).
* Python Tutorial: [for statements](http://docs.python.org/2/tutorial/controlflow.html#for-statements).
