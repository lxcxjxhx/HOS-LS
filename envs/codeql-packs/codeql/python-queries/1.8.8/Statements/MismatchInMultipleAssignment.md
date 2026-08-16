# Mismatch in multiple assignment
An assignment statement evaluates a sequence expression and assigns each item of the sequence to one of the variables on the left. If there is a mismatch between the number of variables on the left and the values in the sequence on the right of the statement, then an exception is raised at runtime.


## Recommendation
Ensure that the number of variables on either side of the assignment match.


## Example
The following examples show a simple definition of the Fibonacci series. In the first example, one of the values in the assignment has been duplicated, causing an exception at runtime.


```python
# Fibonacci series 1:
# the sum of two elements defines the next

a, b = 0, 1, 1  # Assignment fails: accidentally put three values on right
while b < 10:
     print b
     a, b = b, a+b

# Fibonacci series 2:
# the sum of two elements defines the next
a, b = 0, 1   # Assignment succeeds: two variables on left and two values on right
while b < 10:
     print b
     a, b = b, a+b

```

## References
* Python Language Reference: [ Assignment statements](http://docs.python.org/2/reference/simple_stmts.html#grammar-token-assignment_stmt).
* Python Tutorial: [ First steps towards programming](http://docs.python.org/2/tutorial/introduction.html#first-steps-towards-programming).
