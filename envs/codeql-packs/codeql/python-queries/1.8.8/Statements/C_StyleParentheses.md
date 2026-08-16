# C-style condition
Python is designed to be more readable, at least for Western readers, than languages in the C family. This is achieved, in part, by using English language keywords and more familiar punctuation. Top level expressions are thus bracketed by the keyword and either a colon or new line, which can be more easily picked put by eye than parentheses.

Using superfluous parentheses can impair this readability by making the code harder to scan and parse by eye. Parentheses often serve as a visual clue for more complex expressions, and adding them unnecessarily can be distracting.

One notable exception to this rule is when an expression has to span multiple lines. In which case, using of parentheses is preferred to using a back slash for line continuation.


## Recommendation
Remove the unnecessary parentheses.


## Example
In the first of the two examples, most of the expressions are wrapped in parentheses. This is harder to read than the second example, especially to a programmer more familiar with Python than with C or Java.


```python

#Written in Java or C style
def gcd(a, b):
    while(a != 0 and b != 0):
        if(a > b):
            a = a % b
        else:
            b = b % a
    if(a == 0):
        return (b)
    return (a)

#Written in a more Pythonic style
def gcd(a, b):
    while a != 0 and b != 0:
        if a > b:
            a = a % b
        else:
            b = b % a
    if a == 0:
        return b
    return a


```

## References
* Python Language Reference: [Full grammar specification](https://docs.python.org/2/reference/grammar.html).
* Google Python Style Guide: [Use parentheses sparingly](https://google.github.io/styleguide/pyguide.html#Parentheses).
* Python PEP Index: [PEP 8](http://legacy.python.org/dev/peps/pep-0008/).
