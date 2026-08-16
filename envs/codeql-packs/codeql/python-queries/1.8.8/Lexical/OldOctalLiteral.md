# Confusing octal literal
Octal literals starting with 0 are easily misread as a decimal, particularly by those programmers who do not have a C or Java background.

The new literal syntax for non-decimal numbers is more distinct and is thus less likely to be misunderstood.


## Recommendation
Use the 0oXXX form instead of the 0XXX form. Alternatively use binary or hexadecimal format if that would be clearer.


## Example

```python

#Easily misread as x = 15
x = 015

#The extra 'o' alerts the reader that this is an octal literal
y = 0o15

#If this is a byte sized value then a hexadecimal might be clearer
y = 0x0d

#Or if it is a bit pattern then a binary value might be clearer
y = 0b1101

```

## References
* Python Language Reference: [Integer Literals](http://docs.python.org/2/reference/lexical_analysis.html#integer-and-long-integer-literals).
* Python PEP 3127: [Integer Literal Support and Syntax](http://www.python.org/dev/peps/pep-3127/).
