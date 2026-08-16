# Number of parameters without defaults
A function (or method) that uses a high number of parameters makes maintenance more difficult:

* It is difficult to write a call to the function, because the programmer must know how to supply an appropriate value for each parameter.
* It is *externally* difficult to understand, because calls to the function are longer than a single line of code.
* It can be *internally* difficult to understand, because it has so many dependencies.

## Recommendation
Restrict the number of parameters for a function, according to the reason for the high number:

* Several of the parameters are logically related, but are passed into the function separately. The parameters that are logically related should be grouped together (see the 'Introduce Parameter Object' refactoring on pp. 238-242 of \[Fowler\]).
* The function has too many responsibilities. It should be broken into multiple functions (see the 'Extract Method' refactoring on pp. 89-95 of \[Fowler\]), and each new function should be passed a subset of the original parameters.
* The function has redundant parameters that are not used. The two main reasons for this are: (1) parameters were added for future extensibility but are never used; (2) the body of the function was changed so that it no longer uses certain parameters, but the function signature was not correspondingly updated. In both cases, the theoretically correct solution is to delete the unused parameters (see the 'Remove Parameter' refactoring on pp. 223-225 of \[Fowler\]), although you must do this cautiously if the function is part of a published interface.
When a function is part of a published interface, one possible solution is to add a new, wrapper function to the interface that has a tidier signature. Alternatively, you can publish a new version of the interface that has a better design. Clearly, however, neither of these solutions is ideal, so you should take care to design interfaces the right way from the start.

The practice of adding parameters for future extensibility is especially bad. It is confusing to other programmers, who are uncertain what values they should pass in for these unnecessary parameters, and it adds unused code that is potentially difficult to remove later.


## Examples
In the following example, although the parameters are logically related, they are passed into the `print_annotation` function separately.


```python
def print_annotation(message, line, offset, length):
    print("Message: " + message)
    print("Line: " + line)
    print("Offset: " + offset)
    print("Length: " + length)
```
In the following modified example, the `print_annotation` function is simplified by logically grouping the related parameters into a single class. An instance of the class can then be passed into the function instead, as shown below.


```python
class Annotation:
    #...
    pass

def print_annotation(annotation):
    print("Message: " + annotation.message)
    print("Line: " + annotation.line)
    print("Offset: " + annotation.offset)
    print("Length: " + annotation.length)

```
In the following example, the `print_membership` function has too many responsibilities, and so needs to be passed four arguments.


```python
def print_membership(fellows, members, associates, students):
    for f in fellows:
        print(f)
    for m in members:
        print(m)
    for a in associates:
        print(a)
    for s in students:
        print(s)

def print_records():
    #...
    print_membership(fellows, members, associates, students)
```
In the following modified example, `print_membership` has been broken into four functions. (For brevity, only one function is shown.) As a result, each new function needs to be passed only one of the original four arguments.


```python

def print_fellows(fellows):
    for f in fellows:
        print(f)
        
#...

def print_records():
    #...
    print_fellows(fellows)
    print_members(members)
    print_associates(associates)
    print_students(students)
```

## References
* M. Fowler, *Refactoring*. Addison-Wesley, 1999.
