# Conflicting attributes in base classes
When a class subclasses multiple base classes, attribute lookup is performed from left to right amongst the base classes. This form of attribute lookup is called "method resolution order" and is a solution to the [diamond inheritance problem](http://en.wikipedia.org/wiki/Multiple_inheritance#The_diamond_problem) where several base classes override a method in a shared superclass.

Unfortunately, this means that if more than one base class defines the same attribute, the leftmost base class will effectively override the attribute of the rightmost base class, even though the leftmost base class is not a subclass of the rightmost base class. Unless the methods in question are designed for inheritance, using `super`, then this implicit overriding may not be the desired behavior. Even if it is the desired behavior it makes the code hard to understand and maintain.


## Recommendation
There are a number of ways that might be used to address this issue:

* Override the attribute in the subclass to implement the correct behavior.
* Modify the class hierarchy and move equivalent or redundant methods to a common super class.
* Modify the method hierarchy, breaking up complex methods into constituent parts.
* Use delegation rather than inheritance.

## Example
In this example the class `ThreadingTCPServer` inherits from `ThreadingMixIn` and from `TCPServer`. However, both these classes implement `process_request` which means that `ThreadingTCPServer` will inherit `process_request` from `ThreadingMixIn`. Consequently, the implementation of `process_request` in `TCPServer` will be ignored, which may not be the correct behavior.


```python

class TCPServer(object):
    
    def process_request(self, request, client_address):
        self.do_work(request, client_address)
        self.shutdown_request(request)

    
class ThreadingMixIn:
    """Mix-in class to handle each request in a new thread."""

    def process_request(self, request, client_address):
        """Start a new thread to process the request."""
        t = threading.Thread(target = self.do_work, args = (request, client_address))
        t.daemon = self.daemon_threads
        t.start()

class ThreadingTCPServer(ThreadingMixIn, TCPServer): pass

```
This can be fixed either by overriding the method, as shown in class `ThreadingTCPServerOverriding` or by ensuring that the functionality provided by the two base classes does not overlap, as shown in class `ThreadingTCPServerChangedHierarchy`.


```python
   
#Fixed by overriding. This does not change behavior, but makes it explicit and comprehensible.
class ThreadingTCPServerOverriding(ThreadingMixIn, TCPServer):
    
    def process_request(self, request, client_address):
        #process_request forwards to do_work, so it is OK to call ThreadingMixIn.process_request directly
        ThreadingMixIn.process_request(self, request, client_address)
        

#Fixed by separating threading functionality from request handling.
class ThreadingMixIn:
    """Mix-in class to help with threads."""

    def do_job_in_thread(self, job, args):
        """Start a new thread to do the job"""
        t = threading.Thread(target = job, args = args)
        t.start()

class ThreadingTCPServerChangedHierarchy(ThreadingMixIn, TCPServer):
    
    def process_request(self, request, client_address):
        """Start a new thread to process the request."""
        self.do_job_in_thread(self.do_work,  (request, client_address))
    

```

## References
* Python Language Reference: [Data model](https://docs.python.org/2/reference/datamodel.html).
* Python releases: [The Python 2.3 Method Resolution Order](https://www.python.org/download/releases/2.3/mro/).
* Wikipedia: [C3 linearization](https://en.wikipedia.org/wiki/C3_linearization).
* Wikipedia: [Composition over inheritance](http://en.wikipedia.org/wiki/Composition_over_inheritance).
