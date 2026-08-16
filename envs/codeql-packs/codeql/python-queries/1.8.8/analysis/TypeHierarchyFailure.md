# Inheritance hierarchy cannot be inferred for class
In order to analyze uses of a class, all its attributes need to be known. Without the full inheritance hierarchy this is impossible. This query finds classes where type inference fails and gives some indication as to why that failure occurred.

This is an informational query only, this query depends on points-to and type inference. Unlike normal queries it does not indicate any problem with the program being analyzed.

