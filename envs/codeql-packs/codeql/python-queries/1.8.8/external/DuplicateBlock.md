# Duplicate code block
Blocks of code that are duplicated verbatim in several places in the code are candidates for refactoring into functions. The severity of this anti-pattern is higher for longer blocks than for short blocks.


## Recommendation
Code duplication is undesirable for a range of reasons: The artificially inflated amount of code hinders comprehension, and ranges of similar but subtly different lines can mask the real purpose or intention behind a function. There's also a risk of update anomalies, where only one of several copies of the code is updated to address a defect or add a feature.

In the case of code block duplication, how to address the issue depends on the blocks of code themselves. It may be possible to extract the block of code into its own function and call that instead of duplicating the code.


## References
* Elmar Juergens, Florian Deissenboeck, Benjamin Hummel, and Stefan Wagner. 2009. Do code clones matter? In *Proceedings of the 31st International Conference on Software Engineering* (ICSE '09). IEEE Computer Society, Washington, DC, USA, 485-495.
