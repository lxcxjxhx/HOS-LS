# Added lines per file
This metric measures the number of lines of text that have been added, deleted or modified in files below this location in the tree.

Code churn is known to be a good (if not the best) predictor of defects in a code component (see e.g. \[Nagappan\] or \[Khoshgoftaar\]). The intuition is that files, packages or projects that have experienced a disproportionately high amount of churn for the amount of code involved may have been harder to write, and are thus likely to contain more bugs.


## Recommendation
It is a fact of life that some code is going to be changed more than the rest, and little can be done to change this. However, bearing in mind code churn's effectiveness as a defect predictor, code that has been repeatedly changed should be subjected to vigorous testing and code review.


## References
* N. Nagappan et al. *Change Bursts as Defect Predictors*. In Proceedings of the 21st IEEE International Symposium on Software Reliability Engineering, 2010.
* T. M. Khoshgoftaar and R. M. Szabo. *Improving code churn predictions during the system test and maintenance phases*. In ICSM '94, 1994, pp. 58-67.
