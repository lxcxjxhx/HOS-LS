# Frequency counts for external APIs that are used with untrusted data
Using unsanitized untrusted data in an external API can cause a variety of security issues. This query reports external APIs that are used with untrusted data, along with how frequently the API is used, and how many unique sources of untrusted data flow to this API. This query is designed primarily to help identify which APIs may be relevant for security analysis of this application.

An external API is defined as a call to a method that is not defined in the source code, and is not modeled as a taint step in the default taint library. External APIs may be from the Python standard library or dependencies. The query will report the fully qualified name, along with `[position index]` or `[keyword name]`, to indicate the argument passing the untrusted data.

Note that an excepted sink might not be included in the results, if it also defines a taint step. This is the case for `pickle.loads` which is a sink for the Unsafe Deserialization query, but is also a taint step for other queries.

Note: Compared to the Java version of this query, we currently do not give special care to methods that are overridden in the source code.


## Recommendation
For each result:

* If the result highlights a known sink, no action is required.
* If the result highlights an unknown sink for a problem, then add modeling for the sink to the relevant query.
* If the result represents a call to an external API which transfers taint, add the appropriate modeling, and re-run the query to determine what new results have appeared due to this additional modeling.
Otherwise, the result is likely uninteresting. Custom versions of this query can extend the `SafeExternalAPI` class and specify `getSafeCallable` to exclude known safe external APIs from future analysis.


## Example
If the query were to return the API `flask.make_response [param 0]` then we should first consider whether this a security relevant sink. In this case, this is making a HTTP response, so we should consider whether this is an XSS sink. If it is, we should confirm that it is handled by the XSS query.

If the query were to return the API `base64.decodebytes [param 0]`, then this should be reviewed as a possible taint step, because tainted data would flow from the 0th argument to the result of the call.

Note that both examples are correctly handled by the standard taint tracking library and XSS query.


## References
* Common Weakness Enumeration: [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
