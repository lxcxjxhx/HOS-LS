# Use of a broken or weak cryptographic hashing algorithm on sensitive data
Using a broken or weak cryptographic hash function can leave data vulnerable, and should not be used in security related code.

A strong cryptographic hash function should be resistant to:

* pre-image attacks: if you know a hash value `h(x)`, you should not be able to easily find the input `x`.
* collision attacks: if you know a hash value `h(x)`, you should not be able to easily find a different input `y` with the same hash value `h(x) = h(y)`.
In cases with a limited input space, such as for passwords, the hash function also needs to be computationally expensive to be resistant to brute-force attacks. Passwords should also have an unique salt applied before hashing, but that is not considered by this query.

As an example, both MD5 and SHA-1 are known to be vulnerable to collision attacks.

Since it's OK to use a weak cryptographic hash function in a non-security context, this query only alerts when these are used to hash sensitive data (such as passwords, certificates, usernames).

Use of broken or weak cryptographic algorithms that are not hashing algorithms, is handled by the `py/weak-cryptographic-algorithm` query.


## Recommendation
Ensure that you use a strong, modern cryptographic hash function:

* such as Argon2, scrypt, bcrypt, or PBKDF2 for passwords and other data with limited input space.
* such as SHA-2, or SHA-3 in other cases.

## Example
The following example shows two functions for checking whether the hash of a certificate matches a known value -- to prevent tampering. The first function uses MD5 that is known to be vulnerable to collision attacks. The second function uses SHA-256 that is a strong cryptographic hashing function.


```python
import hashlib

def certificate_matches_known_hash_bad(certificate, known_hash):
    hash = hashlib.md5(certificate).hexdigest() # BAD
    return hash == known_hash

def certificate_matches_known_hash_good(certificate, known_hash):
    hash = hashlib.sha256(certificate).hexdigest() # GOOD
    return hash == known_hash

```

## Example
The following example shows two functions for hashing passwords. The first function uses SHA-256 to hash passwords. Although SHA-256 is a strong cryptographic hash function, it is not suitable for password hashing since it is not computationally expensive.


```python
import hashlib

def get_password_hash(password: str, salt: str):
    return hashlib.sha256(password + salt).hexdigest() # BAD

```
The second function uses Argon2 (through the `argon2-cffi` PyPI package), which is a strong password hashing algorithm (and includes a per-password salt by default).


```python
from argon2 import PasswordHasher

def get_initial_hash(password: str):
    ph = PasswordHasher()
    return ph.hash(password) # GOOD

def check_password(password: str, known_hash):
    ph = PasswordHasher()
    return ph.verify(known_hash, password) # GOOD

```

## References
* OWASP: [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* Common Weakness Enumeration: [CWE-327](https://cwe.mitre.org/data/definitions/327.html).
* Common Weakness Enumeration: [CWE-328](https://cwe.mitre.org/data/definitions/328.html).
* Common Weakness Enumeration: [CWE-916](https://cwe.mitre.org/data/definitions/916.html).
