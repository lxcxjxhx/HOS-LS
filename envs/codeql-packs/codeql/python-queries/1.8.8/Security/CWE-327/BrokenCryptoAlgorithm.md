# Use of a broken or weak cryptographic algorithm
Using broken or weak cryptographic algorithms may compromise security guarantees such as confidentiality, integrity, and authenticity.

Many cryptographic algorithms are known to be weak or flawed. The security guarantees of a system often rely on the underlying cryptography, so using a weak algorithm can have severe consequences. For example:

* If a weak encryption algorithm is used, an attacker may be able to decrypt sensitive data.
* If a weak algorithm is used for digital signatures, an attacker may be able to forge signatures and impersonate legitimate users.
This query alerts on any use of a weak cryptographic algorithm that is not a hashing algorithm. Use of broken or weak cryptographic hash functions are handled by the `py/weak-sensitive-data-hashing` query.


## Recommendation
Ensure that you use a strong, modern cryptographic algorithm, such as AES-128 or RSA-2048.


## Example
The following code uses the `pycryptodome` library to encrypt some secret data. When you create a cipher using `pycryptodome` you must specify the encryption algorithm to use. The first example uses DES, which is an older algorithm that is now considered weak. The second example uses AES, which is a stronger modern algorithm.


```python
from Crypto.Cipher import DES, AES

cipher = DES.new(SECRET_KEY)

def send_encrypted(channel, message):
    channel.send(cipher.encrypt(message)) # BAD: weak encryption


cipher = AES.new(SECRET_KEY)

def send_encrypted(channel, message):
    channel.send(cipher.encrypt(message)) # GOOD: strong encryption


```
NOTICE: the original `[pycrypto](https://pypi.org/project/pycrypto/)` PyPI package that provided the `Crypto` module is not longer actively maintained, so you should use the `[pycryptodome](https://pypi.org/project/pycryptodome/)` PyPI package instead (which has a compatible API).


## References
* NIST, FIPS 140 Annex a: [ Approved Security Functions](http://csrc.nist.gov/publications/fips/fips140-2/fips1402annexa.pdf).
* NIST, SP 800-131A: [ Transitions: Recommendation for Transitioning the Use of Cryptographic Algorithms and Key Lengths](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar1.pdf).
* OWASP: [Rule - Use strong approved cryptographic algorithms](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#rule---use-strong-approved-authenticated-encryption).
* Common Weakness Enumeration: [CWE-327](https://cwe.mitre.org/data/definitions/327.html).
