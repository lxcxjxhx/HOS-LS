# PAM authorization bypass due to incorrect usage
Using only a call to `pam_authenticate` to check the validity of a login can lead to authorization bypass vulnerabilities.

A `pam_authenticate` only verifies the credentials of a user. It does not check if a user has an appropriate authorization to actually login. This means a user with an expired login or a password can still access the system.


## Recommendation
A call to `pam_authenticate` should be followed by a call to `pam_acct_mgmt` to check if a user is allowed to login.


## Example
In the following example, the code only checks the credentials of a user. Hence, in this case, a user with expired credentials can still login. This can be verified by creating a new user account, expiring it with ``` chage -E0 `username`  ``` and then trying to log in.


```python
libpam                    = CDLL(find_library("pam"))

pam_authenticate          = libpam.pam_authenticate
pam_authenticate.restype  = c_int
pam_authenticate.argtypes = [PamHandle, c_int]

def authenticate(username, password, service='login'):
    def my_conv(n_messages, messages, p_response, app_data):
        """
        Simple conversation function that responds to any prompt where the echo is off with the supplied password
        """
        ...

    handle = PamHandle()
    conv   = PamConv(my_conv, 0)
    retval = pam_start(service, username, byref(conv), byref(handle))

    retval = pam_authenticate(handle, 0)
    return retval == 0

```
This can be avoided by calling `pam_acct_mgmt` call to verify access as has been done in the snippet shown below.


```python
libpam                    = CDLL(find_library("pam"))

pam_authenticate          = libpam.pam_authenticate
pam_authenticate.restype  = c_int
pam_authenticate.argtypes = [PamHandle, c_int]

pam_acct_mgmt          = libpam.pam_acct_mgmt
pam_acct_mgmt.restype  = c_int
pam_acct_mgmt.argtypes = [PamHandle, c_int]

def authenticate(username, password, service='login'):
    def my_conv(n_messages, messages, p_response, app_data):
        """
        Simple conversation function that responds to any prompt where the echo is off with the supplied password
        """
        ...

    handle = PamHandle()
    conv   = PamConv(my_conv, 0)
    retval = pam_start(service, username, byref(conv), byref(handle))

    retval = pam_authenticate(handle, 0)
    if retval == 0:
        retval = pam_acct_mgmt(handle, 0)
    return retval == 0

```

## References
* Man-Page: [pam_acct_mgmt](https://man7.org/linux/man-pages/man3/pam_acct_mgmt.3.html)
* Common Weakness Enumeration: [CWE-285](https://cwe.mitre.org/data/definitions/285.html).
