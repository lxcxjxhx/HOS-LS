# Unsafe shell command constructed from library input
Dynamically constructing a shell command with inputs from library functions may inadvertently change the meaning of the shell command. Clients using the exported function may use inputs containing characters that the shell interprets in a special way, for instance quotes and spaces. This can result in the shell command misbehaving, or even allowing a malicious user to execute arbitrary commands on the system.


## Recommendation
If possible, provide the dynamic arguments to the shell as an array to APIs such as `subprocess.run` to avoid interpretation by the shell.

Alternatively, if the shell command must be constructed dynamically, then add code to ensure that special characters do not alter the shell command unexpectedly.


## Example
The following example shows a dynamically constructed shell command that downloads a file from a remote URL.


```python
import os

def download(path): 
    os.system("wget " + path) # NOT OK

```
The shell command will, however, fail to work as intended if the input contains spaces or other special characters interpreted in a special way by the shell.

Even worse, a client might pass in user-controlled data, not knowing that the input is interpreted as a shell command. This could allow a malicious user to provide the input `http://example.org; cat /etc/passwd` in order to execute the command `cat /etc/passwd`.

To avoid such potentially catastrophic behaviors, provide the input from library functions as an argument that does not get interpreted by a shell:


```python
import subprocess

def download(path): 
    subprocess.run(["wget", path]) # OK

```

## References
* OWASP: [Command Injection](https://www.owasp.org/index.php/Command_Injection).
* Common Weakness Enumeration: [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
* Common Weakness Enumeration: [CWE-88](https://cwe.mitre.org/data/definitions/88.html).
* Common Weakness Enumeration: [CWE-73](https://cwe.mitre.org/data/definitions/73.html).
