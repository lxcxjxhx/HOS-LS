# Arbitrary file write during a tarball extraction from a user controlled source
Extracting files from a malicious tarball without validating that the destination file path is within the destination directory using `shutil.unpack_archive()` can cause files outside the destination directory to be overwritten, due to the possible presence of directory traversal elements (`..`) in archive path names.

Tarball contain archive entries representing each file in the archive. These entries include a file path for the entry, but these file paths are not restricted and may contain unexpected special elements such as the directory traversal element (`..`). If these file paths are used to determine an output file to write the contents of the archive item to, then the file may be written to an unexpected location. This can result in sensitive information being revealed or deleted, or an attacker being able to influence behavior by modifying unexpected files.

For example, if a tarball contains a file entry `../sneaky-file.txt`, and the tarball is extracted to the directory `/tmp/tmp123`, then naively combining the paths would result in an output file path of `/tmp/tmp123/../sneaky-file.txt`, which would cause the file to be written to `/tmp/`.


## Recommendation
Ensure that output paths constructed from tarball entries are validated to prevent writing files to unexpected locations.

Consider using a safer module, such as: `zipfile`


## Example
In this example an archive is extracted without validating file paths.


```python
import requests
import shutil

url = "https://www.someremote.location/tarball.tar.gz"
response = requests.get(url, stream=True)

tarpath = "/tmp/tmp456/tarball.tar.gz"
with open(tarpath, "wb") as f:
      f.write(response.raw.read())

untarredpath = "/tmp/tmp123"
shutil.unpack_archive(tarpath, untarredpath)
```
To fix this vulnerability, we need to call the function `tarfile.extract()` on each `member` after verifying that it does not contain either `..` or startswith `/`.


```python
import requests
import tarfile

url = "https://www.someremote.location/tarball.tar.gz"
response = requests.get(url, stream=True)

tarpath = "/tmp/tmp456/tarball.tar.gz"
with open(tarpath, "wb") as f:
      f.write(response.raw.read())

untarredpath = "/tmp/tmp123"
with tarfile.open(tarpath) as tar:
	for member in tar.getmembers():
		if member.name.startswith("/") or ".." in member.name:
			raise Exception("Path traversal identified in tarball")

		tar.extract(untarredpath, member)
```

## References
* Shutil official documentation [shutil.unpack_archive() warning.](https://docs.python.org/3/library/shutil.html?highlight=unpack_archive#shutil.unpack_archive)
* Common Weakness Enumeration: [CWE-22](https://cwe.mitre.org/data/definitions/22.html).
