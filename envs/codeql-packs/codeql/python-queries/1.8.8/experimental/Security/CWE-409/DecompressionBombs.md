# Decompression Bomb
Extracting Compressed files with any compression algorithm like gzip can cause to denial of service attacks.

Attackers can compress a huge file which created by repeated similiar byte and convert it to a small compressed file.


## Recommendation
When you want to decompress a user-provided compressed file you must be careful about the decompression ratio or read these files within a loop byte by byte to be able to manage the decompressed size in each cycle of the loop.


## Example
python ZipFile library is vulnerable by default


```python
import zipfile


def Bad(zip_path):
    zipfile.ZipFile(zip_path, "r").extractall()

```
By checking the decompressed size from input zipped file you can check the decompression ratio. attackers can forge this decompressed size header too. So can't rely on file_size attribute of ZipInfo class. this is recommended to use "ZipFile.open" method to be able to manage decompressed size.

Reading decompressed file byte by byte and verifying the total current size in each loop cycle in recommended to use in any decompression library.


```python
import zipfile


def safeUnzip(zipFileName):
    '''
    safeUnzip reads each file inside the zipfile 1 MB by 1 MB
    and during extraction or reading of these files it checks the total decompressed size
    doesn't exceed the SIZE_THRESHOLD
    '''
    buffer_size = 1024 * 1024 * 1  # 1 MB
    total_size = 0
    SIZE_THRESHOLD = 1024 * 1024 * 10  # 10 MB
    with zipfile.ZipFile(zipFileName) as myzip:
        for fileinfo in myzip.infolist():
            with myzip.open(fileinfo.filename, mode="r") as myfile:
                content = b''
                chunk = myfile.read(buffer_size)
                total_size += buffer_size
                if total_size > SIZE_THRESHOLD:
                    print("Bomb detected")
                    return False  # it isn't a successful extract or read
                content += chunk
                # reading next bytes of uncompressed data
                while chunk:
                    chunk = myfile.read(buffer_size)
                    total_size += buffer_size
                    if total_size > SIZE_THRESHOLD:
                        print("Bomb detected")
                        return False  # it isn't a successful extract or read
                    content += chunk

                # An example of extracting or reading each decompressed file here
                print(bytes.decode(content, 'utf-8'))
    return True  # it is a successful extract or read

```

## References
* [CVE-2023-22898](https://nvd.nist.gov/vuln/detail/CVE-2023-22898)
* [A great research to gain more impact by this kind of attack](https://www.bamsoftware.com/hacks/zipbomb/)
* Common Weakness Enumeration: [CWE-409](https://cwe.mitre.org/data/definitions/409.html).
