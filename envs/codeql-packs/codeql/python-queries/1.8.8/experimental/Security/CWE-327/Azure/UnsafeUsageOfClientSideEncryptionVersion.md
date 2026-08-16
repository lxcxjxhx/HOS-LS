# Unsafe usage of v1 version of Azure Storage client-side encryption
Azure Storage .NET, Java, and Python SDKs support encryption on the client with a customer-managed key that is maintained in Azure Key Vault or another key store.

Current release versions of the Azure Storage SDKs use cipher block chaining (CBC mode) for client-side encryption (referred to as `v1`).


## Recommendation
Consider switching to `v2` client-side encryption.


## Example

```python
blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
blob_client.require_encryption = True
blob_client.key_encryption_key = kek
# GOOD: Must use `encryption_version` set to `2.0`
blob_client.encryption_version = '2.0'  # Use Version 2.0!
with open("decryptedcontentfile.txt", "rb") as stream:
    blob_client.upload_blob(stream, overwrite=OVERWRITE_EXISTING)
```

## References
* [Azure Storage Client Encryption Blog.](http://aka.ms/azstorageclientencryptionblog)
* [CVE-2022-30187](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30187)
* Common Weakness Enumeration: [CWE-327](https://cwe.mitre.org/data/definitions/327.html).
