# crypt2cloud
Do not trust your Cloud. Always encrypt data before uploading.

This tool makes an AES encrypted backup of some folder directly in the cloud. There is no redundant data on your local drive.
Even the Metadata like filenames are encrypted, so nobody will be able to see any information about the data you uploaded.

## usage
Make sure you have mounted your cloud folder. We asume you used */media/cloud* in this examples.

To backup data in the folder */data/private* use this command.

```java -jar crypt2cloud --backup --plaindir /data/private --cryptdir /media/cloud/crypt2cloud --password cloudIsEvil```

This will result in a folder Structure similar to this:

```
/media/cloud/crypt2cloud/7/3/8/d/a/8/738da87e017f4161530f785850d80670
/media/cloud/crypt2cloud/b/8/d/4/b/8/b8d4b8ca5ce6aeb33e5fc4b6815a184f
/media/cloud/crypt2cloud/e/5/5/e/3/b/e55e3b217a82ff05dab9e1b5b22c6326
...
```

To restore data to a new folder */tmp/private_restored* use this command.

```java -jar crypt2cloud --restore --plaindir /tmp/private_restore --cryptdir /media/cloud/crypt2cloud --password cloudIsEvil```

