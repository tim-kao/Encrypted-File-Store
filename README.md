# COMSW4181_001_2021_3 - SECURITY I
Assignment 1 - Encrypted File Store for Fall 2021 by **Shuoting Kao (UNI: sk4920)**

## Overview ##
A simple file store supports encryption and decryption.

### Funciton
- List
- Add
- Extract
- Delete

### Design consideration


### Decision making


### Archive Encryption Format
| HMAC(32) |[|File1 HMAC(32) | IV(16) | magicCode(16) | fileNameLength(16) | fileName(32) | filelength(16) | data ] |.....
