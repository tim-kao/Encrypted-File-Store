# COMSW4181_001_2021_3 - SECURITY I
Assignment 1 - Encrypted File Store for Fall 2021 by **Shuoting Kao (UNI: sk4920)**

## Overview ##
A simple file store supports encryption and decryption.

## Demo[Watch the video](https://youtu.be/V-TPNGS4GOQ)

### Funciton
- List
- Add
- Extract
- Delete

### Design choice
#### CBC vs. ECB
I choose CBC because it prevent information leaking compared to ECB, especially matters if we encrypt image files. Through cascading the block ciphers, every block cipher's input depends on the previous output. In this architecture, flipping one bit can change whole file. On the contrary, ECB does not. 

#### List function implementation
I store all archive and its associated files within list.txt and it is plain. We do not need to encrypt list.txt since users can easily obtain the information by 'cstore list archive'. The implementation is straightforward. I simply write each 'archive/file' as a string into list.txt, and one line one 'archive/file'. For example, supposed an archive has HW1.pdf and HW2.pdf, the content presents as 
archive/HW1.pdf\
archive/HW2.pdf\
To support list function, I iterate over each line and see if any archive match and return all of its associated files.


### Archive Encryption Format
| HMAC(32) |[|File1 HMAC(32) | IV(16) | magicCode(16) | fileNameLength(16) | fileName(32) | filelength(16) | data ] |...\
META block size is file HMAC(32) + other(96) = 128 bytes