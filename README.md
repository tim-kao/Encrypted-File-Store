# COMSW4181_001_2021_3 - SECURITY I
Assignment 1 - Encrypted File Store for Fall 2021 by **Shuoting Kao (UNI: sk4920)**

## Overview ##
A simple file store supports encryption and decryption.

### Features
- List
- Add
- Extract
- Delete

### Design choice
#### CBC vs. ECB
I choose CBC because it prevents the information from leaking compared to ECB, especially if we encrypt image files. Through cascading the block ciphers, every block cipher's input depends on the previous output. In this architecture, flipping one bit can change the whole file. On the contrary, ECB does not. 

#### List feature implementation
I store all archives and their associated files within list.txt, and it is plain. We do not need to encrypt list.txt since users can easily obtain the information by 'cstore list archive'. The implementation is straightforward. I simply write each 'archive/file' as a string into list.txt, and one line one 'archive/file'. For example, suppose an archive has HW1.pdf and HW2.pdf, the content presents as \
archive/HW1.pdf\
archive/HW2.pdf\
I iterate over each line to support the list function and see if any archive matches and returns all associated files.

#### Add feature implementation
To add files into an archive, I go through list.txt to make sure no duplicates. If there is a duplicate, assert error and return. 
If no duplicate and file is accessible, then I store the archive/file into list.txt and encrypt the file into an archive with CBC mode. The format I store the file into an archive is shown in the following. Add/Extract/Delete have to follow this self-defined format accordingly.

##### Archive Encryption Format
| HMAC(32) |[|File1 HMAC(32) | IV(16) | magicCode(16) | fileNameLength(16) | fileName(32) | fileLength(16) | data ] |...\
META block size is file HMAC(32) + other(96) = 128 bytes\
The first 32 bytes are reserved for the archive's HMAC, and append each file's encryption after that. Each file consists of its metadata including HMAC(32 bytes), IV(16 bytes), magicCode(16 bytes), fileNameLength(16 bytes), fileName(32 bytes), fileLength(16 bytes). We have to generate this metadata and compute HMAC of this file in the end. Because AES_BLOCK_SIZE is 16 bytes, that is why most of the metadata is 16 bytes. the fileName has to be 32bytes since we have to support filename at most 20 characters. magicCode is a self-defined private key.

#### Extract feature implementation
Extract is straightforward. I simply check HMAC with a password to authenticate and ensure the integrity, then make sure the file's HMAC and the existence in list.txt. After that, I decrypt the file by setting up the AES key, and the CBC decrypt block. 


#### Delete feature implementation
Deletion is similar to extract, except we need to alter archive and list.txt. The difference is that I use a buffer to store the content after the deleted file point position, then resize the file size to the one without the deleted file. Finally, adjusting the file pointer position to the beginning of the deleted file and writing the buffer back all the way to the end. 