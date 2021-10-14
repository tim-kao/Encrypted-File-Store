#include "cstore_add.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"

int decryptMagicCode(FILE* archiveFp, WORD* key, BYTE* IV)
{
        BYTE buf[META_PASSWD_SIZE];
        BYTE decryptedBuf[META_PASSWD_SIZE];
        size_t numOfReadByte = fread(buf, 1, META_PASSWD_SIZE, archiveFp);
        aes_decryptcbc(buf, decryptedBuf, key, AES_KEY_SIZE, IV, META_PASSWD_SIZE);
        if (numOfReadByte != META_PASSWD_SIZE)        throw std::out_of_range( "File reading error");
        return std::memcmp(magicCode, decryptedBuf, META_PASSWD_SIZE);
}

char* decryptString(FILE* archiveFp, WORD* key, BYTE* IV, int length)
{
        BYTE readBuf[AES_BLOCK_SIZE];
        BYTE decryptedBuf[length];
        size_t numReadByte = 0;
        char *String = new char[length];
        memset(String, 0, length);
        for (int i = 0; i < int(length/AES_BLOCK_SIZE); i++) 
        {
                numReadByte += fread(readBuf, 1, AES_BLOCK_SIZE, archiveFp);
                aes_decryptcbc(readBuf, decryptedBuf, key, AES_KEY_SIZE, IV, AES_BLOCK_SIZE);
                if (i == 0)     std::strncpy(String, reinterpret_cast<char*>(decryptedBuf), AES_BLOCK_SIZE);
                else     std::strncat(String, reinterpret_cast<char*>(decryptedBuf), AES_BLOCK_SIZE);
        }
        if (numReadByte != length) throw std::out_of_range( "File reading error");
        return (String);
}

int* decryptInteger(FILE* archiveFp, WORD* key, BYTE* IV)
{
        BYTE buf[META_FILENAME_SIZE];
        size_t numOfReadByte = fread(buf, 1, META_FILENAME_SIZE, archiveFp);
        if (numOfReadByte != META_FILENAME_SIZE)        throw std::out_of_range( "File reading error");
        BYTE decryptedBuf[META_FILENAME_SIZE];
        aes_decryptcbc(buf, decryptedBuf, key, AES_KEY_SIZE, IV, META_FILENAME_SIZE);
        int* value = new int[sizeof(int)];
        *value = *(int *)decryptedBuf;
        return value;
}

long* decryptLong(FILE* archiveFp, WORD* key, BYTE* IV)
{
        BYTE buf[META_FILELENGTH];
        size_t numOfReadByte = fread(buf, 1, META_FILELENGTH, archiveFp);
        if (numOfReadByte != META_FILELENGTH)        throw std::out_of_range( "File reading error");
        BYTE decryptedBuf[META_FILELENGTH];
        aes_decryptcbc(buf, decryptedBuf, key, AES_KEY_SIZE, IV, META_FILELENGTH);
        long* value = new long[sizeof(long)];
        *value = *(long *)decryptedBuf;
        return value;
}


std::unordered_map<std::string, long> verifyFileHMAC(FILE* archiveFp, BYTE hashPassWd[])
{
        std::unordered_map<std::string, long> filenameTofpOffset;
        fseek(archiveFp, SHA256_BLOCK_SIZE, SEEK_SET);  //32
        WORD key_schedule[KEY_SCHEDULE_SIZE];
        aes_key_setup(hashPassWd, key_schedule, AES_KEY_SIZE);
        while(true) 
        {
                BYTE* HMACofFile = getHMAC(archiveFp);   // 64
                BYTE* IV = getIV(archiveFp);    // 80
                int passIsValid = decryptMagicCode(archiveFp, key_schedule, IV); // 96
                if (passIsValid != 0)
                {
                        free(HMACofFile);
                        free(IV);
                        throw std::logic_error( "Incorrect Password");
                }
                int* fileNameLength = decryptInteger(archiveFp, key_schedule, IV);
                char* fileName = decryptString(archiveFp, key_schedule, IV, META_FILENAME);
                long offsetofFile = ftell(archiveFp) - METADATA_SIZE + META_FILELENGTH;
                filenameTofpOffset.insert(make_pair(std::string(fileName, *fileNameLength), offsetofFile));
                long* fileLength = decryptLong(archiveFp, key_schedule, IV);
                long numOfAESBlock = 16 * ceil(float(*fileLength) / 16);
                long size = numOfAESBlock + METADATA_SIZE;
                fseek(archiveFp, -METADATA_SIZE, SEEK_CUR);
                BYTE* HMAC_compute = genHMAC(archiveFp, hashPassWd, size);
                int checkIntegrity = memcmp(HMAC_compute, HMACofFile, 32);
                // release memory
                free(fileNameLength);
                free(fileName);
                free(fileLength);
                free(IV);
                free(HMACofFile);
                free(HMAC_compute);
                // integrity check and eof detection
                if(checkIntegrity!= 0)  throw std::logic_error( "File HMAC Error");
                if (ferror(archiveFp)) throw std::out_of_range( "File access Error");
                if (getc(archiveFp) == EOF) break;
                fseek(archiveFp, -1, SEEK_CUR);
        }
        std::cout << "File HMAC passed verification\n";
        return filenameTofpOffset;
}

std::unordered_map<std::string, long> verifyArchive(FILE* archiveFp, BYTE* key, long length)
{
        verifyArchiveHMAC(archiveFp, key, length);
        return verifyFileHMAC(archiveFp, key);
}

void cstore_extract(FILE *archiveFp, BYTE hashPassWd[], char *newFileName)
{
        WORD key[KEY_SCHEDULE_SIZE];
        aes_key_setup(hashPassWd, key, AES_KEY_SIZE);
        BYTE *IV = getIV(archiveFp);  
        int passIsValid = decryptMagicCode(archiveFp, key, IV);
        int* fileNameLength = decryptInteger(archiveFp, key, IV);
        char* fileName = decryptString(archiveFp, key, IV, META_FILENAME);
        long* fileLength = decryptLong(archiveFp, key, IV);
        FILE* DecryptFp = fopen(newFileName, "wb+");
        if(DecryptFp == NULL)  throw std::out_of_range( "File access error");
        long numOfAESBlock = AES_BLOCK_SIZE * ceil(float(*fileLength) / AES_BLOCK_SIZE);
        BYTE* decryption_buf = new BYTE[numOfAESBlock];
        BYTE* decrypted_buf = new BYTE[numOfAESBlock];
        fread(decryption_buf, 1, numOfAESBlock, archiveFp);
        aes_decryptcbc(decryption_buf, decrypted_buf, key, AES_KEY_SIZE, IV, numOfAESBlock);
        long numOfWriteByte = fwrite(decrypted_buf, 1, *fileLength, DecryptFp);
        free(fileNameLength);
        free(fileName);
        free(IV);
        free(decryption_buf);
        free(decrypted_buf);
        fclose(DecryptFp);

        if (numOfWriteByte != *fileLength or ferror(archiveFp))  throw std::out_of_range( "File access error");
        free(fileLength);
        std::cout << "File " << newFileName << " extracted \n";

}