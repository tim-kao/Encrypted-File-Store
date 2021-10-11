#include "cstore_add.h"
#include "cstore_extract.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include "crypto_lib/aes.h"

void encryptMagicCode(FILE* archiveFp, WORD* key, BYTE* IV) // 16bytes
{
        BYTE buf[META_PASSWD_SIZE];
        aes_encryptcbc(magicCode, buf, key, IV, META_PASSWD_SIZE);
        size_t numOfWriteByte = fwrite(buf, 1, META_PASSWD_SIZE, archiveFp);
        if (numOfWriteByte != META_PASSWD_SIZE) throw std::out_of_range( "File writing error");
}

void encryptInteger(FILE* archiveFp, int value, WORD *key, BYTE* IV) // 16bytes
{
        BYTE writeBuf[META_FILENAME_SIZE];
        BYTE ReadBuf[META_FILENAME_SIZE];
        int temp[4] = {value, 0, 0, 0};
        std::memcpy(ReadBuf, temp, META_FILENAME_SIZE);
        aes_encryptcbc(ReadBuf, writeBuf, key, IV, META_FILENAME_SIZE);
        size_t numOfWriteByte = fwrite(writeBuf, 1, META_FILENAME_SIZE, archiveFp);
        if (numOfWriteByte != META_FILENAME_SIZE)   throw std::out_of_range( "File writing error");
}

void encryptLong(FILE* archiveFp, long value, WORD *key, BYTE* IV) // 16bytes
{
        BYTE writeBuf[META_FILELENGTH];
        BYTE ReadBuf[META_FILELENGTH];
        long temp[4] = {value, 0, 0, 0}; // 4/8 byte for a long long for 32/64 bit OS
        std::memcpy(ReadBuf, temp, META_FILELENGTH);
        aes_encryptcbc(ReadBuf, writeBuf, key, IV, META_FILELENGTH);
        size_t numOfWriteByte = fwrite(writeBuf, 1, META_FILELENGTH, archiveFp);
        if (numOfWriteByte != META_FILELENGTH)   throw std::out_of_range( "File writing error");
}

void encryptString(FILE* archiveFp, char* fileName, WORD* key, BYTE *IV, int length) // variable length, must be multiple of 16
{
        BYTE writeBuf[AES_BLOCK_SIZE];
        BYTE temp[AES_BLOCK_SIZE];
        size_t numOfWriteByte = 0;
        for(int i = 0; i < int(length / AES_BLOCK_SIZE); i++) 
        {
                std::memset(writeBuf, 0, AES_BLOCK_SIZE);
                std::memcpy(temp, &fileName[i * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
                aes_encryptcbc(temp, writeBuf, key, IV, AES_BLOCK_SIZE);
                numOfWriteByte += fwrite(writeBuf, 1, AES_BLOCK_SIZE, archiveFp);
        }
        if (numOfWriteByte != length)        throw std::out_of_range( "File writing error");
}

int cstore_add(FILE *srcFile, FILE *archiveFp, FILE *list, BYTE hashPassWd[], int fileNameLength, char *fileName, long fileLength)
{   
        // Appending starts from the end of archive
        fseek(archiveFp, 0, SEEK_END);
        WORD key[KEY_SCHEDULE_SIZE];
        aes_key_setup(hashPassWd, key, AES_KEY_SIZE);
        BYTE *IV = genIV();
        padFile(archiveFp, SHA256_BLOCK_SIZE); // 32 bytes reserved for file HMAC
        addIV(archiveFp, IV); //16 bytes (128b)
        encryptMagicCode(archiveFp, key, IV); //16
        encryptInteger(archiveFp, fileNameLength, key, IV); // 16 file length
        encryptString(archiveFp, fileName, key, IV, META_FILENAME); // 32 file name 
        encryptLong(archiveFp, fileLength, key, IV); //16 META_FILELENGTH

        long numOfAESBlock = 16 * ceil(float(fileLength) / 16);
        BYTE *readBuf = new BYTE[numOfAESBlock];
        BYTE *writeBuf = new BYTE[numOfAESBlock];
        size_t numOfByteRead = fread(readBuf, 1, fileLength, srcFile);
        if (numOfByteRead != fileLength)    throw std::length_error( "Error");
        padBuf(readBuf + numOfByteRead, numOfAESBlock - numOfByteRead); // tail padding
        aes_encryptcbc(readBuf, writeBuf, key, IV, numOfAESBlock);
        size_t numOfWriteByte = fwrite(writeBuf, 1, numOfAESBlock, archiveFp);
        if (numOfWriteByte != numOfAESBlock)     throw std::length_error( "HMAC update error");
        if (ferror(archiveFp)) throw std::length_error( "Error");
        long encryptedLen = numOfAESBlock + METADATA_SIZE;
        fseek(archiveFp, -encryptedLen, SEEK_CUR);
        BYTE *HMAC = genHMAC(archiveFp, hashPassWd, encryptedLen);
        encryptedLen += SHA256_BLOCK_SIZE;
        fseek(archiveFp, -encryptedLen, SEEK_CUR);
        numOfWriteByte = fwrite(HMAC, 1, SHA256_BLOCK_SIZE, archiveFp);
        if (numOfWriteByte != SHA256_BLOCK_SIZE) throw std::length_error( "HMAC update error");
        free(IV);
        free(readBuf);
        free(writeBuf);
        free(HMAC);
        
    return 1;
}