#include "cstore_extract.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"

bool cstore_delete(char* archiveName, FILE* archiveFp, BYTE hashPassWd[], char* deleteFileName, long fileSize)
{
    bool deleteSucc = false;
    fseek(archiveFp, SHA256_BLOCK_SIZE, SEEK_SET);  //32
    WORD key_schedule[KEY_SCHEDULE_SIZE];
    aes_key_setup(hashPassWd, key_schedule, AES_KEY_SIZE);
    while(true) 
    {
        long headOfFile = ftell(archiveFp);
        BYTE *HMACofFile = getHMAC(archiveFp);   // 64
        BYTE *IV = getIV(archiveFp);    // 80
        decryptMagicCode(archiveFp, key_schedule, IV); // 96
        int* fileNameLength = decryptInteger(archiveFp, key_schedule, IV);
        char* fileName = decryptString(archiveFp, key_schedule, IV, META_FILENAME);
        long* fileLength = decryptLong(archiveFp, key_schedule, IV);
        long numOfAESBlock = 16 * ceil(float(*fileLength) / 16);
        long size = numOfAESBlock + METADATA_SIZE;
        fseek(archiveFp, -METADATA_SIZE, SEEK_CUR);
        BYTE* HMAC_compute = genHMAC(archiveFp, hashPassWd, size);
        int checkIntegrity = memcmp(HMAC_compute, HMACofFile, 32);
        // release memory
        
        
        free(fileLength);
        free(IV);
        free(HMACofFile);
        free(HMAC_compute);
        // integrity check and eof detection
        if (checkIntegrity!= 0)  throw std::logic_error( "File HMAC Error");
        if (ferror(archiveFp)) throw std::out_of_range( "File access Error");
        if (memcmp(fileName, deleteFileName, size_t(*fileNameLength)) == 0) // if filename matches target, start deletion
        {
            long writeSize = fileSize - ftell(archiveFp);
            fileSize -= (ftell(archiveFp) - headOfFile);
            if (fileSize > SHA256_BLOCK_SIZE)
            {
                if (writeSize > 0)
                {
                    BYTE* temp = new BYTE[writeSize];
                    if (fread(temp, 1, writeSize, archiveFp) != writeSize)  throw std::out_of_range( "File read failed");
                    fseek(archiveFp, headOfFile, SEEK_SET);
                    if (fwrite(temp, 1, writeSize, archiveFp) != writeSize)  throw std::out_of_range( "File write failed");
                }
                if (truncate(archiveName, fileSize) != 0) throw std::out_of_range( "File resize failed");
            }
            else
            {
                if (remove(archiveName) == 0) std::cout << "Delete archive " << archiveName << " since it becomes empty\n";
                else    std::cout << "Error: Archive deleton failed\n";
            }
            deleteSucc = true;
        }
        free(fileName);
        free(fileNameLength);
        if (deleteSucc or getc(archiveFp) == EOF) break;
        fseek(archiveFp, -1, SEEK_CUR);
    }
    std::cout << deleteSucc << "File " << deleteFileName << " is delete\n";
    return deleteSucc;
}
