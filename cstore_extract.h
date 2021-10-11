#ifndef CSTORE_EXTRACT
#define CSTORE_EXTRACT
#include "cstore_utils.h"

void cstore_extract(FILE *archiveFp, BYTE hashPassWd[], char *newFileName);
std::unordered_map<std::string, long> verifyFileHMAC(FILE* archiveFp, BYTE hashPassWd[]);
std::unordered_map<std::string, long> verifyArchive(FILE* archiveFp, BYTE* key, long length);
int decryptMagicCode(FILE* archiveFp, WORD *key, BYTE *IV);
char* decryptString(FILE* archiveFp, WORD* key, BYTE* IV, int length);
int* decryptInteger(FILE* archiveFp, WORD* key, BYTE* IV);
long* decryptLong(FILE* archiveFp, WORD* key, BYTE* IV);

#endif