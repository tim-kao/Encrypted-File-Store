#ifndef CSTORE_DELETE
#define CSTORE_DELETE
#include "cstore_utils.h"

bool cstore_delete(char* archiveName, FILE* archiveFp, BYTE hashPassWd[], char* deleteFileName, long fileSize);

#endif