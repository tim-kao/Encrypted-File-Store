#ifndef CSTORE_ADD
#define CSTORE_ADD
#include "cstore_utils.h"
int cstore_add(FILE *newFile, FILE *archiveFp, FILE *list, BYTE key[], int fileNameLength, char *fileName, long fileLength);
#endif