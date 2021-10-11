#ifndef CSTORE_LIST
#define CSTORE_LIST

#include <iostream>
#include <set>
#include <vector>
#include <unordered_set>
#include <map>
#include <fstream>
#include <sstream>
#include <string>
#include <stdio.h>

//int cstore_list(std::string archivename);
void cstore_list(FILE *listFp, char* fileName);
void addList(FILE *listFp, char* archiveName, char* fileName);
bool chkList(FILE *listFp, char* archiveName, char* fileName);
void delList(FILE *listFp, char* archiveName, char* fileName, long length);
#endif