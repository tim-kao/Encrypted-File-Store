#ifndef CSTORE_UTILS
#define CSTORE_UTILS
#include <vector>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <math.h>    
#include <string>
#include <cstring>
#include <unordered_map>
#include <fstream>
#include <unistd.h>
#include "crypto_lib/aes.h"
#include "crypto_lib/sha256.h"

const unsigned char magicCode[] = "sk4920shuotingka";
const char eol[] = "\n";
const char slash[] = "/";
#define ListFile "list.txt"
#define errorList "error.txt"
#define HMAC_SHA256_ITERS 10000
#define ENCRYPT_SHA256_ITERS 20000 
#define HMAC_SIZE 64
#define MAXPASSWD 12
#define AES_KEY_SIZE 256
#define MAX_FILE_NAME_SIZE 20
#define KEY_SCHEDULE_SIZE 60
#define METADATA_SIZE 96
#define META_PASSWD_SIZE 16
#define META_FILENAME_SIZE 16
#define META_FILENAME 32
#define META_FILELENGTH 16
#define MAX_FILE_SIZE LONG_MAX

void show_usage(std::string name);

void print_hex(const BYTE* byte_arr, int len);

void print_hex(const std::vector<BYTE> byte_arr);

long GetFileSize(std::string filename);

BYTE* InitByte(int value, size_t length);

void padFile(FILE *Pt, size_t n);

void padBuf(BYTE *Pt, size_t n);

void xor_operator(const BYTE in[], BYTE out[], size_t length);

BYTE* genHMAC(FILE* archiveFp, BYTE *key, long size);

BYTE* getHMAC(FILE* archivePt);

void verifyArchiveHMAC(FILE *archiveFp, BYTE *key, long size);

void updateHMAC(FILE* archivePt, BYTE *key, long length);

BYTE* genIV();

void addIV(FILE *archivePt, BYTE *IV);

BYTE* getIV(FILE *archivePt);

void aes_decryptcbc(const BYTE in[], BYTE out[], const WORD key[], int keyLength, const BYTE IV[], size_t size);

void aes_encryptcbc(const BYTE in[], BYTE out[], const WORD key[], const BYTE IV[], size_t size);

BYTE* passwdTokey(SHA256_CTX ctx, char* passwd);

#endif
