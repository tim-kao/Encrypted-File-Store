#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include "crypto_lib/aes.h"

#include <iostream>
#include <string>
#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <curses.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

void print_hex(const BYTE* byte_arr, int len)
{
    for(int i = 0; i < len; i++)
    {
        printf("%.2X", byte_arr[i]);
    }
}

void print_hex(const std::vector<BYTE> byte_arr)
{
    for(int i = 0; i < byte_arr.size(); i++)
    {
        printf("%.2X", byte_arr[i]);
    }
}

void show_usage(std::string name)
{
    std::cerr << "Usage: " << name << " <function> [-p password] archivename <files>\n"
              << "<function> can be: list, add, extract, delete.\n"
              << "Options:\n"
              << "\t-h, --help\t\t Show this help message.\n"
              << "\t-p <PASSWORD>\t\t Specify password (plaintext) in console. If not supplied, user will be prompted."
              << std::endl; 
}

BYTE* InitByte(int value, size_t length)
{
        BYTE* res = new BYTE[length];
        std::memset(res, value, length);
        return res;
}

void padFile(FILE *Pt, size_t n)
{
        char zeros[n];
        std::memset(zeros, 0, n);
        size_t size = fwrite(zeros, 1, n, Pt);
        if (size != n) throw std::length_error( "Archive read only or corrupted");
}

void padBuf(BYTE *Pt, size_t n)
{
        char zeros[n];
        std::memset(zeros, '0', n);
        std::memcpy(Pt, zeros, n);
}


// out = out ^ in
void xor_operator(const BYTE in[], BYTE out[], size_t length)
{
	for (size_t i = 0; i < length; i++)        out[i] ^= in[i];
}

// aes decrpyt cbc unit
void aes_decryptcbc(const BYTE in[], BYTE out[], const WORD key[], int keyLength, const BYTE IV[], size_t size)
{
	BYTE bufIn[AES_BLOCK_SIZE];
        BYTE bufOut[AES_BLOCK_SIZE];
        BYTE IVbuf[AES_BLOCK_SIZE];
	memcpy(IVbuf, IV, AES_BLOCK_SIZE);
	for (int i = 0; i < int(size / AES_BLOCK_SIZE); i++) 
        {
                memcpy(bufIn, &in[i * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
                aes_decrypt(bufIn, bufOut, key, keyLength);
                xor_operator(IVbuf, bufOut, AES_BLOCK_SIZE);
                memcpy(&out[ i * AES_BLOCK_SIZE], bufOut, AES_BLOCK_SIZE);
                memcpy(IVbuf, bufIn, AES_BLOCK_SIZE);
	}
}


BYTE *genHMAC(FILE* archiveFp, BYTE *key, long size)
{
        BYTE* readBuf = new BYTE[size];
        size_t numOfReadByte = fread(readBuf, 1, size, archiveFp);
        if (numOfReadByte != size) throw std::length_error( "archive read exception");
        BYTE ipad[SHA256_BLOCK_SIZE];
        BYTE opad[SHA256_BLOCK_SIZE];
        memset(ipad, 0x36, SHA256_BLOCK_SIZE);
        memset(opad, 0x5C, SHA256_BLOCK_SIZE);
        xor_operator(key, ipad, SHA256_BLOCK_SIZE); 
        xor_operator(key, opad, SHA256_BLOCK_SIZE); 

        BYTE righthmac[SHA256_BLOCK_SIZE];
        BYTE *hmac = new BYTE[SHA256_BLOCK_SIZE];
        BYTE *dataBuf = new BYTE [SHA256_BLOCK_SIZE + size];

        memset(dataBuf, 0, SHA256_BLOCK_SIZE + size);
        memcpy(dataBuf, ipad, SHA256_BLOCK_SIZE);
        memcpy(dataBuf + SHA256_BLOCK_SIZE, readBuf, size);

        SHA256_CTX ctx1;
        sha256_init(&ctx1);
        sha256_update(&ctx1, dataBuf, size + SHA256_BLOCK_SIZE);
        sha256_final(&ctx1, righthmac); 

        BYTE mac[SHA256_BLOCK_SIZE + SHA256_BLOCK_SIZE];
        memset(mac, 0, SHA256_BLOCK_SIZE + SHA256_BLOCK_SIZE);
        memcpy(mac, opad, SHA256_BLOCK_SIZE);
        memcpy(mac + SHA256_BLOCK_SIZE, righthmac, SHA256_BLOCK_SIZE);

        SHA256_CTX ctx2;
        sha256_init(&ctx2);
        sha256_update(&ctx2, mac, SHA256_BLOCK_SIZE + SHA256_BLOCK_SIZE);
        sha256_final(&ctx2, hmac);

        free(readBuf);
        free(dataBuf);
        return hmac;
}

// return HMAC of archive
BYTE* getHMAC(FILE* archivePt)
{
        BYTE* buf = new BYTE[32];
        if (fread(buf, 1, 32, archivePt) != 32) throw std::range_error( "Error: Archive HMAC is corrupted\n" );
        return buf;
}

// verify the HMAC
void verifyArchiveHMAC(FILE *archiveFp, BYTE *key, long size)
{
        fseek(archiveFp, 0, SEEK_SET);
        BYTE *HMAC_code = getHMAC(archiveFp);
        BYTE *HMAC_code_calc = genHMAC(archiveFp, key, size);
        int matchedResult = memcmp( HMAC_code, HMAC_code_calc, SHA256_BLOCK_SIZE);
        free(HMAC_code);
        free(HMAC_code_calc);
        if (matchedResult == 0) std::cout<<"Archive HMAC passed verification\n";
        else throw std::invalid_argument( "Authentication failed\n");
}

// update HMAC of archive
void updateHMAC(FILE* archivePt, BYTE *key, long length)
{
    fseek(archivePt, SHA256_BLOCK_SIZE, SEEK_SET);
    BYTE *HMAC = genHMAC(archivePt, key, length);
    fseek(archivePt, 0, SEEK_SET);
    size_t n = fwrite(HMAC, 1, 32, archivePt);
    free(HMAC);
    if (n != 32) throw std::length_error( "HMAC update error");
    verifyArchiveHMAC(archivePt, key, length);
}

// Generate IV(128bits)
BYTE* genIV()
{
    BYTE* IV = new BYTE [AES_BLOCK_SIZE];
    int temp[4];
    for (int i = 0; i < int(AES_BLOCK_SIZE / 4); i++) temp[i] = rand();
    std::memcpy(IV, temp, AES_BLOCK_SIZE);
    return IV;
}

void addIV(FILE* archivePt, BYTE* IV)
{
        size_t size = fwrite(IV, 1, AES_BLOCK_SIZE, archivePt);
        if (size != AES_BLOCK_SIZE) std::out_of_range("File writing error");
}    

BYTE* getIV(FILE* archivePt)
{
        BYTE *IV = new BYTE[AES_BLOCK_SIZE];
        size_t size = fread(IV, 1, AES_BLOCK_SIZE, archivePt);
        if (size != AES_BLOCK_SIZE) std::out_of_range("File writing error");
        return IV;
}

void aes_encryptcbc(const BYTE in[], BYTE out[], const WORD key[], const BYTE IV[], size_t size)
{
	BYTE bufIn[AES_BLOCK_SIZE];
        BYTE bufOut[AES_BLOCK_SIZE];
        BYTE IVbuf[AES_BLOCK_SIZE];
	std::memcpy(IVbuf, IV, AES_BLOCK_SIZE);

	for (int i = 0; i < int(size / AES_BLOCK_SIZE); i++) 
        {
                std::memcpy(bufIn, &in[i * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
                xor_operator(IVbuf, bufIn, AES_BLOCK_SIZE);
                aes_encrypt(bufIn, bufOut, key, AES_KEY_SIZE);
                std::memcpy(&out[i * AES_BLOCK_SIZE], bufOut, AES_BLOCK_SIZE);
                std::memcpy(IVbuf, bufOut, AES_BLOCK_SIZE);
	}
}


BYTE* passwdTokey(SHA256_CTX ctx, char* passwd)
{
    BYTE* key = new BYTE [SHA256_BLOCK_SIZE];
    BYTE* Bytes = reinterpret_cast<BYTE*>(const_cast<char*>(passwd));
    // Hash password with SHA256
    for (int i = 0; i < HMAC_SHA256_ITERS; ++i) 
    {
        sha256_init(&ctx);
        sha256_update(&ctx, Bytes, strlen(passwd));
        sha256_final(&ctx, key);
    }
    
    return key;
}