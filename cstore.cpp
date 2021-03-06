#include <iostream>
#include <map>
#include <fstream>
#include <sstream>
#include <stdio.h>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include "crypto_lib/aes.h"
#include "crypto_lib/sha256.h"
#include "cstore_list.h"
#include "cstore_add.h"
#include "cstore_extract.h"
#include "cstore_delete.h"
#include "cstore_utils.h"
#define program "cstore"

void validatePasswd(char* passwd)
{
	if(strlen(passwd) > MAXPASSWD) throw std::invalid_argument( "Error: the length of a password is at most 12 characters\n" );
	for(int i = 0; i < int(strlen(passwd)); i++) if(!isascii(passwd[i])) throw std::invalid_argument( "Error: password must be ascii characters\n" );
}

int main(int argc, char* argv[])
{   
    // construct valid commands
    std::map<std::string, int> cmds;
    cmds["list"] = 1;
    cmds["add"] = 2;
    cmds["extract"] = 3;
    cmds["delete"] = 4;
    argv++;
    // check correct number of arguments (minimum 3)
    if(argc < 3)
    {
        show_usage(program);
        return 1;
    }
    // gets argv[1]
    char* cmd = *argv++;
    // check invalid commands
    if (cmds.find(cmd) == cmds.end()){
        std::cout << "Error: Invalid command. Use cstore [list|add|extract|delete] [-p] [password] archivename [files]\n";
        return 1;
    }
    // create list file if not exist
    FILE * ListFp;
    if (access(ListFile, F_OK) != 0)
    {
        ListFp = fopen(ListFile , "w+" );
        fclose(ListFp);
    }
    ListFp = fopen(ListFile , "r+" );
    
    // list
    if (cmds[cmd] == 1)
    {
        char* fileNameFp = *argv++;
        while (fileNameFp)
        {
            cstore_list(ListFp, fileNameFp);
            fileNameFp = *argv++;  
        }
        fclose(ListFp);
        return 1;
    }
    // add, extract, delete
    char dashp[] = "-p\0";
    char* option = *argv++;
    char* passwd;
    char* archiveName;
    SHA256_CTX ctx;
    
    // password in the arguments
    if (strcmp(dashp, option) == 0)
    {
        passwd = *argv++;
        if (passwd == NULL){
            show_usage("cstore");
            return 0;
        }
        archiveName = *argv++;
    }
    // user input pasword
    else
    {
        archiveName = option;
        passwd = getpass("Please enter password");
        free(passwd);
    }
    validatePasswd(passwd);
    BYTE* key = passwdTokey(ctx, passwd);
    // scan all files in the archive and make as a set for later use
    if (cmds[cmd] > 2 && access(archiveName, F_OK) != 0)
    {
        free(key);
        throw std::invalid_argument( "Error: archive is not available\n");
    }
    else if (cmds[cmd] > 2 && strlen(archiveName) > MAX_FILE_NAME_SIZE)  
    {
        free(key);
        throw std::invalid_argument( "Error: archive file name longer than 20 characters\n");
    }
    // add: write to archive and archive list
    FILE* archiveFp = NULL;
    FILE* fileFp = NULL;
    FILE* errorFp = NULL;
    struct stat archiveSt;
    struct stat fileSt;
    struct stat listSt;
    char* fileNameFp = *argv++;
    bool firstRound = true;
    std::unordered_map<std::string, long> filenameTofpOffset;
    
    if (fileNameFp == NULL) show_usage(program);

    while (fileNameFp)
    {
        stat(archiveName, &archiveSt);
        stat(fileNameFp, &fileSt);
        stat(ListFile, &listSt);
        switch(cmds[cmd])
        {
            case 2: // add file to archive
            {
                // archive does not exist or empty, create a new one. append 32bytes for HMAC
                if (firstRound)
                {
                    if (access(archiveName, F_OK) != 0 || archiveSt.st_size == 0)
                    {
                        archiveFp = fopen(archiveName , "wb+" );
                        padFile(archiveFp, SHA256_BLOCK_SIZE);
                        fclose(archiveFp);
                        archiveFp = fopen(archiveName , "rb+" );
                    }
                    else
                    {
                        archiveFp = fopen(archiveName , "rb+" );
                        filenameTofpOffset = verifyArchive(archiveFp, key, archiveSt.st_size - SHA256_BLOCK_SIZE);
                    }
                    //errorFp = fopen(errorList, "w");
                } 
                fileFp = fopen(fileNameFp , "rb" );
                if(access(archiveName, F_OK) == 0 && access(fileNameFp, F_OK) == 0 && MAX_FILE_SIZE >= fileSt.st_size > 0 && strlen(fileNameFp) <= MAX_FILE_NAME_SIZE)
                {
                    addList(ListFp, archiveName, fileNameFp);
                    cstore_add(fileFp, archiveFp, ListFp, key, strlen(fileNameFp), fileNameFp, fileSt.st_size);
                    std::cout << "Add files " << fileNameFp << " to "<< archiveName << "\n";
                } 
                else if (fileSt.st_size  > MAX_FILE_SIZE) std::cout << "File " << fileNameFp << "'s size is too larger\n";
                else if (strlen(fileNameFp) > MAX_FILE_NAME_SIZE) std::cout << "File " << fileNameFp << "'s name is at most 20 characters\n";
                else std::cout << "File '" << fileNameFp << "' is skipped because it is not accessible or empty\n";
                // update the archive HMAC in the end of all operations
                if (!*argv) 
                {
                    stat(archiveName, &archiveSt);
                    updateHMAC(archiveFp, key, archiveSt.st_size - SHA256_BLOCK_SIZE);
                    std::cout << "Double verification\n";
                    verifyArchive(archiveFp, key, archiveSt.st_size - SHA256_BLOCK_SIZE);
                } 
                break;
            }
            case 3: //extract
            {
                // Open files and verify/Parse archive. 
                // Single pass - put all files' pointer position into map filenameTofpOffset
                if (firstRound) 
                {
                    archiveFp = fopen(archiveName , "rb" );
                    errorFp = fopen(errorList, "w");
                    filenameTofpOffset = verifyArchive(archiveFp, key, archiveSt.st_size - SHA256_BLOCK_SIZE);
                }
                if (access(archiveName, F_OK) == 0)
                {
                    // file exists in both list.txt and archive
                    if(chkList(ListFp, archiveName, fileNameFp) && filenameTofpOffset.find(std::string(fileNameFp)) != filenameTofpOffset.end())
                    {
                        fseek(archiveFp, filenameTofpOffset[std::string(fileNameFp)], SEEK_SET); 
                        cstore_extract(archiveFp, key, fileNameFp);
                    }
                    else // file does not exist
                    {
                        std::cout << "File " << fileNameFp << " deletion failed due to absence in archive\n";
                        size_t s1 = fwrite(archiveName, 1, strlen(archiveName), errorFp);
                        size_t s2 = fwrite(slash, 1, strlen(slash), errorFp);
                        size_t s3 = fwrite(fileNameFp, 1, strlen(fileNameFp), errorFp);
                        size_t s4 = fwrite(eol, 1, strlen(eol), errorFp);
                        if ((s1 + s2 + s3 + s4) != strlen(archiveName) + strlen(slash) + strlen(fileNameFp) + strlen(eol)) throw std::range_error( "Error");
                    }
                }
                else
                {
                    throw std::invalid_argument( "Archive does not exist\n" );
                    free(key);
                    return 1;
                }
                if (!*argv) std::cout<<"Extraction completed.\n Files that does not exist in archive are loggeed in error.txt";
                break;       
            }    
            case 4: // delete
            {
                // Open files and verify/Parse archive. 
                // Single pass - put all files' pointer position into map filenameTofpOffset
                if (firstRound) 
                {
                    archiveFp = fopen(archiveName , "rb+" );
                    errorFp = fopen(errorList, "w");
                    verifyArchive(archiveFp, key, archiveSt.st_size - SHA256_BLOCK_SIZE);
                }
                if (access(archiveName, F_OK) == 0)
                {
                    // file exists in both list.txt and archive
                    if(chkList(ListFp, archiveName, fileNameFp) && cstore_delete(archiveName, archiveFp, key, fileNameFp, archiveSt.st_size))
                    {
                        delList(ListFp, archiveName, fileNameFp, listSt.st_size);
                    }
                    else // file does not exist
                    {
                        std::cout << "File " << fileNameFp << " deletion failed due to absence in archive\n";
                        size_t s1 = fwrite(archiveName, 1, strlen(archiveName), errorFp);
                        size_t s2 = fwrite(slash, 1, strlen(slash), errorFp);
                        size_t s3 = fwrite(fileNameFp, 1, strlen(fileNameFp), errorFp);
                        size_t s4 = fwrite(eol, 1, strlen(eol), errorFp);
                        if ((s1 + s2 + s3 + s4) != strlen(archiveName) + strlen(slash) + strlen(fileNameFp) + strlen(eol)) throw std::range_error( "Error");
                    }
                }
                else
                {
                    throw std::invalid_argument( "Archive does not exist\n" );
                    free(key);
                    return 1;
                }
                if (!*argv) 
                {
                    stat(archiveName, &archiveSt);
                    updateHMAC(archiveFp, key, archiveSt.st_size - SHA256_BLOCK_SIZE);
                    std::cout << "Deletation complete, check error.txt for failure items\n";
                } 
                break;       
            }    
        }
        if (fileFp) fclose(fileFp);
        fileNameFp = *argv++;   
        firstRound = false;
    }
    // close files and release memory
    if (archiveFp)  fclose(archiveFp);
    if (fileFp) fclose(fileFp);
    if (ListFp) fclose(ListFp);
    if (errorFp) fclose(errorFp);
    free(key);
    return 1;
}


