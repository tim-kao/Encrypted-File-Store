#include "cstore_list.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"

void cstore_list(FILE* listFp, char* fileName)
{
        char * line = NULL;
        size_t len = 0;
        ssize_t read;
        while ((read = getline(&line, &len, listFp)) != -1) 
        {
                char* archiveName = strtok(line, "/");
                char* fileNameOfArchive = strtok (NULL, "/");
                if (strcmp(archiveName, fileName) == 0) std::cout<<fileNameOfArchive;
        }
        fseek(listFp, 0, SEEK_END);
}


bool chkList(FILE* listFp, char* archiveName, char* fileName)
{
        fseek(listFp, 0, SEEK_SET);
        char * line = NULL;
        size_t len = 0;
        ssize_t read;
        while ((read = getline(&line, &len, listFp)) != -1) 
        {
                char* archiveNameInList = strtok(line, "/");
                char* fileNameInList = strtok (NULL, "\n");
                if (strcmp(archiveName, archiveNameInList) == 0 && strcmp(fileName, fileNameInList) == 0)
                {
                    return true;
                } 
        }
        return false;
}

void addList(FILE* listFp, char* archiveName, char* fileName)
{
        if (chkList(listFp, archiveName, fileName)) throw std::invalid_argument("File already exists\n");
        // write 'archive/fileName to list.txt
        char buffer[strlen(archiveName) + strlen(fileName) + 2];
        strcpy(buffer, archiveName);
        strcpy(buffer + strlen(archiveName), slash);
        strcpy(buffer + strlen(archiveName) + 1, fileName);
        strcpy(buffer + strlen(archiveName) + 1 + strlen(fileName), eol);
        size_t n = fwrite(buffer, 1, strlen(buffer), listFp);
        if (n != strlen(buffer)) throw std::range_error( "Error");
}

void delList(FILE *listFp, char* archiveName, char* fileName, long length)
{
        fseek(listFp, 0, SEEK_SET);
        char* line = NULL;
        size_t len = 0;
        size_t remainLength = 0;
        size_t targetlength = length - (strlen(archiveName) + strlen(fileName) + 2);
        if (targetlength == 0) // erase the file and return
        {
                remove(errorList);
                listFp = fopen(errorList , "w" );
                return;
        }
        ssize_t read;
        char* buf = new char[targetlength];
        
	//memset(buf, 0, length);
	
	while ((read = getline(&line, &len, listFp)) != -1) 
        {
		
                char temp[read];
                std::strcpy(temp, line);
                char* archiveNameInList = strtok(line, "/");
                char* fileNameInList = strtok (NULL, "\n");
                if (strcmp(archiveName, archiveNameInList) != 0 || strcmp(fileName, fileNameInList) != 0)
                {
                        std::strcpy(buf + remainLength, temp);
                        remainLength += read;
                }
        }
	
        if (truncate(ListFile, remainLength) != 0 || targetlength != remainLength) throw std::out_of_range("File can't access\n");
	fseek(listFp, 0, SEEK_SET);
	if (fwrite(buf, 1, strlen(buf), listFp) != strlen(buf))
        {
                free(buf);
                throw std::out_of_range("File can't access\n");
        }
        free(buf);
}
