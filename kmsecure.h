#ifndef KMSECURE_H
#define KMSECURE_H

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string.h>
#include <vector>
#include "blowfish.h"

static const char* CRYPT_HEADER_CODE = "?|938ìçd%_KMS_";
static const int CRYPT_HEADER_CODE_SIZE = 16;

class kmsecure {

public:

    typedef enum{
        KMSERROR,
        KMS_NO_ERROR,
        KMS_NO_ERROR_NO_CRYPT,
    }kmsecure_error;

    typedef struct{
        bool hard;
        int soft_perc;
        int soft_point;
    }kmsecure_info;

    typedef struct{
        char code[CRYPT_HEADER_CODE_SIZE];
        char hard;
        char soft_point;
        char soft_perc;
        unsigned int size_buf;
    }kmsecure_header;

    kmsecure();
    kmsecure_error crypt(char** buffer, int size, kmsecure_info &info, int &new_size);
    kmsecure_error decrypt(char** buffer, int size, int &new_size);

    void set_key(const char* key);
    void calc_soft_points(int soft_point, int soft_perc,int len,int* px1,int* px2);


protected:
    char* key;
    Blowfish* blowfish;

    kmsecure_info decrypted_info;
    kmsecure_error decrypt_last_result;

private:
    int get_len8_dim(int size);
};


#endif
