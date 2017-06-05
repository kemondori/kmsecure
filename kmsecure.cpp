/*
 * KMSECURE
 * The MIT License (MIT)
 * Copyright (c) 2015 Matteo Fumagalli
*/

#include "kmsecure.h"

using namespace std;

kmsecure::kmsecure()
{
    kmcrypto = NULL;
}

int kmsecure::get_len_padded_dim(int size)
{
    int len8;
    uint16_t minblk = kmcrypto->get_minimum_block_size();

    int padding_length = size % minblk;
    if (padding_length == 0) {
      padding_length = minblk;
    } else {
      padding_length = minblk - padding_length;
    }
    len8 = size + padding_length;
    return len8;
}

kmsecure::kmsecure_error kmsecure::crypt(char** buffer, int &size, kmsecure::kmsecure_info &info)
{
    kmsecure_header ash;
    int hoff = sizeof(kmsecure_header);
    int len8;
    char* buffer_dest;
    int oldsize;
    int px1,px2,tmpsize,tmpsize8;

    if(kmcrypto == NULL)
    {
        printf("\nMUST INITIALIZE KMSECURE WITH KMCRYPTO\n");
        return KMSERROR;
    }
    memcpy(&ash.code,CRYPT_HEADER_CODE,CRYPT_HEADER_CODE_SIZE);
    ash.hard = info.hard;
    ash.soft_point = info.soft_point;
    ash.soft_perc = info.soft_perc;
    ash.size_buf = size;
    ash.version = KMS_VERSION;

    len8 = get_len_padded_dim(size);
    if(!info.hard)
    {
        calc_soft_points(info.soft_point,info.soft_perc,size,&px1,&px2);
        tmpsize = px2 - px1;
        if(tmpsize > 0)
        {
            tmpsize8 = get_len_padded_dim(tmpsize);
            oldsize = size;
            size = hoff + size + (tmpsize8 - tmpsize);
            buffer_dest = new char[size];
            memcpy(buffer_dest,&ash,hoff);
            std::vector<char> buffer_crypted((*buffer + px1),(*buffer + px1) + tmpsize8);
            buffer_crypted = kmcrypto->encrypt(buffer_crypted);
            char* c_buffer = reinterpret_cast<char*>(buffer_crypted.data());
            memcpy((buffer_dest + hoff + px1),c_buffer,buffer_crypted.size());
            memcpy(buffer_dest + hoff,*buffer,px1);
            memcpy((buffer_dest + hoff + px1) + buffer_crypted.size() ,*buffer + px2,oldsize - px2);
        }
        else
        {
            info.hard = 1;
            ash.hard = info.hard;
        }


    }

    if(info.hard)
    {
        buffer_dest = new char[hoff + len8];
        memcpy(buffer_dest,&ash,hoff);
        std::vector<char> buffer_crypted(*buffer,*buffer + size);
        for(int i=0; i < (len8 - size); i++)
            buffer_crypted.push_back(0);
        buffer_crypted = kmcrypto->encrypt(buffer_crypted);
        char* c_buffer = reinterpret_cast<char*>(buffer_crypted.data());
        memcpy(buffer_dest + hoff,c_buffer,buffer_crypted.size());
        size = len8 + hoff;
    }

    delete[] *buffer;
    *buffer = buffer_dest;

    return KMS_NO_ERROR;
}

kmsecure::kmsecure_error kmsecure::decrypt(char** buffer, int &size)
{
    bool cryptato = false;
    int len8;
    char* buffer_dest;
    int px1,px2,tmpsize,tmpsize8;
    unsigned int total_file_size;
    int hoff = sizeof(kmsecure_header);
    kmsecure_header ash;

    total_file_size = size;

    if(total_file_size > sizeof(kmsecure_header))
    {
         memcpy((char*)&ash,*buffer,sizeof(kmsecure_header));
         cryptato = true;
         for(int k=0;k<CRYPT_HEADER_CODE_SIZE;k++)
            if(ash.code[k] != CRYPT_HEADER_CODE[k])
             cryptato = false;
    }
    else
        cryptato = false;

    if(cryptato == false)
    {
        decrypt_last_error = KMS_NO_ERROR_NO_CRYPT;
        return KMS_NO_ERROR_NO_CRYPT;
    }

    if(kmcrypto == NULL)
    {
        printf("\nMUST INITIALIZE KMSECURE WITH KMCRYPTO\n");
        decrypt_last_error = KMSERROR;
        return KMSERROR;
    }

    decrypt_last_info.hard = ash.hard;
    decrypt_last_info.soft_perc = ash.soft_perc;
    decrypt_last_info.soft_point = ash.soft_point;

    buffer_dest = new char[ash.size_buf];
    memset(buffer_dest,0,ash.size_buf);

    if(!ash.hard)
    {
        calc_soft_points(ash.soft_point,ash.soft_perc,ash.size_buf,&px1,&px2);
        tmpsize = px2 - px1;
        size = ash.size_buf;
        if(tmpsize > 0)
        {
            tmpsize8 = get_len_padded_dim(tmpsize);
            std::vector<char> buffer_crypt((*buffer + hoff + px1),(*buffer + hoff + px1) + tmpsize8);
            buffer_crypt = kmcrypto->decrypt(buffer_crypt);
            char* c_buffer = reinterpret_cast<char*>(buffer_crypt.data());
            memcpy(buffer_dest,*buffer + hoff,px1);
            memcpy(buffer_dest + px2,*buffer + hoff + px1 + tmpsize8,ash.size_buf - px2);
            memcpy(buffer_dest + px1,c_buffer,buffer_crypt.size());
        }
        else
        {
            decrypt_last_error = KMS_NO_ERROR;
            return KMS_NO_ERROR;
        }


    }
    else
    {
        len8 = get_len_padded_dim(ash.size_buf);
        std::vector<char> buffer_crypt(*buffer + hoff,*buffer + hoff + len8);
        buffer_crypt = kmcrypto->decrypt(buffer_crypt);
        buffer_crypt.resize(ash.size_buf);
        char* c_buffer = reinterpret_cast<char*>(buffer_crypt.data());
        memcpy(buffer_dest,c_buffer,buffer_crypt.size());
        size = ash.size_buf;
    }

    delete[] *buffer;
    *buffer = buffer_dest;


    decrypt_last_error = KMS_NO_ERROR;
    return KMS_NO_ERROR;
}

void kmsecure::set_crypto(ikmcrypto* kmcrypto)
{
    this->kmcrypto = kmcrypto;
}

void kmsecure::calc_soft_points(int soft_point, int soft_perc, int len, int *px1, int *px2)
{
    int perc_size = (int)(((float)soft_perc/100) * len);
    int _point = (int)(((float)soft_point/100) * len);
    int off = 0;

    *px1 = _point - perc_size/2;

    off = 0;
    while(*px1 < 0)
    {
        *px1 = *px1 + 1;
        off++;
    }

    *px2 = *px1 + ((_point + perc_size) - *px1);

    off = 0;
    while(*px2 > len)
    {
        *px2 = *px2 - 1;
        off++;
    }

    *px1-=off;

    if(*px1 < 0)
    {
        printf("file too small to handle this soft crypt");
        exit(-99);
    }
}

kmsecure::kmsecure_info kmsecure::get_last_decrypted_info()
{
    return decrypt_last_info;
}

kmsecure::kmsecure_error kmsecure::get_last_decrypted_error()
{
    return decrypt_last_error;
}

