#include "kmsecure.h"

using namespace std;

kmsecure::kmsecure()
{
    key = NULL;
    blowfish = NULL;
}

int kmsecure::get_len8_dim(int size)
{
    int len8;
    int padding_length = size % sizeof(uint64_t);
    if (padding_length == 0) {  //don't know why blowfish do this even if 0, just getting along...
      padding_length = sizeof(uint64_t);
    } else {
      padding_length = sizeof(uint64_t) - padding_length;
    }
    len8 = size + padding_length;
    return len8;
}

kmsecure::kmsecure_error kmsecure::crypt(char** buffer, int size, kmsecure::kmsecure_info &info, int &new_size)
{
    kmsecure_header ash;
    int hoff = sizeof(kmsecure_header);
    int len8;
    char* buffer_dest;
    int px1,px2,tmpsize,tmpsize8;

    if(key == NULL)
    {
        printf("\nMUST INITIALIZE KMSECURE WITH SETKEY\n");
        return KMSERROR;
    }
    memcpy(&ash.code,CRYPT_HEADER_CODE,CRYPT_HEADER_CODE_SIZE);
    ash.hard = info.hard;
    ash.soft_point = info.soft_point;
    ash.soft_perc = info.soft_perc;
    ash.size_buf = size;

    len8 = get_len8_dim(size);
    if(!info.hard)
    {
        calc_soft_points(info.soft_point,info.soft_perc,size,&px1,&px2);
        tmpsize = px2 - px1;
        if(tmpsize > 0)
        {
            tmpsize8 = get_len8_dim(tmpsize);
            new_size = hoff + size + (tmpsize8 - tmpsize);
            buffer_dest = new char[new_size];
            memcpy(buffer_dest,&ash,hoff);
            std::vector<char> buffer_crypted((*buffer + px1),(*buffer + px1) + tmpsize);
            buffer_crypted = blowfish->Encrypt(buffer_crypted);
            char* c_buffer = reinterpret_cast<char*>(buffer_crypted.data());
            memcpy((buffer_dest + hoff + px1),c_buffer,buffer_crypted.size());
            memcpy(buffer_dest + hoff,*buffer,px1);
            memcpy((buffer_dest + hoff + px1) + buffer_crypted.size() ,*buffer + px2,size - px2);
        }
        else
        {
            new_size = size;
            return KMS_NO_ERROR_NO_CRYPT;
        }


    }
    else
    {
        buffer_dest = new char[hoff + len8];
        memcpy(buffer_dest,&ash,hoff);
        std::vector<char> buffer_crypted(*buffer,*buffer + size);
        buffer_crypted = blowfish->Encrypt(buffer_crypted);
        char* c_buffer = reinterpret_cast<char*>(buffer_crypted.data());
        memcpy(buffer_dest + hoff,c_buffer,buffer_crypted.size());
        new_size = len8 + hoff;
    }

    delete *buffer;
    *buffer = buffer_dest;

    return KMS_NO_ERROR;
}

kmsecure::kmsecure_error kmsecure::decrypt(char** buffer, int size, int &new_size)
{
    bool cryptato = false;
    int len8;
    char* buffer_dest;
    int px1,px2,tmpsize,tmpsize8;
    unsigned int total_file_size;
    int hoff = sizeof(kmsecure_header);
    kmsecure_header ash;

    if(key == NULL)
    {
        printf("\nMUST INITIALIZE KMSECURE WITH SETKEY\n");
        return KMSERROR;
    }

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
        return KMS_NO_ERROR_NO_CRYPT;

    buffer_dest = new char[ash.size_buf];
    memset(buffer_dest,0,ash.size_buf);

    if(!ash.hard)
    {
        calc_soft_points(ash.soft_point,ash.soft_perc,ash.size_buf,&px1,&px2);
        tmpsize = px2 - px1;
        new_size = ash.size_buf;
        if(tmpsize > 0)
        {
            tmpsize8 = get_len8_dim(tmpsize);
            std::vector<char> buffer_crypt((*buffer + hoff + px1),(*buffer + hoff + px1) + tmpsize8);
            buffer_crypt = blowfish->Decrypt(buffer_crypt);
            char* c_buffer = reinterpret_cast<char*>(buffer_crypt.data());
            memcpy(buffer_dest,*buffer + hoff,px1);
            memcpy(buffer_dest + px2,*buffer + hoff + px1 + tmpsize8,ash.size_buf - px2);
            memcpy(buffer_dest + px1,c_buffer,buffer_crypt.size());
        }
        else
        {
            return KMS_NO_ERROR;
        }


    }
    else
    {
        len8 = get_len8_dim(ash.size_buf);
        std::vector<char> buffer_crypt(*buffer + hoff,*buffer + hoff + len8);
        buffer_crypt = blowfish->Decrypt(buffer_crypt);
        char* c_buffer = reinterpret_cast<char*>(buffer_crypt.data());
        memcpy(buffer_dest,c_buffer,buffer_crypt.size());
        new_size = ash.size_buf;
    }

    delete *buffer;
    *buffer = buffer_dest;



    return KMS_NO_ERROR;
}

void kmsecure::set_key(const char *key)
{
    this->key = (char*)key;
    if(blowfish != NULL)
        delete blowfish;
    std::vector<char> v_key(key,key + (strlen(key) + 1));
    blowfish = new Blowfish(v_key);
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

