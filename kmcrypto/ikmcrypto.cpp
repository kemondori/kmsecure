
#include "ikmcrypto.h"

kmcrypto_exception::kmcrypto_exception(std::string what_message) : std::runtime_error(what_message.c_str())
{

}

void ikmcrypto::set_key(const char *key, size_t byte_length)
{
    throw new kmcrypto_exception("Current IKMCrypto instance does not provide a SetKey method");
}


void ikmcrypto::set_key_with_iv(const char *key, size_t byte_length, const char* iv, size_t iv_length)
{
    throw new kmcrypto_exception("Current IKMCrypto instance does not provide a SetKeyWithIV method");
}
