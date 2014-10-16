#include "options.h"

#include "common.h"

#include <xmlsec/crypto.h>

// Key Transport Strings.
static const char RSA1_5_STRING[] = "rsa-1_5";
static const char RSA_OAEP_MGF1P_STRING[] = "rsa-oaep-mgf1p";

// Block Encryption Strings.
static const char TRIPLEDES_CBC_STRING[] = "tripledes-cbc";
static const char AES128_CBC_STRING[] = "aes128-cbc";
static const char AES256_CBC_STRING[] = "aes256-cbc";
static const char AES192_CBC_STRING[] = "aes192-cbc";

BOOL GetXmlEncOptions(VALUE rb_opts,
                      XmlEncOptions* options,
                      VALUE* rb_exception_result,
                      const char** exception_message) {
  VALUE rb_block_encryption = rb_hash_aref(rb_opts, ID2SYM(rb_intern("block_encryption")));
  VALUE rb_key_transport = rb_hash_aref(rb_opts, ID2SYM(rb_intern("key_transport")));

  if (NIL_P(rb_block_encryption) ||
      TYPE(rb_block_encryption) != T_STRING ||
      NIL_P(rb_key_transport) ||
      TYPE(rb_key_transport) != T_STRING) {
    *rb_exception_result = rb_eArgError;
    *exception_message = "Must supply :block_encryption & :key_transport";
    return FALSE;
  }

  char* blockEncryptionValue = RSTRING_PTR(rb_block_encryption);
  int blockEncryptionLen = RSTRING_LEN(rb_block_encryption);
  char* keyTransportValue = RSTRING_PTR(rb_key_transport);
  int keyTransportLen = RSTRING_LEN(rb_key_transport);

  if (strncmp(AES256_CBC_STRING, blockEncryptionValue, blockEncryptionLen) == 0) {
    options->block_encryption = AES256_CBC;
    options->key_bits = 256;
  } else if (strncmp(AES128_CBC_STRING, blockEncryptionValue, blockEncryptionLen) == 0) {
    options->block_encryption = AES128_CBC;
    options->key_bits = 128;
  } else if (strncmp(AES192_CBC_STRING, blockEncryptionValue, blockEncryptionLen) == 0) {
    options->block_encryption = AES192_CBC;
    options->key_bits = 192;
  } else if (strncmp(TRIPLEDES_CBC_STRING, blockEncryptionValue, blockEncryptionLen) == 0) {
    options->block_encryption = TRIPLEDES_CBC;
    options->key_bits = 192;
  } else {
    *rb_exception_result = rb_eArgError;
    *exception_message = "Unknown :block_encryption value";
    return FALSE;
  }

  if (strncmp(RSA1_5_STRING, keyTransportValue, keyTransportLen) == 0) {
    options->key_transport = RSA1_5;
  } else if (strncmp(RSA_OAEP_MGF1P_STRING, keyTransportValue, keyTransportLen) == 0) {
    options->key_transport = RSA_OAEP_MGF1P;
  } else {
    *rb_exception_result = rb_eArgError;
    *exception_message = "Unknown :key_transport value";
    return FALSE;
  }

  return TRUE;
}
