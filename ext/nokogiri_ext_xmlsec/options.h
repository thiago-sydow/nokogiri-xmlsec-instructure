#ifndef NOKOGIRI_EXT_XMLSEC_OPTIONS_H
#define NOKOGIRI_EXT_XMLSEC_OPTIONS_H

#include "common.h"

#include <ruby.h>

// Supported algorithms taken from 5.1 of
// http://www.w3.org/TR/xmlenc-core
//
// For options, only use the URL fragment (stuff post #)
// since that's unique enough and it removes a lot of typing.
typedef enum {
  TRIPLEDES_CBC,
  AES128_CBC,
  AES256_CBC,
  AES192_CBC,
} BlockEncryption;

typedef enum {
  RSA1_5,
  RSA_OAEP_MGF1P,
} KeyTransport;

typedef struct {
  // From :block_encryption
  BlockEncryption block_encryption;

  // From :key_transport
  KeyTransport key_transport;

  // From :key_bits
  int key_bits;
} XmlEncOptions;

BOOL GetXmlEncOptions(VALUE rb_opts, XmlEncOptions* options,
                     VALUE* rb_exception_result,
                     const char** exception_message);

#endif  // NOKOGIRI_EXT_XMLSEC_OPTIONS_H
