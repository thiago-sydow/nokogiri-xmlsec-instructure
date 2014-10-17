#include "xmlsecrb.h"

#include "options.h"
#include "util.h"

// Appends an xmlsig <dsig:Signature> node to document stored in |self|
// with a signature based on the given bare rsa key and keyname.
//
// Expects a ruby hash for the signing arguments.
// Hash parameters:
//   :key_name - String with name of the rsa key. May be the empty string.
//   :rsa_key - A PEM encoded rsa key for signing.
//   :signature_alg - Algorithm identified by the URL fragment. Supported algorithms
//             taken from http://www.w3.org/TR/xmldsig-core
//   :digest_alg - Algorithm identified by the URL fragment. Supported algorithms
//             taken from http://www.w3.org/TR/xmldsig-core
//   :ref_uri - [optional] The URI attribute for the <Reference> node in the
//             signature.
VALUE sign_with_key(VALUE self, VALUE rb_opts) {
  VALUE rb_exception_result = Qnil;
  const char* exception_message = NULL;

  xmlDocPtr doc = NULL;
  xmlNodePtr signNode = NULL;
  xmlNodePtr refNode = NULL;
  xmlNodePtr keyInfoNode = NULL;
  xmlSecDSigCtxPtr dsigCtx = NULL;
  char *keyName = NULL;
  char *rsaKey = NULL;
  char *refUri = NULL;
  unsigned int rsaKeyLength = 0;

  resetXmlSecError();

  VALUE rb_key_name = rb_hash_aref(rb_opts, ID2SYM(rb_intern("name")));
  VALUE rb_rsa_key = rb_hash_aref(rb_opts, ID2SYM(rb_intern("key")));
  VALUE rb_signature_alg = rb_hash_aref(rb_opts, ID2SYM(rb_intern("signature_alg")));
  VALUE rb_digest_alg = rb_hash_aref(rb_opts, ID2SYM(rb_intern("digest_alg")));
  VALUE rb_uri = rb_hash_aref(rb_opts, ID2SYM(rb_intern("uri")));

  Check_Type(rb_rsa_key,  T_STRING);
  Check_Type(rb_key_name, T_STRING);
  Check_Type(rb_signature_alg, T_STRING);
  Check_Type(rb_digest_alg, T_STRING);

  rsaKey = RSTRING_PTR(rb_rsa_key);
  rsaKeyLength = RSTRING_LEN(rb_rsa_key);
  keyName = StringValueCStr(rb_key_name);

  if (!NIL_P(rb_uri)) {
    Check_Type(rb_uri, T_STRING);
    refUri = StringValueCStr(rb_uri);
  }

  Data_Get_Struct(self, xmlDoc, doc);
  xmlSecTransformId signature_algorithm = GetSignatureMethod(rb_signature_alg,
      &rb_exception_result, &exception_message);
  if (signature_algorithm == xmlSecTransformIdUnknown) {
    // Propagate exception.
    goto done;
  }

  // create signature template for enveloped signature
  signNode = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId,
                                       signature_algorithm, NULL);
  if (signNode == NULL) {
    rb_exception_result = rb_eSigningError;
    exception_message = "failed to create signature template";
    goto done;
  }

  // add <dsig:Signature/> node to the doc
  xmlAddChild(xmlDocGetRootElement(doc), signNode);

  // add reference
  xmlSecTransformId digest_algorithm = GetDigestMethod(rb_digest_alg,
      &rb_exception_result, &exception_message);
  if (digest_algorithm == xmlSecTransformIdUnknown) {
    // Propagate exception.
    goto done;
  }
  refNode = xmlSecTmplSignatureAddReference(signNode, digest_algorithm,
                                            NULL, (const xmlChar *)refUri, NULL);
  if(refNode == NULL) {
    rb_exception_result = rb_eSigningError;
    exception_message = "failed to add reference to signature template";
    goto done;
  }

  // add enveloped transform
  if(xmlSecTmplReferenceAddTransform(refNode, xmlSecTransformEnvelopedId) == NULL) {
    rb_exception_result = rb_eSigningError;
    exception_message = "failed to add enveloped transform to reference";
    goto done;
  }

  if(xmlSecTmplReferenceAddTransform(refNode, xmlSecTransformExclC14NId) == NULL) {
    rb_exception_result = rb_eSigningError;
    exception_message = "failed to add canonicalization transform to reference";
    goto done;
  }

  // add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to put key name in the signed
  // document
  keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
  if(keyInfoNode == NULL) {
    rb_exception_result = rb_eSigningError;
    exception_message = "failed to add key info";
    goto done;
  }
  if(xmlSecTmplKeyInfoAddKeyName(keyInfoNode, NULL) == NULL) {
    rb_exception_result = rb_eSigningError;
    exception_message = "failed to add key name";
    goto done;
  }

  // create signature context, we don't need keys manager in this example
  dsigCtx = createDSigContext(NULL);
  if(dsigCtx == NULL) {
    rb_exception_result = rb_eSigningError;
    exception_message = "failed to create signature context";
    goto done;
  }

  // load private key, assuming that there is no password
  dsigCtx->signKey = xmlSecCryptoAppKeyLoadMemory((xmlSecByte *)rsaKey,
                                                  rsaKeyLength,
                                                  xmlSecKeyDataFormatPem,
                                                  NULL, // password
                                                  NULL,
                                                  NULL);
  if(dsigCtx->signKey == NULL) {
    rb_exception_result = rb_eSigningError;
    exception_message = "failed to load private pem key";
    goto done;
  }

  // set key name
  if(xmlSecKeySetName(dsigCtx->signKey, (xmlSecByte *)keyName) < 0) {
    rb_exception_result = rb_eSigningError;
    exception_message = "failed to set key name";
    goto done;
  }

  // sign the template
  if(xmlSecDSigCtxSign(dsigCtx, signNode) < 0) {
    rb_exception_result = rb_eSigningError;
    exception_message = "signature failed";
    goto done;
  }

done:
  if(dsigCtx != NULL) {
    xmlSecDSigCtxDestroy(dsigCtx);
  }

  if(rb_exception_result != Qnil) {
    if (hasXmlSecLastError()) {
      rb_raise(rb_exception_result, "%s, XmlSec error: %s", exception_message,
               getXmlSecLastError());
    } else {
      rb_raise(rb_exception_result, "%s", exception_message);
    }
  }

  return Qnil;
}
