#include "xmlsecrb.h"
#include "util.h"

// Appends an xmlsig <dsig:Signature> node to document stored in |self|
// with a signature based on the given bare rsa key and keyname.
//
// Expects 2-3 positional arguments:
//   key_name - String with name of the rsa key. May be the empty string.
//   rsa_key - A PEM encoded rsa key for signing.
//   ref_uri - [optional] The URI attribute for the <Reference> node in the
//             signature.
VALUE sign_with_key(int argc, VALUE* argv, VALUE self) {
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

  if (argc < 2 || argc > 3) {
    rb_exception_result = rb_eArgError;
    exception_message = "Expecting 2-3 arguments";
    goto done;
  }

  VALUE rb_key_name = argv[0];
  VALUE rb_rsa_key = argv[1];

  Check_Type(rb_rsa_key,  T_STRING);
  Check_Type(rb_key_name, T_STRING);
  Data_Get_Struct(self, xmlDoc, doc);
  rsaKey = RSTRING_PTR(rb_rsa_key);
  rsaKeyLength = RSTRING_LEN(rb_rsa_key);
  keyName = StringValueCStr(rb_key_name);

  if (argc > 2) {
    VALUE rb_ref_uri = argv[2];
    if (TYPE(rb_ref_uri) != T_NIL) {
      Check_Type(rb_ref_uri, T_STRING);
      refUri = StringValueCStr(rb_ref_uri);
    }
  }

  // create signature template for RSA-SHA1 enveloped signature
  signNode = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId,
                                       xmlSecTransformRsaSha1Id, NULL);
  if (signNode == NULL) {
    rb_exception_result = rb_eSigningError;
    exception_message = "failed to create signature template";
    goto done;
  }

  // add <dsig:Signature/> node to the doc
  xmlAddChild(xmlDocGetRootElement(doc), signNode);

  // add reference
  refNode = xmlSecTmplSignatureAddReference(signNode, xmlSecTransformSha1Id,
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
