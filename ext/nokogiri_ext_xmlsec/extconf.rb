require 'mkmf'

def barf message = 'dependencies not met'
  raise message
end

barf unless have_header('ruby.h')

$CFLAGS << " -fvisibility=hidden -fvisibility-inlines-hidden"

if $CFLAGS =~ /\-DXMLSEC_CRYPTO=\\\\\\"openssl\\\\\\"/
  $CFLAGS['-DXMLSEC_CRYPTO=\\\\\\"openssl\\\\\\"'] =
    '-DXMLSEC_CRYPTO=\\"openssl\\"'
end

pkg_config('xmlsec1-openssl')
have_library 'xmlsec1-openssl'
create_makefile('nokogiri_ext_xmlsec')
