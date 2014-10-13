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

pkg_config('xmlsec1')
$libs = `xmlsec1-config  --libs`.strip
create_makefile('nokogiri_ext_xmlsec')
