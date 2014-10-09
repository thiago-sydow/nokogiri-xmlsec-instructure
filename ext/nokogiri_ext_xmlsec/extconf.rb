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

$CFLAGS += " " << `pkg-config --cflags xmlsec1-openssl`.strip
$CXXFLAGS += " $CFLAGS"
$LDFLAGS += " " << `pkg-config --libs-only-L xmlsec1-openssl`.strip
$libs += " " << `pkg-config --libs-only-l xmlsec1-openssl`.strip

have_library 'xmlsec1-openssl'
create_makefile('nokogiri_ext_xmlsec')
