Fast HTTP Vulnerability Scanner V1.1:
--------------------------------

Folders:
- HTTPCore: Multithreading HTTP/1.1 Library. Supports gzip,ssl,ntlm/digest/basic auth.
- Documentation: Doxygen HTML documentation for the HTTPCore.
- Fhscan: Fhscan source code + libraries `+ binary
- Includes: Some include files needed to build Fscan under win32
- Examples: Some simple examples of how HTTPCore Api works.


Compile:

a) There is a Visual studio project included (Fscan folder) that should work for building, if needed, windows binaries.


b) Fscan have been tested under Linux g++ v4.1..2 under Debian 4.1.1-21:
To compile it just type:

g++  -DLINUX  -D_OPENSSL_SUPPORT_ -D_ZLIB_SUPPORT_ -D_MULTITHREADING_ -c -fPIC HTTPCore/*.cpp HTTPCore/Authentication/*.cpp HTTPCore/Modules/*.cpp
g++ -shared -o HTTPCore.so -fPIC HTTPCore/*.o
g++  -lpthread -lssl -DLINUX  -D_OPENSSL_SUPPORT_ -D_ZLIB_SUPPORT_ -D_MULTITHREADING_ Fscan/*.cpp Fscan/Reporting/*.cpp HTTPCore.so -o Fscan


Dont forget to copy necesary files (.ini files, tmpl.dat and css folder from Fscan/Release directory)