/********************************************************|
|  rawaes 1.1 for BeOS (Matthew Badger, (c) 2000)        |
|  Encrypts files using the Advanced Encryption Standard |
|--------------------------------------------------------|
|  Makes use of code written by Dr. B. R. Gladman; this  |
|  code can be found in the sub directory "aes".         |
|--------------------------------------------------------|
|  This program may be freely compiled and distributed,  |
|  if and only if the program's source is also           |
|  distributed. The author assumes no responsibility     |
|  for damaged caused due to the use of this program.    |
|--------------------------------------------------------|
| rawaes.h                                 (file 2 of 2) |
|********************************************************/

#if !defined(rawaes_h)
#define rawaes_h

#include <cstdlib>
#include <cstring>
#include <iostream>
using namespace std;

#include "aes.h"
#include <be/storage/File.h>
#include <be/support/SupportDefs.h>

#define rawaes_menu \
"Encrypts a file using Advanced Encryption Standard\n\
AES uses Rijndael, a 128-bit block cipher, to encrypt\n\n\
Usage: rawaes [-e|-d] key input_file output_file\n\n\
key: bits used to encrypt file; up 128 bits (16 characters)\n\
input_file: path of the input data\n\
output_file: path to place output data\n\n\
options:\n\
  -e, -e16, -e128     encrypt the input file, 128-bit key\n\
      -e24, -e192                           , 192-bit key\n\
      -e32, -e256                           , 256-bit key\n\n\
  -d, -d16, -d128     decrypt the input file, 128-bit key\n\
      -d24, -d192                           , 192-bit key\n\
      -d32, -d256                           , 256-bit key\n\n\
      --help          displays this text and exits\n\
      --version       displays version and exits\n"
      
#if defined(__INTEL__)
#define rawaes_version \
"rawaes 1.1 for BeOS x86 (Matthew Alan Badger, (c) 2001)\n\n\
This program may be freely used and distributed.\n\
The author assumes no liability for loss of data\n\
or damage caused by the use of this program.\n\
rawaes uses encryption code written by Dr. B. R. Gladman\n"
#else
#define rawaes_version \
"rawaes 1.1 for BeOS ppc (Matthew Alan Badger, (c) 2001)\n\n\
This program may be freely used and distributed.\n\
The author assumes no liability for loss of data\n\
or damage caused by the use of this program.\n\
rawaes uses encryption code written by Dr. B. R. Gladman\n"
#endif

#endif
