rawaes 1.1 for BeOS x86
©2001 Matthew Alan Badger

rawaes encrypts a file using the Advandced Encryption Standard (AES).  AES uses the Rijndael Algorithm, a 128-bit block cipher, to encrypt.  Since the encryption requires 16-byte blocks, rawaes will pad any uneven blocks with 0s, possibly increasing the size of the file upto 15 bytes.

Terms of Use:
This program may be freely used and distributed.  The author assumes no liability for loss of data or damage caused by the use of this program.  rawaes uses code written by Dr. B. R. Gladman.

To Install From Tracker:
Drag "rawaes" to the folder "Drag 'rawaes' Here"

To Install From Terminal
-Set current working directory to location of rawaes
-Type:  cp rawaes ~/config/bin/

New In This Version
-Can now specify key size of 128, 192, or 256 bits.  Larger keys take longer to encrypt but may increase security.