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
| rawaes.cpp                               (file 1 of 2) |
|********************************************************/

#include "rawaes.h"

int main(int argc, char** argv) try {
	// Arguments
	char*	flag;
	char*	keyt;
	char*	path1;  // input file
	char*	path2;  // output file
	
	// Check Arguments For "--help" or "--version"
	if (argc > 1) {
		flag = *(argv + 1);
		
		if (strcmp("--help", flag) == 0) { cout << rawaes_menu; exit(0); }
		if (strcmp("--version", flag) == 0) { cout << rawaes_version; exit(0); }
	}
	else { cout << rawaes_menu; exit(0); }
	
	// Check Argument Count
	if (argc != 5) throw "Must have 4 arguments!";
	
	// AES Class Variable
	bool	dir_enc = true;
	int		key_size = 128;
	aes		crypto;
	
	// Check Direction and Key Size
	if (
		strcmp("-d", flag) == 0 ||
		strcmp("--decrypt", flag) == 0 ||
		strcmp("-d16", flag) == 0 ||
		strcmp("-d128", flag) == 0
	) {	dir_enc = false; }
	else if (
		strcmp("-d24", flag) == 0 ||
		strcmp("-d192", flag) == 0
	) { dir_enc = false; key_size = 192; }
	else if (
		strcmp("-d32", flag) == 0 ||
		strcmp("-d256", flag) == 0
	) { dir_enc = false; key_size = 256; }
	else if (
		strcmp("-e32", flag) == 0 ||
		strcmp("-e256", flag) == 0
	) { key_size = 256; }
	else if (
		strcmp("-e24", flag) == 0 ||
		strcmp("-e192", flag) == 0
	) { key_size = 192; }
	else if (
		strcmp("-e", flag) != 0 &&
		strcmp("--encrypt", flag) != 0 &&
		strcmp("-e16", flag) != 0 &&
		strcmp("-e128", flag) != 0
	) { throw "Must Specify Direction: --encrypt --decrypt"; }
	
	// Initalize Key Set-up
	keyt = *(argv + 2);
	int		keyln = strlen(keyt);
	byte*	keydt = new byte[keyln];
	for (int i = 0; i < keyln; ++i) *(keydt + i) = static_cast<byte>(*(keyt + i)); 
		
	if (dir_enc) crypto.key(keydt, key_size, aes::enc);
	else crypto.key(keydt, key_size, aes::dec);
	
	delete keydt;
	

	// Open Input and Output Files
	path1 = *(argv + 3);
	path2 = *(argv + 4);
	
	BFile*	fin;
	BFile*	fout;
	
	fin = new BFile(path1, B_READ_ONLY);
	if (fin->InitCheck() != B_OK) {
		delete fin;
		throw "Cannot Initialize Input File!";
	}
	
	fout = new BFile(path2, B_WRITE_ONLY|B_CREATE_FILE);
	if (fout->InitCheck() != B_OK) {
		fin->Unset();
		delete fin;
		delete fout;
		throw "Cannot Initialize Output File!";
	}
	
	// Get Input File Dimensions
	off_t* fin_size_temp = new off_t;
	fin->GetSize(fin_size_temp);
	
	uint64 fin_size = static_cast<unsigned>(*fin_size_temp);
	delete fin_size_temp;
	
	// Encrypt or Decrypt Loop
	uint64	fin_offset = 0;
	byte*	fin_buffer;
	byte*	fout_buffer;
	
	fin_buffer = new byte[17];
	fout_buffer = new byte[17];
	
	typedef void (aes::* aes_encrypt_decrypt)(const byte[], byte[]);
	
	aes_encrypt_decrypt aesfunc;
	if (dir_enc) aesfunc = &aes::encrypt;
	else aesfunc = &aes::decrypt;
	
	if (dir_enc) cout << "Encrypting...";
	else cout << "Decrypting...";
	
	while ((fin_size - fin_offset) >= 16) {
		fin->Read(fin_buffer, 16);
		(crypto.*aesfunc)(fin_buffer, fout_buffer);
		fout->Write(fout_buffer, 16);
		
		fin_offset += 16;
	}
	
	int fin_rsize = fin_size - fin_offset;
	if (fin_rsize != 0) {
		for (int i = fin_rsize; i < 16; ++i) *(fin_buffer + i) = 0; 
		
		fin->Read(fin_buffer, fin_rsize);
		(crypto.*aesfunc)(fin_buffer, fout_buffer);
		fout->Write(fout_buffer, 16);
	}
	
	fin->Unset();
	fout->Unset();
	
	delete fout;
	delete fin;
	delete fout_buffer;
	delete fin_buffer;

	// Output Good News
	cout << "Complete!\n";
	
	return 0;
	
} catch (const char* str) {
	cout << rawaes_menu << endl << "ERROR: " << str << endl;
	exit(1);
}
