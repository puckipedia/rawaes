
// Copyright in this code is held by Dr B. R. Gladman but free direct or
// derivative use is permitted subject to acknowledgement of its origin.
// Dr B. R. Gladman <brg@gladman.uk.net> 27th October 2000.
//
// This is an implementation of the AES encryption algorithm (Rijndael)
// designed by Joan Daemen and Vincent Rijmen. This version is designed
// for a fixed block length of 128 bits (Nb = 4) and can run with either 
// big or little endian internal byte order.

#define AES_BIG_ENDIAN		1	// do not change
#define	AES_LITTLE_ENDIAN	2	// do not change

// set INTERNAL_BYTE_ORDER to one of the above constants to set the
// internal byte order (the order used within the algorithm code)

#if defined(__INTEL__)
#define	INTERNAL_BYTE_ORDER	AES_LITTLE_ENDIAN
#else
#define INTERNAL_BYTE_ORDER AES_BIG_ENDIAN
#endif

// set EXTERNAL_BYTE_ORDER to one of the above constants to set the byte
// order used at the external interfaces for the input, output and key 
// byte arrays.

#if defined(__INTEL__)
#define	EXTERNAL_BYTE_ORDER	AES_LITTLE_ENDIAN
#else
#define EXTERNAL_BYTE_ORDER AES_BIG_ENDIAN
#endif

typedef unsigned char   byte;	// must be an 8-bit storage unit
typedef unsigned long   word;	// must be a 32-bit storage unit

#if(INTERNAL_BYTE_ORDER == AES_LITTLE_ENDIAN)

// Circular byte rotates of 32-bit words 

inline word rot1(const word x)	{ return (x <<  8) | (x >> 24);	}
inline word rot2(const word x)	{ return (x << 16) | (x >> 16);	}
inline word rot3(const word x)	{ return (x << 24) | (x >>  8);	}

// Extract bytes from a 32-bit words

inline byte byte0(word x)	{ return static_cast<byte>(x);		}
inline byte byte1(word x)   { return static_cast<byte>(x >>  8);}
inline byte byte2(word x)   { return static_cast<byte>(x >> 16);}
inline byte byte3(word x)   { return static_cast<byte>(x >> 24);}

inline word bytes2word(byte b3, byte b2, byte b1, byte b0) 
{	return (word)b3 << 24 | (word)b2 << 16 | (word)b1 << 8 | b0;} 

// Invert byte order in a 32 bit variable

inline word byte_swap(const word x)
{
    return rot1(x) & 0x00ff00ff | rot3(x) & 0xff00ff00;
}

#else

// Circular byte rotates of 32-bit words 

inline word rot3(const word x)	{ return (x <<  8) | (x >> 24);	}
inline word rot2(const word x)	{ return (x << 16) | (x >> 16);	}
inline word rot1(const word x)	{ return (x << 24) | (x >>  8);	}

// Extract bytes from a 32-bit words

inline byte byte3(word x)	{ return static_cast<byte>(x);		}
inline byte byte2(word x)   { return static_cast<byte>(x >>  8);}
inline byte byte1(word x)   { return static_cast<byte>(x >> 16);}
inline byte byte0(word x)   { return static_cast<byte>(x >> 24);}

inline word bytes2word(byte b3, byte b2, byte b1, byte b0) 
{	return (word)b0 << 24 | (word)b1 << 16 | (word)b2 << 8 | b3;} 

// Invert byte order in a 32 bit variable

inline word byte_swap(const word x)
{
    return rot3(x) & 0x00ff00ff | rot1(x) & 0xff00ff00;
}

#endif

#if(INTERNAL_BYTE_ORDER == EXTERNAL_BYTE_ORDER)

inline word word_in(const byte x[])             {   return *(word*)x;   };
inline void word_out(byte x[], const word v)    {   *(word*)x = v;      };

#else

inline word word_in(const byte x[])             {   return byte_swap(*(word*)x);    };
inline void word_out(byte x[], const word v)    {   *(word*)x = byte_swap(v);       };

#endif

class aes
{
public:								// a 'hack' to obtain class constants
	enum aes_const	{	Nrow =  4,	// the number of rows in the cipher state
						Mcol =  8,	// the maximum number of columns in the cipher state
						Mkbl = 15	// the maximum number of key schedule blocks
					};
	
	enum aes_key	{	enc  =  1,	// set if the encryption key schedule is needed 
						dec  =  2,	// set if the decryption key schedule is needed
						both =  3,	// set if both schedules are needed
					};

	aes(word Nb = 4) : Ncol(Nb) {};	// to allow other block lengths later
   ~aes(void)	{};
									// note that key_len is in bits (128, 192, 256)
	void    key(const byte key[], const word key_len, const aes_key f);
    void    encrypt(const byte in_blk[], byte out_blk[]);
    void    decrypt(const byte in_blk[], byte out_blk[]);

private:
	word	Ncol;		// the number of columns in the cipher block (= 4)
    word    Nkey;		// the number of words in the key input block
	word	Nrnd;		// the number of cipher rounds
	word	Sr[Nrow];	// the row shift counts (note that Sr[0] is not used)
    word    e_key[64];	// the encryption key schedule (128 bit block only)
    word    d_key[64];	// the decryption key schedule (128 bit block only)
    aes_key	mode;		// encrypt, decrypt or both
};
