
// Copyright in this code is held by Dr B. R. Gladman but free direct or
// derivative use is permitted subject to acknowledgement of its origin.
// Dr B. R. Gladman <brg@gladman.uk.net> 27th October 2000.
//
// This is an implementation of the AES encryption algorithm (Rijndael)
// designed by Joan Daemen and Vincent Rijmen. This version is designed
// for a fixed block length of 128 bits (Nb = 4) and can run with either 
// big or little endian internal byte order (see aes.h).

// define COMPACT for a slow but compact version

//#define COMPACT

// define UNROLL to unroll the loops in encrypt and decrypt

#define UNROLL
 
// define FIXED_TABLES for ultimate speed but increased memory use - 
// otherwise the tables will be generated in memory on first use

#define FIXED_TABLES

// define LARGE_TABLES for ultimate speed but increased memory use

#define LARGE_TABLES

#include "aes.h"

#if	defined(FIXED_TABLES) || defined(COMPACT)
#  if(INTERNAL_BYTE_ORDER == AES_LITTLE_ENDIAN)
#  include "aes_let.h"	// tables in little endian order
#  else
#  include "aes_bet.h"	// tables in big endian order
#  endif
#endif

namespace
{
// multiply four bytes in GF(2^8) by 'x' in parallel

inline word FFmulX(const word x) 
{ 
    return ((x & 0x7f7f7f7f) << 1) ^ (((x & 0x80808080) >> 7) * 0x1b);
}

// perform column mix operation on four bytes in parallel

inline word mix_col(const word x)
{   word	FFmul02 = FFmulX(x);

    return FFmul02 ^ rot3(x ^ FFmul02) ^ rot2(x) ^ rot1(x);
}

// perform inverse column mix operation on four bytes in parallel

inline word inv_mix_col(const word x)
{   word    FFmul02 = FFmulX(x), 
			FFmul04 = FFmulX(FFmul02), 
            FFmul08 = FFmulX(FFmul04), 
			FFmul09 = x ^ FFmul08;
    
    return FFmul02 ^ FFmul04 ^ FFmul08 ^ rot3(FFmul02 ^ FFmul09) 
                   ^ rot2(FFmul04 ^ FFmul09) ^ rot1(FFmul09);
}

}   // end of anonymous namespace

#if !defined(COMPACT)

#if	!defined(FIXED_TABLES)

namespace
{
static byte  FFpow[256];		// powers of generator (0x03) in GF(2^8) 
static byte  FFlog[256];		// log: map element to power of generator

static byte  s_box[256];        // the S box
static byte  inv_s_box[256];    // the inverse S box
static word  rcon_tab[32];      // table of round constants (can be reduced
								// to a length of 10 for 128-bit blocks)
static word  ft_tab[4][256];
static word  it_tab[4][256];

#ifdef  LARGE_TABLES
    static word  fl_tab[4][256];
    static word  il_tab[4][256];
#endif

static bool tab_gen = false;    // true if tables have been generated   

inline byte FFmul(const byte a, const byte b)
{   byte u = FFlog[a], v = u + FFlog[b];

    return a && b ? FFpow[v + (v < u ? 1 : 0)] : 0;
}

void gen_tabs(void)
{   word  i, t;
    byte  p, q;

    // log and power tables for GF(2**8) finite field with
    // 0x011b as modular polynomial - the simplest prmitive
    // root is 0x03, used here to generate the tables

    for(i = 0,p = 1; i < 256; ++i)
    {
        FFpow[i] = p; 
        FFlog[p] = static_cast<byte>(i);
        p ^=  (p << 1) ^ (p & 0x80 ? 0x01b : 0);
    }

    FFlog[1] = 0;

    for(i = 0,p = 1; i < 32; ++i)
    {
        rcon_tab[i] = bytes2word(0, 0, 0, p);
        p = (p << 1) ^ (p & 0x80 ? 0x01b : 0);
    }

    for(i = 0; i < 256; ++i)
    {
        p = (i ? FFpow[255 - FFlog[i]] : 0);
        q  = ((p >> 7) | (p << 1)) ^ ((p >> 6) | (p << 2));
        p ^= 0x63 ^ q ^ ((q >> 6) | (q << 2));
        s_box[i] = p; 
        inv_s_box[p] = static_cast<byte>(i);
    }

    for(i = 0; i < 256; ++i)
    {
        p = s_box[i];

#ifdef  LARGE_TABLES

        t = p; 
        fl_tab[0][i] = bytes2word(0, 0, 0, p);
        fl_tab[1][i] = bytes2word(0, 0, p, 0);
        fl_tab[2][i] = bytes2word(0, p, 0, 0);
        fl_tab[3][i] = bytes2word(p, 0, 0, 0);
#endif

        t = bytes2word(FFmul(3, p), p, p, FFmul(2, p));
		
        ft_tab[0][i] = t;
        ft_tab[1][i] = rot1(t);
        ft_tab[2][i] = rot2(t);
        ft_tab[3][i] = rot3(t);

        p = inv_s_box[i];

#ifdef  LARGE_TABLES

        t = p; 
        il_tab[0][i] = bytes2word(0, 0, 0, p);
        il_tab[1][i] = bytes2word(0, 0, p, 0);
        il_tab[2][i] = bytes2word(0, p, 0, 0);
        il_tab[3][i] = bytes2word(p, 0, 0, 0);
#endif
        t = bytes2word(FFmul(11, p), FFmul(13, p), FFmul( 9, p), FFmul(14, p));

        it_tab[0][i] = t;
        it_tab[1][i] = rot1(t);
        it_tab[2][i] = rot2(t);
        it_tab[3][i] = rot3(t);
    }

    tab_gen = true;
}
}   // end of anonymous namespace

#endif

#ifdef LARGE_TABLES

#define ls_box(x)       \
 (  fl_tab[0][byte0(x)] \
  ^ fl_tab[1][byte1(x)] \
  ^ fl_tab[2][byte2(x)] \
  ^ fl_tab[3][byte3(x)] )

#define lf_rnd(x, n)                    \
  ( fl_tab[0][byte0(x[n])]              \
  ^ fl_tab[1][byte1(x[(n + 1) & 3])]    \
  ^ fl_tab[2][byte2(x[(n + 2) & 3])]    \
  ^ fl_tab[3][byte3(x[(n + 3) & 3])] )

#define li_rnd(x, n)                    \
  ( il_tab[0][byte0(x[n])]              \
  ^ il_tab[1][byte1(x[(n + 3) & 3])]    \
  ^ il_tab[2][byte2(x[(n + 2) & 3])]    \
  ^ il_tab[3][byte3(x[(n + 1) & 3])] )

#else

#define ls_box(x) bytes2word(			\
	s_box[byte3(x)], s_box[byte2(x)],	\
	s_box[byte1(x)], s_box[byte0(x)])

#define lf_rnd(x, n)	bytes2word(     \
	s_box[byte3(x[(n + 3) & 3])],		\
	s_box[byte2(x[(n + 2) & 3])],		\
	s_box[byte1(x[(n + 1) & 3])],		\
	s_box[byte0(x[n])])

#define li_rnd(x, n)	bytes2word(		\
	inv_s_box[byte3(x[(n + 1) & 3])],	\
	inv_s_box[byte2(x[(n + 2) & 3])],	\
	inv_s_box[byte1(x[(n + 3) & 3])],	\
	inv_s_box[byte0(x[n])])

#endif

// initialise the key schedule from the user supplied key

void aes::key(const byte in_key[], const word key_len, const aes_key f)
{   word  i, t;

#if !defined(FIXED_TABLES)

    if(!tab_gen)

        gen_tabs();
#endif

    mode = f;                       // encryption mode = enc, dec or both

    Nkey = (key_len + 31) / 32;    // Nkey = 4, 6 or 8

    e_key[0] = word_in(in_key     );
    e_key[1] = word_in(in_key +  4);
    e_key[2] = word_in(in_key +  8);
    e_key[3] = word_in(in_key + 12);

    word    *k1 = e_key, *rcp = rcon_tab;

    switch(Nkey)
    {
    case 4: while(k1 < e_key + 40)
            {   t = rot3(k1[3]);
                k1[4] = k1[0] ^ ls_box(t) ^ *rcp++;
                k1[5] = k1[1] ^ k1[4];
                k1[6] = k1[2] ^ k1[5];
                k1[7] = k1[3] ^ k1[6];
                k1 += 4;
            }
            break;

    case 6: e_key[4] = word_in(in_key + 16);
            e_key[5] = word_in(in_key + 20);
            while(k1 < e_key + 48)
            {   t = rot3(k1[5]); 
                k1[ 6] = k1[0] ^ ls_box(t) ^ *rcp++;
                k1[ 7] = k1[1] ^ k1[ 6];
                k1[ 8] = k1[2] ^ k1[ 7];
                k1[ 9] = k1[3] ^ k1[ 8];
                k1[10] = k1[4] ^ k1[ 9];
                k1[11] = k1[5] ^ k1[10];
                k1 += 6;
            }
            break;

    case 8: e_key[4] = word_in(in_key + 16);
            e_key[5] = word_in(in_key + 20);
            e_key[6] = word_in(in_key + 24);
            e_key[7] = word_in(in_key + 28);
            while(k1 < e_key + 56)
            {   t = rot3(k1[7]); 
                k1[ 8] = k1[0] ^ ls_box(t) ^ *rcp++;
                k1[ 9] = k1[1] ^ k1[ 8];
                k1[10] = k1[2] ^ k1[ 9];
                k1[11] = k1[3] ^ k1[10];
                k1[12] = k1[4] ^ ls_box(k1[11]);
                k1[13] = k1[5] ^ k1[12];
                k1[14] = k1[6] ^ k1[13];
                k1[15] = k1[7] ^ k1[14];
                k1 += 8;
            }
            break;
    }

    if(mode != enc)
    {
        d_key[0] = e_key[0]; 
        d_key[1] = e_key[1];
        d_key[2] = e_key[2]; 
        d_key[3] = e_key[3];

        for(i = 4; i < 4 * Nkey + 24; ++i)
        
            d_key[i] = inv_mix_col(e_key[i]);

        d_key[4 * Nkey + 24] = e_key[4 * Nkey + 24];
        d_key[4 * Nkey + 25] = e_key[4 * Nkey + 25];
        d_key[4 * Nkey + 26] = e_key[4 * Nkey + 26];
        d_key[4 * Nkey + 27] = e_key[4 * Nkey + 27];
    }

    return;
}

// encrypt a block of text

#define f_rnd(x, n)                     \
  ( ft_tab[0][byte0(x[n])]              \
  ^ ft_tab[1][byte1(x[(n + 1) & 3])]    \
  ^ ft_tab[2][byte2(x[(n + 2) & 3])]    \
  ^ ft_tab[3][byte3(x[(n + 3) & 3])] )

#define f_round(bo, bi, k)          \
    bo[0] = f_rnd(bi, 0) ^ k[0];    \
    bo[1] = f_rnd(bi, 1) ^ k[1];    \
    bo[2] = f_rnd(bi, 2) ^ k[2];    \
    bo[3] = f_rnd(bi, 3) ^ k[3];    \
    k += 4

void aes::encrypt(const byte in_blk[16], byte out_blk[16])
{   word    b0[4], b1[4], *kp = e_key;

    b0[0] = word_in(in_blk     ) ^ *kp++;
    b0[1] = word_in(in_blk +  4) ^ *kp++;
    b0[2] = word_in(in_blk +  8) ^ *kp++;
    b0[3] = word_in(in_blk + 12) ^ *kp++;

#if	defined(UNROLL)

    if(Nkey > 6)
    {
        f_round(b1, b0, kp); 
        f_round(b0, b1, kp);
    }

    if(Nkey > 4)
    {
        f_round(b1, b0, kp); 
        f_round(b0, b1, kp);
    }

    f_round(b1, b0, kp); 
    f_round(b0, b1, kp);
    f_round(b1, b0, kp); 
    f_round(b0, b1, kp);
    f_round(b1, b0, kp); 
    f_round(b0, b1, kp);
    f_round(b1, b0, kp); 
    f_round(b0, b1, kp);
    f_round(b1, b0, kp); 

#else

	for(word i = 0; i < 2 + (Nkey >> 1); ++i)
	{
	    f_round(b1, b0, kp); 
		f_round(b0, b1, kp);
	}

    f_round(b1, b0, kp); 

#endif

    word_out(out_blk,      lf_rnd(b1, 0) ^ kp[0]); 
    word_out(out_blk +  4, lf_rnd(b1, 1) ^ kp[1]);
    word_out(out_blk +  8, lf_rnd(b1, 2) ^ kp[2]); 
    word_out(out_blk + 12, lf_rnd(b1, 3) ^ kp[3]);
}

// decrypt a block of text

#define i_rnd(x, n)                     \
  ( it_tab[0][byte0(x[n])]              \
  ^ it_tab[1][byte1(x[(n + 3) & 3])]    \
  ^ it_tab[2][byte2(x[(n + 2) & 3])]    \
  ^ it_tab[3][byte3(x[(n + 1) & 3])] )

#define i_round(bo, bi, k)          \
    k -= 4;                         \
    bo[3] = i_rnd(bi, 3) ^ k[3];	\
    bo[2] = i_rnd(bi, 2) ^ k[2];    \
    bo[1] = i_rnd(bi, 1) ^ k[1];    \
    bo[0] = i_rnd(bi, 0) ^ k[0]

void aes::decrypt(const byte in_blk[16], byte out_blk[16])
{   word    b0[4], b1[4], *kp = d_key + 4 * (Nkey + 6);

    b0[3] = word_in(in_blk + 12) ^ kp[3];
    b0[2] = word_in(in_blk +  8) ^ kp[2];
    b0[1] = word_in(in_blk +  4) ^ kp[1];
    b0[0] = word_in(in_blk     ) ^ kp[0];

#if	defined(UNROLL)

    if(Nkey > 6)
    {
        i_round(b1, b0, kp); 
        i_round(b0, b1, kp);
    }

    if(Nkey > 4)
    {
        i_round(b1, b0, kp); 
        i_round(b0, b1, kp);
    }

    i_round(b1, b0, kp); 
    i_round(b0, b1, kp);
    i_round(b1, b0, kp); 
    i_round(b0, b1, kp);
    i_round(b1, b0, kp); 
    i_round(b0, b1, kp);
    i_round(b1, b0, kp); 
    i_round(b0, b1, kp);
    i_round(b1, b0, kp); 

#else

	for(word i = 0; i < 2 + (Nkey >> 1); ++i)
	{
	    i_round(b1, b0, kp); 
		i_round(b0, b1, kp);
	}

    i_round(b1, b0, kp); 

#endif

    kp -= 4;
    word_out(out_blk + 12, li_rnd(b1, 3) ^ kp[3]);
    word_out(out_blk +  8, li_rnd(b1, 2) ^ kp[2]); 
    word_out(out_blk +  4, li_rnd(b1, 1) ^ kp[1]);
    word_out(out_blk,      li_rnd(b1, 0) ^ kp[0]); 
}

#else

#define ls_box(x) bytes2word(			\
	s_box[byte3(x)], s_box[byte2(x)],	\
	s_box[byte1(x)], s_box[byte0(x)])

#define sbx_row(i) bytes2word(			\
	s_box[byte3(b0[(i + 3) & 3])],		\
	s_box[byte2(b0[(i + 2) & 3])],		\
	s_box[byte1(b0[(i + 1) & 3])],		\
	s_box[byte0(b0[i])]) 

#define inv_sbx_row(i)	bytes2word(		\
	inv_s_box[byte3(b0[(i + 1) & 3])],	\
	inv_s_box[byte2(b0[(i + 2) & 3])],	\
	inv_s_box[byte1(b0[(i + 3) & 3])],	\
	inv_s_box[byte0(b0[i])])

void aes::key(const byte in_key[], const word key_len, const aes_key f)
{   word  t;

    mode = f;

    Nkey = (key_len + 31) / 32;

    e_key[0] = word_in(in_key     );
    e_key[1] = word_in(in_key +  4);
    e_key[2] = word_in(in_key +  8);
    e_key[3] = word_in(in_key + 12);

    word    *k1 = e_key, *rcp = rcon_tab;

    switch(Nkey)
    {
    case 4: while(k1 < e_key + 40)
            {   t = rot3(k1[3]);
                k1[4] = k1[0] ^ ls_box(t) ^ *rcp++;
                k1[5] = k1[1] ^ k1[4];
                k1[6] = k1[2] ^ k1[5];
                k1[7] = k1[3] ^ k1[6];
                k1 += 4;
            }
            break;

    case 6: e_key[4] = word_in(in_key + 16);
            e_key[5] = word_in(in_key + 20);
            while(k1 < e_key + 48)
            {   t = rot3(k1[5]); 
                k1[ 6] = k1[0] ^ ls_box(t) ^ *rcp++;
                k1[ 7] = k1[1] ^ k1[ 6];
                k1[ 8] = k1[2] ^ k1[ 7];
                k1[ 9] = k1[3] ^ k1[ 8];
                k1[10] = k1[4] ^ k1[ 9];
                k1[11] = k1[5] ^ k1[10];
                k1 += 6;
            }
            break;

    case 8: e_key[4] = word_in(in_key + 16);
            e_key[5] = word_in(in_key + 20);
            e_key[6] = word_in(in_key + 24);
            e_key[7] = word_in(in_key + 28);
            while(k1 < e_key + 56)
            {   t = rot3(k1[7]); 
                k1[ 8] = k1[0] ^ ls_box(t) ^ *rcp++;
                k1[ 9] = k1[1] ^ k1[ 8];
                k1[10] = k1[2] ^ k1[ 9];
                k1[11] = k1[3] ^ k1[10];
                k1[12] = k1[4] ^ ls_box(k1[11]);
                k1[13] = k1[5] ^ k1[12];
                k1[14] = k1[6] ^ k1[13];
                k1[15] = k1[7] ^ k1[14];
                k1 += 8;
            }
            break;
    }

    return;
}

void aes::encrypt(const byte in_blk[16], byte out_blk[16])
{   word    b0[4], b1[4], *kp = e_key;

    b0[0] = word_in(in_blk     ) ^ *kp++;
    b0[1] = word_in(in_blk +  4) ^ *kp++;
    b0[2] = word_in(in_blk +  8) ^ *kp++;
    b0[3] = word_in(in_blk + 12) ^ *kp++;

    word t = (Nkey == 4u ? 9u : (Nkey == 6u ? 11u : 13u));
    
    for(word r = 0; r < t; ++r)
    {
        b1[0] = sbx_row(0); 
        b1[1] = sbx_row(1); 
        b1[2] = sbx_row(2); 
        b1[3] = sbx_row(3); 

        b0[0] = mix_col(b1[0]) ^ *kp++; 
        b0[1] = mix_col(b1[1]) ^ *kp++; 
        b0[2] = mix_col(b1[2]) ^ *kp++; 
        b0[3] = mix_col(b1[3]) ^ *kp++;
    }

    word_out(out_blk,      sbx_row(0) ^ *kp++); 
    word_out(out_blk +  4, sbx_row(1) ^ *kp++);
    word_out(out_blk +  8, sbx_row(2) ^ *kp++); 
    word_out(out_blk + 12, sbx_row(3) ^ *kp++);
}

// decrypt a block of text

void aes::decrypt(const byte in_blk[16], byte out_blk[16])
{   word    b0[4], b1[4], *kp = e_key + 4 * (Nkey + 7);

    b0[3] = word_in(in_blk + 12) ^ *--kp;
    b0[2] = word_in(in_blk +  8) ^ *--kp;
    b0[1] = word_in(in_blk +  4) ^ *--kp;
    b0[0] = word_in(in_blk     ) ^ *--kp;

    word t = (Nkey == 4u ? 9u : (Nkey == 6u ? 11u : 13u));
    
    for(word r = 0; r < t; ++r)
    {
        b1[3] = inv_sbx_row(3); 
        b1[2] = inv_sbx_row(2); 
        b1[1] = inv_sbx_row(1); 
        b1[0] = inv_sbx_row(0); 

        b0[3] = inv_mix_col(b1[3] ^ *--kp); 
        b0[2] = inv_mix_col(b1[2] ^ *--kp); 
        b0[1] = inv_mix_col(b1[1] ^ *--kp); 
        b0[0] = inv_mix_col(b1[0] ^ *--kp);     
    }

    word_out(out_blk + 12, inv_sbx_row(3) ^ *--kp); 
    word_out(out_blk +  8, inv_sbx_row(2) ^ *--kp); 
    word_out(out_blk +  4, inv_sbx_row(1) ^ *--kp); 
    word_out(out_blk,      inv_sbx_row(0) ^ *--kp); 
}

#endif