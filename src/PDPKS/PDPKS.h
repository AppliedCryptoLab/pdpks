//#define CYBOZU_TEST_DISABLE_AUTO_RUN
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include "cpucycles.h"
#include "speed.h"
unsigned long long timing_overhead;
#define MCLBN_FP_UNIT_SIZE 8
#define MCLBN_FR_UNIT_SIZE 8
#include <mcl/bn.h>
#define HASHBITL_224 224
#define HASHBITL_256 256
#define HASHBITL_384 384
#define HASHBITL_512 512
static void randombytes(unsigned char *x, size_t xlen)
{
  int i;
  int fd = -1;

  if (fd == -1) {
    for (;;) {
      fd = open("/dev/urandom", O_RDONLY);
      if (fd != -1) break;
      sleep(1);
    }
  }

  while (xlen > 0) {
    if (xlen < 1048576) i = xlen; else i = 1048576;

    i = read(fd, x, i);
    if (i < 1) {
      sleep(1);
      continue;
    }

    x += i;
    xlen -= i;
  }
}
//a good hash1
void Hash1(mclBnFr *hash, const mclBnG2 *Q1, const mclBnG2 *Q2)
{
        char s1[4096] = {0};
        mclBnG2_getStr(s1, 2048, Q1, 2);
        mclBnG2_getStr(s1+2048, 2048, Q2, 2);
        mclBnFr_setHashOf(hash, s1, 4096);
}

//a good hash2
void Hash2(mclBnFr *hash, char *m, int mlen, const mclBnGT *P)
{
        int i;
        char s1[4096] = {0};
        mclBnGT_getStr(s1, 2048, P, 2);
        for (i = 0; i < mlen; ++i)
        {
                s1[i + 2048] = m[i];
        }
        mclBnFr_setHashOf(hash, s1, 4096);
}

void Setup(mclBnG2 *Q, mclBnG1 *P, mclBnGT *g)
{
	int ret = mclBn_init(MCL_BN462, MCLBN_COMPILED_TIME_VAR);
	if (ret != 0) {
		printf("err ret=%d\n", ret);
	}
        unsigned char s1[10], s2[10];
        randombytes(s1, 10);
        randombytes(s2, 10);
        mclBnG1_hashAndMapTo(P, s1, 10);
        mclBnG2_hashAndMapTo(Q, s2, 10);
        mclBn_pairing(g, P, Q);
}

void RandZpGen(mclBnFr *a)
{        
        unsigned char tmp[100];
        randombytes(tmp, 100);
        mclBnFr_setHashOf(a, tmp, 100);
}

void MasterKeyGen(mclBnFr *a, mclBnFr *b, const mclBnG2 *Q, mclBnG2 *Qpub1, mclBnG2 *Qpub2)
{
	 RandZpGen(a);
	 RandZpGen(b);
	 mclBnG2_mul(Qpub1, Q, a);
	 mclBnG2_mul(Qpub2, Q, b);
}

void VrfyKeyDerive(mclBnFr *r, const mclBnG2 *Q, const mclBnG2 *Qpub1, const mclBnG2 *Qpub2, mclBnG2 *Qr, mclBnG2 *Qvk)
{
	mclBnG2 Qtmp1, Qtmp2;
	mclBnFr hash;
	RandZpGen(r);
        mclBnG2_mul(Qr, Q, r);
	mclBnG2_mul(&Qtmp1, Qpub1, r); 
	Hash1(&hash, Qr, &Qtmp1); 
	mclBnG2_mul(&Qtmp2, Q, &hash);
	mclBnG2_add(Qvk, &Qtmp2, Qpub2);
}

bool VrfyKeyCheck(const mclBnG2 *Q, const mclBnG2 *Qr, const mclBnG2 *Qvk, const mclBnG2 *Qpub2,const mclBnFr *a)
{
	mclBnG2 Qtmp, Qtmp1, Qtmp2;
	mclBnFr hash;

	mclBnG2_mul(&Qtmp1, Qr, a);
	Hash1(&hash, Qr, &Qtmp1);
	mclBnG2_mul(&Qtmp2, Q, &hash);
	mclBnG2_add(&Qtmp, &Qtmp2, Qpub2);
	
	return mclBnG2_isEqual(Qvk, &Qtmp);

}

void SignKeyDrv(const mclBnG2 *Q, const mclBnG1 *P, const mclBnG2 *Qr, const mclBnG2 *Qvk, const mclBnG2 *Qpub2, const mclBnFr *a, const mclBnFr *b, mclBnG1 *Psk)
{
	mclBnG2 Qa;
	mclBnFr hash1, hash2, reverse;
	if (VrfyKeyCheck(Q, Qr, Qvk, Qpub2, a))
	{
                mclBnG2_mul(&Qa, Qr, a);
		Hash1(&hash1, Qr, &Qa);
                mclBnFr_add(&hash2, &hash1, b);
                mclBnFr_inv(&reverse, &hash2);
		mclBnG1_mul(Psk, P, &reverse);
	}
	else printf("Invalid derived verification key.\n");
}

void Sign(char *m, int mlen, mclBnFr *x, const mclBnG1 *Psk, const mclBnG1 *P,const mclBnG2 *Q, mclBnG1 *Psig, mclBnFr *h)
{
        mclBnFr hash;
	mclBnGT X;
        mclBnG1 xP;
        RandZpGen(x);
        mclBnG1_mul(&xP, P, x);
        mclBn_pairing(&X, &xP, Q);
	Hash2(h, m, mlen, &X);
        mclBnFr_add(&hash, h, x);
	mclBnG1_mul(Psig, Psk, &hash);
}
bool Verify(char *m, int mlen, const mclBnG1 *Psig, const mclBnFr *h, const mclBnG2 *Qvk, const mclBnG1 *P,const mclBnG2 *Q)
{
	mclBnFr hash;
	mclBnGT gt,gt1,gt2,gt3;
        mclBnG1 hP;

        mclBnG1_mul(&hP, P, h);
        mclBn_pairing(&gt, &hP, Q);
	mclBnGT_inv(&gt2, &gt);
	mclBn_pairing(&gt1, Psig, Qvk);
	mclBnGT_mul(&gt3, &gt1, &gt2);
	Hash2(&hash,m, mlen, &gt3);
	
	return mclBnFr_isEqual(&hash, h);			//the compare() function of string.h will return 0 if two strings are the same.
}
