#include <stdio.h>
#include <string.h>
#define MCLBN_FP_UNIT_SIZE 8
#define MCLBN_FR_UNIT_SIZE 8
#include <mcl/bn.h>
#include "PDPKS.h"
#include <stdbool.h>
#include "cpucycles.h"
#include "speed.h"
#define round 100

template<class T, class Serializer, class Deserializer>
void serializeTest(const T& x, const Serializer& serialize, const Deserializer& deserialize)
{
	char buf[700];
        int n;
	n = serialize(buf, sizeof(buf), &x);
        printf(" : %d\n", n);
	T y;
	deserialize(&y, buf, n);
}

int main()
{
	mclBnG1 P; 
        mclBnG2 Q; 
        mclBnGT g;
        
        //Test Correctness
        printf("Test for correctness :\n\n");
        printf("Byte size of different elements in PDPKS after serializing:\n\n");

	// Setup;
	Setup(&Q, &P, &g);

        printf("Q    ");
        serializeTest(Q, mclBnG2_serialize, mclBnG2_deserialize);
        printf("P    ");
        serializeTest(P, mclBnG1_serialize, mclBnG1_deserialize);
        printf("g    ");
        serializeTest(g, mclBnGT_serialize, mclBnGT_deserialize);

	// Key Generation;
	mclBnFr a, b;
	mclBnG2 Qpub1, Qpub2;
	MasterKeyGen(&a, &b, &Q, &Qpub1, &Qpub2);

        printf("a    ");
        serializeTest(a, mclBnFr_serialize, mclBnFr_deserialize);
        printf("b    ");
        serializeTest(b, mclBnFr_serialize, mclBnFr_deserialize);
        printf("Qpub1");
        serializeTest(Qpub1, mclBnG2_serialize, mclBnG2_deserialize);
        printf("Qpub2");
        serializeTest(Qpub2, mclBnG2_serialize, mclBnG2_deserialize);

	//Generate Derived Key & Check;
	mclBnFr r;
	mclBnG2 Qr, Qvk;
	VrfyKeyDerive(&r, &Q, &Qpub1, &Qpub2, &Qr, &Qvk);

        printf("r    ");
        serializeTest(r, mclBnFr_serialize, mclBnFr_deserialize);
        printf("Qr   ");
        serializeTest(Qr, mclBnG2_serialize, mclBnG2_deserialize);
        printf("Qvk  ");
        serializeTest(Qvk, mclBnG2_serialize, mclBnG2_deserialize);
	
	if (!VrfyKeyCheck(&Q, &Qr, &Qvk, &Qpub2, &a)) { printf("Derived Verification Key invalid!\n\n"); return 0;}					

	// Sign Key Drv;
	mclBnG1 Psk;
	SignKeyDrv(&Q, &P, &Qr, &Qvk, &Qpub2, &a, &b, &Psk);

        printf("Psk  ");
        serializeTest(Psk, mclBnG1_serialize, mclBnG1_deserialize);

	// Sign;
	mclBnG1 sig;
	mclBnFr h;
	mclBnFr x;
	char m[] = "hello PDPKS"; 
	Sign(m, sizeof(m), &x, &Psk, &P, &Q, &sig, &h);

        printf("h    ");
        serializeTest(h, mclBnFr_serialize, mclBnFr_deserialize);
        printf("x    ");
        serializeTest(x, mclBnFr_serialize, mclBnFr_deserialize);
        printf("Psk  ");
        serializeTest(Psk, mclBnG1_serialize, mclBnG1_deserialize);

	// Verify;
        if (Verify(m, sizeof(m), &sig, &h, &Qvk, &P, &Q)) {printf("\nsignature valid!\n\n");}
        else {printf("\nsignature invalid!\n\n");}

        //Test Time Cost;
        printf("\n\nTest for time cost:\n\n");
        timing_overhead = cpucycles_overhead();
        unsigned long long tRandomGen[round], tSetup[round], tMasterKeyGen[round], tVrfyKeyDerive[round], tVrfyKeyCheck[round], tSignKeyDrv[round], tSign[round], tVerify[round];
        int round_i = 0;
        int check = 0;
        while(round_i < round)
        {
//                printf("%d\n", round_i);
                tRandomGen[round_i] = cpucycles_start();
                RandZpGen(&a);
                tRandomGen[round_i] = cpucycles_stop() - tRandomGen[round_i] - timing_overhead;

                tSetup[round_i] = cpucycles_start();
                Setup(&Q, &P, &g);
                tSetup[round_i] = cpucycles_stop() - tSetup[round_i] - timing_overhead;

                tMasterKeyGen[round_i] = cpucycles_start();
                MasterKeyGen(&a, &b, &Q, &Qpub1, &Qpub2);
                tMasterKeyGen[round_i] = cpucycles_stop() - tMasterKeyGen[round_i] - timing_overhead;

                tVrfyKeyDerive[round_i] = cpucycles_start();
                VrfyKeyDerive(&r, &Q, &Qpub1, &Qpub2, &Qr, &Qvk);
                tVrfyKeyDerive[round_i] = cpucycles_stop() - tVrfyKeyDerive[round_i] - timing_overhead;

                tVrfyKeyCheck[round_i] = cpucycles_start();
                check = VrfyKeyCheck(&Q, &Qr, &Qvk, &Qpub2, &a);
                tVrfyKeyCheck[round_i] = cpucycles_stop() - tVrfyKeyCheck[round_i] - timing_overhead;
                if (check == 0) {printf("Derived Verification Key invalid!\n\n"); return 0;}
              
                tSignKeyDrv[round_i] = cpucycles_start();
                SignKeyDrv(&Q, &P, &Qr, &Qvk, &Qpub2, &a, &b, &Psk);
                tSignKeyDrv[round_i] = cpucycles_stop() - tSignKeyDrv[round_i] - timing_overhead;

                tSign[round_i] = cpucycles_start();
	        Sign(m, sizeof(m), &x, &Psk, &P, &Q, &sig, &h);
                tSign[round_i] = cpucycles_stop() - tSign[round_i] - timing_overhead;

                tVerify[round_i] = cpucycles_start();
                check = Verify(m, sizeof(m), &sig, &h, &Qvk, &P, &Q);
                tVerify[round_i] = cpucycles_stop() - tVerify[round_i] - timing_overhead;
                if (check == 0) {printf("signature invalid!\n\n"); return 0;}

                round_i = round_i + 1;
        }
        print_results("RandomGen:", tRandomGen, round);
        print_results("Setup:", tSetup, round);
        print_results("MasterKeyGen:", tMasterKeyGen, round);
        print_results("VrfyKeyDerive:", tVrfyKeyDerive, round);
        print_results("VrfyKeyCheck:", tVrfyKeyCheck, round);
        print_results("SignKeyDrv:", tSignKeyDrv, round);
        print_results("Sign:", tSign, round);
        print_results("Verify:", tVerify, round);
}
	
