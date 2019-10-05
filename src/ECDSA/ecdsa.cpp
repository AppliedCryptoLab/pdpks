#include <mcl/ecdsa.h>
#include <cybozu/test.hpp>
#include <string.h>
#include "cpucycles.h"
#include "speed.h"
#define round 100
unsigned long long timing_overhead;

template<class T, class Serializer, class Deserializer>
void serializeTest(const T& x, const Serializer& serialize, const Deserializer& deserialize)
{
	char buf[128];
	size_t n = serialize(buf, sizeof(buf), &x);
        printf("byte size after serialize in ECDSA in mcl:%ld\n\n", n);
	CYBOZU_TEST_ASSERT(n > 0);
	T y;
	size_t m = deserialize(&y, buf, n);
	CYBOZU_TEST_EQUAL(m, n);
	CYBOZU_TEST_ASSERT(memcmp(&x, &y, n) == 0);
}

CYBOZU_TEST_AUTO(ecdsa)
{
        unsigned long long tsign[round], tverify[round];
	int ret, i;
        timing_overhead = cpucycles_overhead();
	ret = ecdsaInit();
	CYBOZU_TEST_EQUAL(ret, 0);
	ecdsaSecretKey sec;
	ecdsaPublicKey pub;
	ecdsaPrecomputedPublicKey *ppub;
	ecdsaSignature sig;
	const char *msg = "hello";
	mclSize msgSize = strlen(msg);


	ret = ecdsaSecretKeySetByCSPRNG(&sec);
        printf("size of sec:\n\n");
        printf("\nbyte size before serialize in ECDSA in mcl:%ld\n", sizeof(sec));
	CYBOZU_TEST_EQUAL(ret, 0);
	serializeTest(sec, ecdsaSecretKeySerialize, ecdsaSecretKeyDeserialize);

	ecdsaGetPublicKey(&pub, &sec);
        printf("size of pub:\n\n");
        printf("\nbyte size before serialize in ECDSA in mcl:%ld\n", sizeof(pub));
	serializeTest(pub, ecdsaPublicKeySerialize, ecdsaPublicKeyDeserialize);
        for (i = 0; i < round; ++i)
        {
        tsign[i] = cpucycles_start();
	ecdsaSign(&sig, &sec, msg, msgSize);
        tsign[i] = cpucycles_stop() - tsign[i] - timing_overhead;
        }
        printf("size of sig:\n\n");
        printf("\nbyte size before serialize in ECDSA in mcl:%ld\n", sizeof(sig));
	serializeTest(sig, ecdsaSignatureSerialize, ecdsaSignatureDeserialize);

        for (i = 0; i < round; ++i)
        {
        tverify[i] = cpucycles_start();
	CYBOZU_TEST_ASSERT(ecdsaVerify(&sig, &pub, msg, msgSize));
        tverify[i] = cpucycles_stop() - tverify[i] - timing_overhead;
        }

	ppub = ecdsaPrecomputedPublicKeyCreate();
	CYBOZU_TEST_ASSERT(ppub);
	ret = ecdsaPrecomputedPublicKeyInit(ppub, &pub);
	CYBOZU_TEST_EQUAL(ret, 0);

	CYBOZU_TEST_ASSERT(ecdsaVerifyPrecomputed(&sig, ppub, msg, msgSize));

	sig.d[0]++;
	CYBOZU_TEST_ASSERT(!ecdsaVerify(&sig, &pub, msg, msgSize));
	CYBOZU_TEST_ASSERT(!ecdsaVerifyPrecomputed(&sig, ppub, msg, msgSize));

	ecdsaPrecomputedPublicKeyDestroy(ppub);
        print_results("Sign:", tsign, round);
        print_results("Verify:", tverify, round);
}
