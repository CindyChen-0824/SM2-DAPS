/************************************************************************


File name:  Version:    Date:       Description:


SM2_sv.c
SM2_sv_V1.0
Sep 27,2016
implementation of SM2 signature algorithm and verification algorithm



Function List:
1.SM2_Init
2.Test_Point
3.Test_PubKey
4.Test_Zero
5.Test_n
6.Test_Range
7.SM2_KeyGeneration
8.SM2_Sign
9.SM2_Verify
10.SM2_SelfCheck()
11.SM3_256()



//initiate SM2 curve
//test if the given point is on SM2 curve
//test if the given public key is valid
//test if the big x equals zero
//test if the big x equals n
//test if the big x belong to the range[1,n-1] //generate public key
//SM2 signature algorithm
//SM2 verification
//SM2 slef-check
//this function can be found in SM3.c and SM3.h


Notes:
This SM2 implementation source code can be used for academic, non-profit making or non-commercial use only.
This SM2 implementation is created on MIRACL. SM2 implementation source code provider does not provide MIRACL library, MIRACL license or any permission to use MIRACL library. Any commercial use of MIRACL requires a license which may be obtained from Shamus Software Ltd.            
**************************************************************************/


#include "../inc/SM2.h"
#include "../inc/KDF.h"

unsigned char SM2_p[32] = { 0x85,0x42,0xD6,0x9E, 0x4C,0x04,0x4F,0x18, 0xE8,0xB9,0x24,0x35, 0xBF,0x6F,0xF7,0xDE, 0x45,0x72,0x83,0x91, 0x5C,0x45,0x51,0x7D, 0x72,0x2E,0xDB,0x8B, 0x08,0xF1,0xDF,0xC3 };
unsigned char SM2_a[32] = { 0x78,0x79,0x68,0xB4 ,0xFA,0x32,0xC3,0xFD,0x24,0x17,0x84,0x2E ,0x73,0xBB,0xFE,0xFF ,0x2F,0x3C,0x84,0x8B ,0x68,0x31,0xD7,0xE0,0xEC,0x65,0x22,0x8B ,0x39,0x37,0xE4,0x98};
unsigned char SM2_b[32] = { 0x63,0xE4,0xC6,0xD3 ,0xB2,0x3B,0x0C,0x84 ,0x9C,0xF8,0x42,0x41 ,0x48,0x4B,0xFE,0x48 ,0xF6,0x1D,0x59,0xA5,0xB1,0x6B,0xA0,0x6E,0x6E,0x12,0xD1,0xDA,0x27,0xC5,0x24,0x9A };

unsigned char SM2_Gx[32] = { 0x42,0x1D,0xEB,0xD6 ,0x1B,0x62,0xEA,0xB6 ,0x74,0x64,0x34,0xEB ,0xC3,0xCC,0x31,0x5E ,0x32,0x22,0x0B,0x3B ,0xAD,0xD5,0x0B,0xDC ,0x4C,0x4E,0x6C,0x14 ,0x7F,0xED,0xD4,0x3D };
unsigned char SM2_Gy[32] = { 0x06,0x80,0x51,0x2B ,0xCB,0xB4,0x2C,0x07 ,0xD4,0x73,0x49,0xD2 ,0x15,0x3B,0x70,0xC4 ,0xE5,0xD7,0xFD,0xFC ,0xBF,0xA3,0x6E,0xA1 ,0xA8,0x58,0x41,0xB9 ,0xE4,0x6E,0x09,0xA2 };

unsigned char SM2_n[32] = { 0x85,0x42,0xD6,0x9E ,0x4C,0x04,0x4F,0x18 ,0xE8,0xB9,0x24,0x35 ,0xBF,0x6F,0xF7,0xDD ,0x29,0x77,0x20,0x63 ,0x04,0x85,0x62,0x8D ,0x5A,0xE7,0x4E,0xE7 ,0xC3,0x2E,0x79,0xB7 };
unsigned char one[32] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01 };

big Gx, Gy, p, a, b, n;

epoint* G, * nG;
/****************************************************************

Function:	SM2_Init
Description:	Initiate SM2 curve
Calls:	MIRACL functions
Called By:	SM2_KeyGeneration,SM2_Sign,SM2_Verify,SM2_SelfCheck
Input:	null
Output:	null
Return:	0: sucess;
1: parameter initialization error;
4: the given point G is not a point of order n
Others:
****************************************************************/
int SM2_Init()

{
	Gx = mirvar(0);
	Gy = mirvar(0);
	p = mirvar(0);
	a = mirvar(0);
	b = mirvar(0);
	n = mirvar(0);

	bytes_to_big(SM2_NUMWORD, SM2_Gx, Gx);
	bytes_to_big(SM2_NUMWORD, SM2_Gy, Gy);
	bytes_to_big(SM2_NUMWORD, SM2_p, p);
	bytes_to_big(SM2_NUMWORD, SM2_a, a);
	bytes_to_big(SM2_NUMWORD, SM2_b, b);
	bytes_to_big(SM2_NUMWORD, SM2_n, n);

	ecurve_init(a, b, p, MR_PROJECTIVE);
	G = epoint_init();
	nG = epoint_init();

	if (!epoint_set(Gx, Gy, 0, G))//initialise point G
	{
		return ERR_ECURVE_INIT;
	}
	ecurve_mult(n, G, nG);


	if (!point_at_infinity(nG)) {
		return ERR_ORDER;
	}


	//test if the order of the point is n


	return 0;

}


/****************************************************************

Function:	Test_Point
Description: Calls:	test if the given point is on SM2 curve
Called By:	SM2_KeyGeneration
Input:	point
Output:	null
Return:	0: sucess
3: not a valid point on curve


Others:
****************************************************************/
int Test_Point(epoint* point)
{
	big x, y, x_3, tmp;
	x = mirvar(0);
	y = mirvar(0);
	x_3 = mirvar(0);
	tmp = mirvar(0);


	//test if y^2=x^3+ax+b
	epoint_get(point, x, y);


	power(x, 3, p, x_3);
	multiply(x, a, x);
	divide(x, p, tmp);
	add(x_3, x, x);
	add(x, b, x);
	divide(x, p, tmp);
	power(y, 2, p, y);
	if (mr_compare(x, y) != 0)


		//x_3=x^3 mod p
		//x=a*x
		//x=a*x mod p  , tmp=a*x/p
		//x=x^3+ax
		//x=x^3+ax+b
		//x=x^3+ax+b mod p
		//y=y^2 mod p

		return ERR_NOT_VALID_POINT;
	else
		return 0;
}


/****************************************************************

Function:	Test_PubKey
Description: Calls:	test if the given public key is valid
Called By:	SM2_KeyGeneration
Input:	pubKey    //a point
Output:	null
Return:	0: sucess
2: a point at infinity
5: X or Y coordinate is beyond Fq
3: not a valid point on curve
4: not a point of order n
Others:
****************************************************************/
int Test_PubKey(epoint * pubKey)
{
	big x, y, x_3, tmp;

	epoint* nP;
	x = mirvar(0);
	y = mirvar(0);
	x_3 = mirvar(0);
	tmp = mirvar(0);

	nP = epoint_init();

	//test if the pubKey is the point at infinity
	if (point_at_infinity(pubKey))// if pubKey is point at infinity, return error; return ERR_INFINITY_POINT;
	//test if x<p   and  y<p  both hold
		epoint_get(pubKey, x, y);
	if ((mr_compare(x, p) != -1) || (mr_compare(y, p) != -1))
		return ERR_NOT_VALID_ELEMENT;

	if (Test_Point(pubKey) != 0)
		return ERR_NOT_VALID_POINT;

	//test if the order of pubKey is equal to n


	ecurve_mult(n, pubKey, nP);
	if (!point_at_infinity(nP))


		// nP=[n]P
		// if np is point NOT at infinity, return error;

		return ERR_ORDER;
	return 0;
}


/****************************************************************

Function:	Test_Zero
Description: Calls:	test if the big x is zero
Called By:	SM2_Sign
Input:	pubKey    //a point
Output:	null
Return:	0: x!=0
1: x==0
Others:
****************************************************************/
int Test_Zero(big x)
{
	big zero;
	zero = mirvar(0);
	if (mr_compare(x, zero) == 0)

		return 1;
	else return 0;

}


/****************************************************************

Function:	Test_n
Description: Calls:	test if the big x is order n
Called By:	SM2_Sign
Input:	big x    //a miracl data type
Output:	null
Return:	0: sucess
1: x==n,fail
Others:
****************************************************************/
int Test_n(big x)
{
	//   bytes_to_big(32,SM2_n,n);
	if (mr_compare(x, n) == 0)
		return 1;
	else return 0;
}


/****************************************************************
Function:       Test_Range
Description:    test if the big x belong to the range[1,n-1]
Calls:


Called By:
Input:


SM2_Verify
big x    ///a miracl data type



Output:
Return:


null
0: sucess

1: fail
Others:
****************************************************************/
int Test_Range(big x)
{
	big one, decr_n;

	one = mirvar(0);
	decr_n = mirvar(0);

	convert(1, one);
	decr(n, 1, decr_n);

	if ((mr_compare(x, one) < 0) | (mr_compare(x, decr_n) > 0))
		return 1;
	return 0;
}


/****************************************************************

Function:	SM2_KeyGeneration
Description:	calculate a pubKey out of a given priKey
Calls:	SM2_SelfCheck()
Called By:	SM2_Init()
Input:	priKey       // a big number lies in[1,n-2]
Output:	pubKey       // pubKey=[priKey]G
Return:	0: sucess
2: a point at infinity
5: X or Y coordinate is beyond Fq
3: not a valid point on curve
4: not a point of order n
Others:
****************************************************************/                  
int DAP_SM2_KeyGeneration(unsigned char PriKey[], unsigned char Ukey[], unsigned char key[], unsigned char Px[], unsigned char Py[], unsigned char ad[]) {
	int i = 0;
	int addspace = 50;//µÿ÷∑¥Û–°
	big d, PAx, PAy, z1, u, K, z2, v, t, a, one1;
	epoint* PA;

	SM2_Init();
	PA = epoint_init();

	d = mirvar(0);
	PAx = mirvar(0);
	PAy = mirvar(0);
	z1 = mirvar(0);
	z2 = mirvar(0);
	u = mirvar(0);
	K = mirvar(0);
	v = mirvar(0);
	t = mirvar(0);
	a = mirvar(0);
	one1 = mirvar(0);

	bytes_to_big(SM2_NUMWORD, PriKey, d);//d
	bytes_to_big(SM2_NUMWORD, Ukey, u);//u
	bytes_to_big(SM2_NUMWORD, key, K);//k
	bytes_to_big(SM2_NUMWORD, ad, a);//alpha
	bytes_to_big(SM2_NUMBITS, one, one1);//1

	for (i = 0; i < addspace; i++)
	{
		add(one1, d, z1);//d+1=z1
		xgcd(z1, n, z1, z1, z1);//z1=(z1)^(-1)mod n
		multiply(d, z1, v);//v=d*(d+1)^-1
		/*cotnum(v, stdout);*/

		multiply(u, z1, t);//t=u*(d+1)^-1

		ecurve_mult(d, G, PA);
		epoint_get(PA, PAx, PAy);
		/*printf("The Public key Pa:\n");
		cotnum(PAx, stdout); cotnum(PAy, stdout);*/
		H1(a, v, t, z2, n);//hash1
		add(z2, K, z2);//K[a]
		/*cotnum(z2, stdout);*/

		zero(z1); zero(z2);
	}

	big_to_bytes(SM2_NUMWORD, PAx, Px, TRUE);
	big_to_bytes(SM2_NUMWORD, PAy, Py, TRUE);


	i = Test_PubKey(PA);
	if (i)
		return i;
	else
		return 0;

}


/****************************************************************


Function:
Description:
Calls:
Called By:
Input:


SM2_Sign
SM2 signature algorithm
SM2_Init(),Test_Zero(),Test_n(), SM3_256()
SM2_SelfCheck()
message    //the message to be signed


len	//the length of message
ZA	// ZA=Hash(ENTLA| | IDA| | a| | b| | Gx || Gy || xA| | yA)
rand	//a random number K lies in [1,n-1]
d	//the private key



Output:
Return:





Others:


R,S        //signature result
0: sucess
1: parameter initialization error;
4: the given point G is not a point of order n
6: the signed r equals 0 or r+rand equals n
7  the signed s equals 0

****************************************************************/
int SM2_Sign(unsigned char* message, int len, unsigned char ZA[], unsigned char rand[], unsigned char d[], unsigned char R[], unsigned char S[])
{
	/*unsigned char E[32] = { 0xB5,0x24,0xF5,0x52 ,0xCD,0x82,0xB8,0xB0 ,0x28,0x47,0x6E,0x00 ,0x5C,0x37,0x7F,0xB1 ,0x9A,0x87,0xE6,0xFC ,0x68,0x2D,0x48,0xBB ,0x5D,0x42,0xE3,0xD9 ,0xB9,0xEF,0xFE,0x76 };*/
	unsigned char hash[SM3_len / 8];
	int M_len = len + SM3_len / 8;
	unsigned char* M = NULL;
	int i;

	big dA, r, s, e, k, KGx, KGy;
	big rem, rk, z1, z2, one1;
	epoint* KG;

	//initiate
	dA = mirvar(0);
	e = mirvar(0);
	k = mirvar(0);
	KGx = mirvar(0);
	KGy = mirvar(0);
	r = mirvar(0);
	s = mirvar(0);
	rem = mirvar(0);
	rk = mirvar(0);
	z1 = mirvar(0);
	z2 = mirvar(0);
	one1 = mirvar(0);

	bytes_to_big(SM2_NUMWORD, d, dA);//cinstr(dA,d);
	bytes_to_big(SM2_NUMWORD, one, one1);

	KG = epoint_init();

	//step1,set M=ZA| |M
	M = (char*)malloc(sizeof(char) * (M_len + 1));
	memcpy(M, ZA, SM3_len / 8);
	memcpy(M + SM3_len / 8, message, len);

	//step2,generate e=H(M)
	SM3_256(M, M_len, hash);
	bytes_to_big(SM3_len / 8, hash, e);
	/*bytes_to_big(SM2_NUMWORD, E, e);*/
	/*printf("\ne:\n");
	cotnum(e, stdout);*/

	//step3:generate k
	bytes_to_big(SM3_len / 8, rand, k);

	//step4:calculate kG
	ecurve_mult(k, G, KG);//[k]G

	//step5:calculate r
	epoint_get(KG, KGx, KGy);
	/*printf("\nThe Point R:\n");
	cotnum(KGx, stdout); cotnum(KGy, stdout);*/
	add(e, KGx, r);
	divide(r, n, rem);
	/*printf("\nr:\n");
	cotnum(r, stdout);*/

	//judge r=0 or n+k=n?
	add(r, k, rk);
	if (Test_Zero(r) | Test_n(rk))
		return ERR_GENERATE_R;

	//Step6:
	//xgcd(z1, n, z1, z1, z1);//z1=(z1)^(-1)mod n
	//multiply(r, dA, z2);//(dA*r)->z2
	//divide(z2, n, rem);//z2 mod n
	//subtract(k, z2, z2);//z2-k->z2
	//add(z2, n, z2);//z2+n
	//multiply(z1, z2, s);//z1+z2=s
	//divide(s, n, rem);
	add(one1, dA, z1);//(1+dA)
	xgcd(z1, n, z1, z1, z1);//z1=(z1)^(-1)mod n
	/*printf("\n(1+d)^(-1):\n");
	cotnum(z1, stdout);*/
	multiply(r, dA, z2);//(dA*r)->z2
	divide(z2, n, rem);//z2 mod n
	subtract(k, z2, z2);//k-z2->z2
	multiply(z1, z2, s);//z1+z2=s
	divide(s, n, rem);
	/*printf("\ns:\n");
	cotnum(s, stdout);*/

	//judge s=0?
	if (Test_Zero(s))
		return ERR_GENERATE_S;

	big_to_bytes(SM2_NUMWORD, r, R, TRUE);
	big_to_bytes(SM2_NUMWORD, s, S, TRUE);

	free(M);
	return 0;
}


/****************************************************************


Function:
Description:
Calls:
Called By:


SM2_Verify
SM2 verification algorithm
SM2_Init(),Test_Range(), Test_Zero(),SM3_256()
SM2_SelfCheck()



Input:


message len
ZA
Px,Py
R,S


//the message to be signed
//the length of message
//ZA=Hash(ENTLA| | IDA| | a| | b| | Gx || Gy || xA| | yA) //the public key
//signature result


Output:
Return:         0: sucess
1: parameter initialization error;
4: the given point G is not a point of order n
B: public key error
8: the signed R out of range [1,n-1]
9: the signed S out of range [1,n-1]
A: the intermediate data t equals 0
C: verification fail
Others:
****************************************************************/
int SM2_Verify(unsigned char* message, int len, unsigned char ZA[], unsigned char Px[], unsigned char Py[], unsigned char R[], unsigned char S[])

{
	unsigned char hash[SM3_len / 8];
	int M_len = len + SM3_len / 8;
	unsigned char* M = NULL;
	int i;

	big PAx, PAy, r, s, e, t, rem, x1, y1;
	big RR;
	epoint* PA, * sG, * tPA;

	i = SM2_Init();
	if (i) return i;

	PAx = mirvar(0);
	PAy = mirvar(0);
	r = mirvar(0);
	s = mirvar(0);
	e = mirvar(0);
	t = mirvar(0);
	x1 = mirvar(0);
	y1 = mirvar(0);
	rem = mirvar(0);
	RR = mirvar(0);

	PA = epoint_init();
	sG = epoint_init();
	tPA = epoint_init();

	bytes_to_big(SM2_NUMWORD, Px, PAx);
	bytes_to_big(SM2_NUMWORD, Py, PAy);

	bytes_to_big(SM2_NUMWORD, R, r);
	bytes_to_big(SM2_NUMWORD, S, s);

	if (!epoint_set(PAx, PAy, 0, PA))//initialise public key
	{
		return ERR_PUBKEY_INIT;
	}

	//step1: test if r belong to [1,n-1]
	if (Test_Range(r))
		return ERR_OUTRANGE_R;

	//step2: test if s belong to [1,n-1]

	if (Test_Range(s))
		return ERR_OUTRANGE_S;

	//step3,generate M
	M = (char*)malloc(sizeof(char) * (M_len + 1));
	memcpy(M, ZA, SM3_len / 8);
	memcpy(M + SM3_len / 8, message, len);

	//step4,generate e=H(M)
	SM3_256(M, M_len, hash);
	bytes_to_big(SM3_len / 8, hash, e);
	/*printf("\ne':\n");
	cotnum(e, stdout);*/

	//step5:generate t
	add(r, s, t);//r+s=t
	divide(t, n, rem);//t mod n

	if (Test_Zero(t))
		return ERR_GENERATE_T;

	//step 6: generate(x1,y1)
	ecurve_mult(s, G, sG);//[s]G
	ecurve_mult(t, PA, tPA);//[t]P
	ecurve_add(sG, tPA);//tPA=[s]G+[t]P
	epoint_get(tPA, x1, y1);
	/*printf("\ntPA:\n");
	cotnum(x1, stdout); cotnum(y1, stdout);*/

	//step7:generate RR
	add(e, x1, RR);
	divide(RR, n, rem);

	free(M);
	if (mr_compare(RR, r) == 0)
		return 0;
	else
		return ERR_DATA_MEMCMP;
}

int DAP_SM2_Extract(unsigned char* message1, unsigned char* message2, unsigned char S1[], unsigned char S2[], int len1,int len2, unsigned char rand[], unsigned char ZA[])
{
	unsigned char hash1[SM3_len / 8];
	unsigned char hash2[SM3_len / 8];
	int M_len1 = len1 + SM3_len / 8;
	int M_len2 = len2 + SM3_len / 8;
	unsigned char* M_1 = NULL;
	unsigned char* M_2 = NULL;

	big e1, e2, k, KGx, KGy, rem_1, r_1, rem_2, r_2, s_1, s_2, v;
	epoint* KG;

	e1 = mirvar(0);
	e2 = mirvar(0);
	k = mirvar(0);
	KGx = mirvar(0);
	KGy = mirvar(0);
	rem_1 = mirvar(0);
	r_1 = mirvar(0);
	rem_2 = mirvar(0);
	r_2 = mirvar(0);
	s_1 = mirvar(0);
	s_2 = mirvar(0);
	v = mirvar(0);

	KG = epoint_init();

	//step3:generate k
	bytes_to_big(SM3_len / 8, rand, k);

	//step4:calculate kG
	ecurve_mult(k, G, KG);//[k]G

	//step1,set M=ZA| |M
	M_1 = (char*)malloc(sizeof(char) * (M_len1 + 1));
	memcpy(M_1, ZA, SM3_len / 8);
	memcpy(M_1 + SM3_len / 8, message1, len1);

	//step2,generate e=H(M)
	SM3_256(M_1, M_len1, hash1);
	bytes_to_big(SM3_len / 8, hash1, e1);
	/*bytes_to_big(SM2_NUMWORD, E, e);*/
	/*printf("\ne:\n");
	cotnum(e, stdout);*/

	//step5:calculate r
	epoint_get(KG, KGx, KGy);
	/*printf("\nThe Point R:\n");
	cotnum(KGx, stdout); cotnum(KGy, stdout);*/
	add(e1, KGx, r_1);
	divide(r_1, n, rem_1);
	/*printf("\nr:\n");
	cotnum(r, stdout);*/

	//step1,set M=ZA| |M
	M_2 = (char*)malloc(sizeof(char) * (M_len2 + 1));
	memcpy(M_2, ZA, SM3_len / 8);
	memcpy(M_2 + SM3_len / 8, message1, len1);

	//step2,generate e=H(M)
	SM3_256(M_2, M_len2, hash2);
	bytes_to_big(SM3_len / 8, hash2, e2);
	/*bytes_to_big(SM2_NUMWORD, E, e);*/
	/*printf("\ne:\n");
	cotnum(e, stdout);*/

	//step5:calculate r
	epoint_get(KG, KGx, KGy);
	/*printf("\nThe Point R:\n");
	cotnum(KGx, stdout); cotnum(KGy, stdout);*/
	add(e2, KGx, r_2);
	divide(r_2, n, rem_2);
	/*printf("\nr:\n");
	cotnum(r, stdout);*/

	bytes_to_big(SM2_NUMWORD, S1, s_1);
	bytes_to_big(SM2_NUMWORD, S2, s_2);
	
	subtract(s_1, s_2, rem_1);
	subtract(r_2, r_1, rem_2);
	divide(rem_1, rem_2, v);
	/*printf("v:\n");
	cotnum(v, stdout);*/

	return 0;
}


/****************************************************************


Function:   Description: Calls:
Called By:
Input:
Output:


SM2_SelfCheck
SM2 self check
SM2_Init(), SM2_KeyGeneration,SM2_Sign, SM2_Verify,SM3_256()

Return:         0: sucess
1: paremeter initialization error
2: a point at infinity
5: X or Y coordinate is beyond Fq
3: not a valid point on curve
4: not a point of order n
B: public key error
8: the signed R out of range [1,n-1]
9: the signed S out of range [1,n-1]
A: the intermediate data t equals 0
C: verification fail
Others:
****************************************************************/
int SM2_SelfCheck()
{
	//the private key
	unsigned char
		dA[32] = { 0x12,0x8B,0x2F,0xA8 ,0xBD,0x43,0x3C,0x6C ,0x06,0x8C,0x8D,0x80 ,0x3D,0xFF,0x79,0x79 ,0x2A,0x51,0x9A,0x55 ,0x17,0x1B,0x1B,0x65 ,0x0C,0x23,0x66,0x1D ,0x15,0x89,0x72,0x63 };//d
	//unsigned char
	//	uA[32] = { 0x32,0x19,0x4C,0x01 ,0x55,0x43,0x6C,0x71 ,0x54,0x8C,0x8D,0x80 ,0x3D,0xFF,0x79,0x79 ,0x2A,0x51,0x9A,0x31 ,0x85,0x1B,0x1B,0x65 ,0x0C,0x23,0x66,0x1D ,0x15,0x89,0x72,0x23 };//u
	unsigned char 
		k[32] = { 0x00,0x00,0x00,0x00,0x55,0x43,0x6C,0x71,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3D,0xFF,0x79,0x79,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07 };//k
	unsigned char
		add[32] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x32,0xFF,0x79,0x79,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0B };//add
	unsigned char
		rand[32] = { 0x6C,0xB2,0x8D,0x99,0x38,0x5C,0x17,0x5C,0x94,0xF9,0x4E,0x93,0x48,0x17,0x66,0x3F,0xC1,0x76,0xD9,0x25,0xDD,0x72,0xB7,0x27,0x26,0x0D,0xBA,0xAE,0x1F,0xB2,0xF9,0x6F};
	//the public key
	unsigned char
		xA[32]={0x0A,0xE4,0xC7,0x79 ,0x8A,0xA0,0xF1,0x19 ,0x47,0x1B,0xEE,0x11 ,0x82,0x5B,0xE4,0x62,0x02,0xBB,0x79,0xE2 ,0xA5,0x84,0x44,0x95 ,0xE9,0x7C,0x04,0xFF ,0x4D,0xF2,0x54,0x8A};
	unsigned char
		yA[32]={0x7C,0x02,0x40,0xF8 ,0x8F,0x1C,0xD4,0xE1 ,0x63,0x52,0xA7,0x3C ,0x17,0xB7,0xF1,0x6F ,0x07,0x35,0x3E,0x53 ,0xA1,0x76,0xD6,0x84 ,0xA9,0xFE,0x0C,0x6B ,0xB7,0x98,0xE8,0x57 };
	/*unsigned char xA[32], yA[32];*/
	unsigned char r[32], s[32], s2[32];// Signature

	unsigned char IDA[18] = { 0x41,0x4C ,0x49,0x43,0x45,0x31 ,0x32,0x33,0x40,0x59 ,0x41,0x48,0x4F,0x4F ,0x2E,0x43,0x4F,0x4D };//ASCII code of userA's identification
	int IDA_len = 16;
	unsigned char ENTLA[2] = { 0x00,0x90 };//the length of userA's identification,presentation in ASCII code
	unsigned char* message = "message digest";//the message(1) to be signed
	unsigned char* message2 = "happy";
	int len = strlen(message);//the length of message
	int len2 = strlen(message2);

	unsigned char ZA[SM3_len / 8];//ZA=Hash(ENTLA| | IDA| | a| | b| | Gx || Gy || xA| | yA) 
	unsigned char Msg[210]; //210=IDA_len+2+SM2_NUMWORD*6
	int temp;

	miracl* mip = mirsys(10000, 16);
	mip->IOBASE = 16;

	temp = DAP_SM2_KeyGeneration(dA, rand, xA, k, yA, add);
	if (temp)
		return temp;

	// ENTLA| | IDA| | a| | b| | Gx || Gy || xA| | yA
	memcpy(Msg, ENTLA, 2);
	memcpy(Msg + 2, IDA, IDA_len);
	memcpy(Msg + 2 + IDA_len, SM2_a, SM2_NUMWORD);
	memcpy(Msg + 2 + IDA_len + SM2_NUMWORD, SM2_b, SM2_NUMWORD);
	memcpy(Msg + 2 + IDA_len + SM2_NUMWORD * 2, SM2_Gx, SM2_NUMWORD);
	memcpy(Msg + 2 + IDA_len + SM2_NUMWORD * 3, SM2_Gy, SM2_NUMWORD);
	memcpy(Msg + 2 + IDA_len + SM2_NUMWORD * 4, xA, SM2_NUMWORD);
	memcpy(Msg + 2 + IDA_len + SM2_NUMWORD * 5, yA, SM2_NUMWORD);
	SM3_256(Msg, 210, ZA);

	temp = SM2_Sign(message, len, ZA, rand, dA, r, s);
	if (temp)
		return temp;//if tmp!=0,return tmp

	temp = SM2_Verify(message, len, ZA, xA, yA, r, s);
	if (temp)
		return temp;
	temp = SM2_Sign(message2, len2, ZA, rand, dA, r, s2);

	temp = DAP_SM2_Extract(message, message2, s, s2, len, len2, rand, ZA);

	return 0;
}
