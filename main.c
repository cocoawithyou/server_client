#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <json-c/json.h>
////////////////////가져온거//////////////
#include <openssl/aes.h>
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
typedef unsigned char U8;
#define PK2_new() BN_dxy_new(2)
#define PK2_free(a) BN_dxy_free(a, 2)
#define SK2_new() BN_dxy_new(2)
#define SK2_free(a) BN_dxy_free(a, 2)
#define CT2_new() BN_dxy_new(2)
#define CT2_free(a) BN_dxy_free(a, 2)
#define PK3_new() BN_dxy_new(3)
#define PK3_free(a) BN_dxy_free(a, 3)
#define SK3_new() BN_dxy_new(3)
#define SK3_free(a) BN_dxy_free(a, 3)
#define DXY_new() BN_dxy_new(3)
#define DXY_free(a) BN_dxy_free(a, 3)
////////////////////////////////////////////////////////////////////////
static struct sockaddr_in client_addr;
static int client_fd, n, n2, state = 1;
static char recv_data[6000];
static char chat_data[6000];
static char tmp[6000];
//////////////////////////RSAsign코드/////////////////////////////////
typedef struct
{
	union{
		BIGNUM *p;
		BIGNUM *d;
		BIGNUM *N; //p*q 사용
		BIGNUM *C0;
	};
	union{
		BIGNUM *y;
		BIGNUM *key; // e,d 로 사용
		BIGNUM *C1;
	};
	union{
		BIGNUM *g;
		BIGNUM *x;
	};
}BN_dxy;
typedef BN_dxy PK;
typedef BN_dxy SK;
typedef BN_dxy CT;
void BN_scanf(BIGNUM *input)
{
	int x;
	scanf("%d",&x);
	BN_set_word(input,x);
}
void BN_printf(const BIGNUM *input)
{
	U8 *c = BN_bn2dec(input);
	printf("%s",c);
	free(c);
}
BN_dxy * BN_dxy_new(int element)
{
	BN_dxy * dxy = (BN_dxy *)calloc(1, sizeof(BN_dxy));
	if(element >=1)	dxy->d = BN_new(); 
	if(element >=2)	dxy->y = BN_new();
	if(element >=3)	dxy->x = BN_new();
	return dxy;
}
int BN_dxy_copy(const BN_dxy * dxy, const BIGNUM *d, const BIGNUM *x, const BIGNUM *y)
{
	BN_copy(dxy->d, d); 
	BN_copy(dxy->x, x); 
	BN_copy(dxy->y, y);
}
void BN_dxy_free(BN_dxy * dxy, int element)
{
	if(element >=1)	BN_free(dxy->d);
	if(element >=2)	BN_free(dxy->y);
	if(element >=3)	BN_free(dxy->x);
	free(dxy);
}
BN_dxy * BN_Ext_Euclid(const BIGNUM* a, const BIGNUM* b, BN_CTX * ctx){
	BN_dxy * dxy;
	dxy = DXY_new();
	if (BN_is_zero(b)){
		//BN_dxy * dxy; 이동
		BIGNUM * one = BN_new();
		BN_one(one);
		//dxy = DXY_new(); 이동
		BN_dxy_copy(dxy, a, one, b);
		BN_free(one);
		return dxy;
	}
	else{
		/*code*/
		BIGNUM *div, *rem,*tmp;
	
		div = BN_new();
		rem =BN_new();
		tmp = BN_new();

		// div = a/b
		BN_div(div,rem,a,b,ctx);
		dxy = BN_Ext_Euclid(b,rem,ctx);

		BN_mul(tmp,div,dxy->y,ctx);
		BN_sub(tmp,dxy->x,tmp);

		BN_dxy_copy(dxy,dxy->d,dxy->y,tmp);

		BN_free(div);BN_free(rem);BN_free(tmp);
	
		return dxy;
	}
}

void BN_Square_Multi(BIGNUM * z,BIGNUM *x, BIGNUM *a, BIGNUM *n, BN_CTX * bn_ctx)
{
	//채워야할 부분
	/*code*/
	BN_one(z);
	BIGNUM *tmp;
	tmp = BN_new();
	
    for(int i=BN_num_bits(a)-1;i>=0;i--){
	  BN_mul(tmp,z,z,bn_ctx);
	  BN_mod(z,tmp,n,bn_ctx);
      if(BN_is_bit_set(a,i)==1){
		 BN_mul(tmp,z,x,bn_ctx);
         BN_mod(z,tmp,n,bn_ctx);
      }
   }
	
   BN_free(tmp);
  
}
void RSA_setup(PK *pub, SK *priv)
{
	BN_CTX * ctx = BN_CTX_new();
	BIGNUM *p = BN_new();	
	BIGNUM *q = BN_new();
	BN_set_word(pub->key, 3);
	/*code*/
	BN_dxy * dxy; 
	BIGNUM *ord = BN_new(); // order of group
	
	while(1){
		BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL);
		BN_generate_prime_ex(q, 1024, 0, NULL, NULL, NULL);

		/* code */
		//N = p*q
		BN_mul(pub->N,p,q,ctx);
		
		//calc order
		BN_sub(p,p,BN_value_one());//p = p-1
		BN_sub(q,q,BN_value_one());//q = q-1
		BN_mul(ord,p,q,ctx);// ord = (p-1) * (q-1)
		
		dxy = BN_Ext_Euclid(ord,pub->key,ctx);
		if(!BN_is_one(dxy->d)){
			BN_dxy_free(dxy,2);
			continue;
		}
		break;
	}

	/* code */
	// x * ord + y * e  = d 
	// 양변에 mod ord
	// y * e = d mod ord
	while(BN_is_negative(dxy->y)){
		BN_mod_add(dxy->y,dxy->y,ord,pub->N,ctx);
	}
	BN_copy(priv->key,dxy->y);
	BN_copy(priv->N,pub->N);
	
	BN_free(p); BN_free(q); BN_free(ord);
	BN_dxy_free(dxy,2); BN_CTX_free(ctx);
	
}
U8* RSA_sign(U8 *msg, int msg_len, const SK *priv)
{
	/*code*/
	//digest =H(M)
	U8 digest[SHA256_DIGEST_LENGTH]={0};
	SHA256((U8*)&msg, msg_len, (U8*)&digest);
	
	//digest -> bn_digest
	BIGNUM *bn_digest = BN_new();
	BN_bin2bn(digest,SHA256_DIGEST_LENGTH,bn_digest);
	// printf("bn_digest\t : %s\n", BN_bn2hex(bn_digest));
	BN_CTX * ctx = BN_CTX_new();
	
	
	//sigma = bn_sign
	BIGNUM *bn_sign = BN_new();
	//sigma = pow(bn_digest,d) mod N
	BN_Square_Multi(bn_sign, bn_digest, priv->key, priv->N, ctx);
	// printf("bn_sign\t : %s\n", BN_bn2hex(bn_sign));
	U8 *sign = (U8*)calloc(BN_num_bytes(bn_sign),sizeof(U8));
	sign = BN_bn2hex(bn_sign);
	
	BN_free(bn_digest); BN_free(bn_sign);
	BN_CTX_free(ctx);
	return sign;
}
int RSA_verify(U8 *msg, int msg_len,const U8 *sign, const PK *pub)
{
	/*code*/
	int result;
	BN_CTX * ctx = BN_CTX_new();
	BIGNUM *bn_digest_prime = BN_new();
	BIGNUM *bn_sign = BN_new();
	BN_hex2bn(&bn_sign,sign);
	//printf("bn_sign\t : %s\n", BN_bn2hex(bn_sign));//cert 확인용
	
	BN_Square_Multi(bn_digest_prime, bn_sign, pub->key, pub->N, ctx);
	
	U8 digest[SHA256_DIGEST_LENGTH]={0};
	SHA256((U8*)msg, msg_len, (U8*)&digest);//이거머임????  (U8*)&msg넘겨줘야 하는거 아닌가
	// printf("RSA_verify msg\t : %p\n", msg);
	// printf("RSA_verify &msg\t : %p\n", &msg);
	// printf("RSA_verify &digest\t : %p\n", &digest);
	
	BIGNUM *bn_digest = BN_new();
	BN_bin2bn(digest,SHA256_DIGEST_LENGTH,bn_digest);
	// printf("bn_digest_prime\t : %s\n", BN_bn2hex(bn_digest_prime));
	// printf("bn_digest\t : %s\n", BN_bn2hex(bn_digest));
	
	//같으면 zero 반환
	if(BN_cmp(bn_digest_prime,bn_digest)==0){
		result = 1;
	}
	else{
		result = 0;
	}
	// printf("result: %d\n",result);
	BN_free(bn_sign);BN_free(bn_digest_prime);BN_free(bn_digest);
	BN_CTX_free(ctx);

	return result;
}
//////////////////////////////////RSA ENC,DEC////////////////////////////////////////
U8 * RSA_enc(U8 *msg, int msg_len,PK *pub)
{
	BIGNUM *C = BN_new();
	BIGNUM *M = BN_new();
	BN_bin2bn(msg, msg_len, M);
	U8 * cipher;
	BN_CTX * ctx = BN_CTX_new();
	
	/* code */
	BN_Square_Multi(C,M,pub->key,pub->N,ctx);
	cipher = BN_bn2hex(C);
	
	BN_free(C); BN_free(M);
	BN_CTX_free(ctx);
	
	return cipher;
}
/////////////////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Useage : ./client [IP] [PORT]\n");
        exit(0);
    }
    
    char *IP = argv[1];
    in_port_t PORT = atoi(argv[2]);

    client_fd = socket(PF_INET, SOCK_STREAM, 0);

    client_addr.sin_addr.s_addr = inet_addr(IP);
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(PORT);

    if (connect(client_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) == -1)
    {
        printf("Can't Connect\n");
        close(client_fd);
        return -1;
    }
	
	//256 prime nc 생성 및 json을 이용해 전송
	BIGNUM * bn_nc = BN_new();
	BN_generate_prime_ex(bn_nc, 256, 0, NULL, NULL, NULL);
	U8 *hex_nc = (U8*)calloc(BN_num_bytes(bn_nc),sizeof(U8));
	hex_nc = BN_bn2hex(bn_nc);
	
	U8 *bin_nc = (U8*)calloc(BN_num_bytes(bn_nc),sizeof(U8));
	BN_bn2bin(bn_nc,bin_nc);
	json_object *c_trans1 = json_object_new_object();//변수 선언 및 할당
	json_object_object_add(c_trans1,"scheme",json_object_new_string("RSA_SCHEME"));
	json_object_object_add(c_trans1,"N",json_object_new_string(hex_nc));
	U8* send_c_trans1 = json_object_to_json_string(c_trans1);
	n = send(client_fd, send_c_trans1, strlen(send_c_trans1)+1, 0);
	
	//U8* recv_data에 메세지를 받은 상태
	n = recv(client_fd, recv_data, sizeof(recv_data), 0);//체크
	memcpy(tmp,recv_data,strlen(recv_data)+1); // mac_prime = HMACmk(s_trans1) s_trans1으로 사용할 문자열을 tmp에 복사
	
	json_object *token = json_tokener_parse(recv_data);//받은 문자열을 json형식으로 parse
	
	PK *pub_s = PK2_new();//PK_s
	
	json_object *find_P_N = json_object_object_get(token,"P_N");//key값 P_N으로 object를 찾는다
	U8* pub_s_n = json_object_get_string(find_P_N); // value 값을 얻어서 문자열 pub_n로 return 한다.
	BN_hex2bn(&pub_s->N,pub_s_n);
	
	json_object *find_P_E = json_object_object_get(token,"P_E");//key값 P_E으로 object를 찾는다
	U8* pub_s_e = json_object_get_string(find_P_E); // value 값을 얻어서 문자열 pub_e로 return 한다.
	BN_hex2bn(&pub_s->key,pub_s_e);

	PK *pub_ca = PK2_new(); //PK_CA
	
	json_object *find_CA_N = json_object_object_get(token,"CA_N");//key값 P_N으로 object를 찾는다
	U8* pub_ca_n = json_object_get_string(find_CA_N); // value 값을 얻어서 문자열 pub_n로 return 한다.
	BN_hex2bn(&pub_ca->N,pub_ca_n);
	
	json_object *find_CA_E = json_object_object_get(token,"CA_E");//key값 P_E으로 object를 찾는다
	U8* pub_ca_e = json_object_get_string(find_CA_E); // value 값을 얻어서 문자열 pub_e로 return 한다.
	BN_hex2bn(&pub_ca->key,pub_ca_e);
	
	json_object *find_CERT = json_object_object_get(token,"CERT");//key값 P_E으로 object를 찾는다
	U8* cert = json_object_get_string(find_CERT); // value 값을 얻어서 문자열 cert로 return 한다.
	
	json_object *find_N = json_object_object_get(token,"N");//key값 N으로 object를 찾는다
	U8* hex_ns = json_object_get_string(find_N); // value 값을 얻어서 문자열 hex_ns로 return 한다.
	//빅넘을 이용해 bin로 바꾸는 과정
	BIGNUM * bn_ns = BN_new();
	BN_hex2bn(&bn_ns,hex_ns);
	U8 *bin_ns = (U8*)calloc(BN_num_bytes(bn_ns),sizeof(U8));
	BN_bn2bin(bn_ns,bin_ns);
	
	
	//p_n, p_e = PKs
	U8 *pub_s_N2bin = (U8*)calloc(BN_num_bytes(pub_s->N),sizeof(U8));
	BN_bn2bin(pub_s->N,pub_s_N2bin);
	
	U8 *pub_s_key2bin = (U8*)calloc(BN_num_bytes(pub_s->key),sizeof(U8));
	BN_bn2bin(pub_s->key,pub_s_key2bin);
	
	//H <- HASH(p_n||p_e)
	SHA256_CTX hs = {0};
	SHA256_Init(&hs);
	U8 digest[SHA256_DIGEST_LENGTH] = {0};
	SHA256_Update(&hs, pub_s_N2bin, BN_num_bytes(pub_s->N));
	SHA256_Update(&hs, pub_s_key2bin, BN_num_bytes(pub_s->key));
	SHA256_Final(digest, &hs);
	
	if(RSA_verify(digest, SHA256_DIGEST_LENGTH,cert,pub_ca)){
		printf("cert verify ok !\n");
	}
	else{
		printf("cert verify fali !\n");
	}
 
	//pmk 생성
	BIGNUM * bn_pmk = BN_new();
	BN_generate_prime_ex(bn_pmk, 256, 0, NULL, NULL, NULL);
	U8 *bin_pmk = (U8*)calloc(BN_num_bytes(bn_pmk),sizeof(U8));
	BN_bn2bin(bn_pmk,bin_pmk);
	
	//Mk = HASH(pmk||Nc||Ns)
	SHA256_Init(&hs);
	SHA256_Update(&hs, bin_pmk, BN_num_bytes(bn_pmk));
	SHA256_Update(&hs, bin_nc, BN_num_bytes(bn_nc));
	SHA256_Update(&hs, bin_ns, BN_num_bytes(bn_ns));
	SHA256_Final(digest, &hs);
	BIGNUM * bn_mk = BN_new();
	BN_bin2bn(digest,SHA256_DIGEST_LENGTH,bn_mk);
	U8* mk= (U8*)calloc(SHA256_DIGEST_LENGTH+1,sizeof(U8));;
	memcpy(mk,digest,SHA256_DIGEST_LENGTH+1);
	
	
	U8 *C_hex;
	C_hex = RSA_enc(bin_pmk, BN_num_bytes(bn_pmk),pub_s);
	
	//c_trans2 전송
	json_object *c_trans2 = json_object_new_object();//변수 선언 및 할당
	json_object_object_add(c_trans2,"C",json_object_new_string(C_hex));
	U8* send_c_trans2 = json_object_to_json_string(c_trans2);
	n = send(client_fd, send_c_trans2, strlen(send_c_trans2)+1, 0);
	///////////////////////////page 1///////////////////////////////////////
	
	BIGNUM * bn_send_c_trans1 = BN_new();
	BIGNUM * bn_send_c_trans2 = BN_new();
	BN_bin2bn(send_c_trans1,strlen(send_c_trans1),bn_send_c_trans1);
	BN_bin2bn(send_c_trans2,strlen(send_c_trans2),bn_send_c_trans2);
	
	int c_mac_Len;
	unsigned char c_mac[EVP_MAX_MD_SIZE];
	EVP_MD* evpmd;
	evpmd=EVP_get_digestbyname("SHA256"); //해쉬함수 선택 
	// unsigned char *mk = "012345678901234567890123456789aa";//HMAC의 key //digest쓰기
	HMAC_CTX *hctx = HMAC_CTX_new();//HMAC_CTX 할당
	HMAC_CTX_reset(hctx);//CTX 초기화
	HMAC_Init(hctx, digest, SHA256_DIGEST_LENGTH, evpmd);//선택한 해쉬함수와 key로 초기 세팅
	HMAC_Update(hctx, send_c_trans1, strlen(send_c_trans1)); // update str
	HMAC_Update(hctx, send_c_trans2, strlen(send_c_trans2)); //update str
	HMAC_Final(hctx, c_mac, &c_mac_Len); //결과물을 md에 return (binary_string)

	//c_mac 전송전 hex 형태로 바꾸기
	BIGNUM * bn_c_mac = BN_new();
	BN_bin2bn(c_mac,c_mac_Len,bn_c_mac);
	U8 *c_mac_hex;
	c_mac_hex = BN_bn2hex(bn_c_mac);
	//printf("c_mac_hex : %s\n",c_mac_hex);
	
	//c_mac_hex 전송
	json_object *c_mac_trans = json_object_new_object();//변수 선언 및 할당
	json_object_object_add(c_mac_trans,"MAC",json_object_new_string(c_mac_hex));
	U8* send_c_mac_trans = json_object_to_json_string(c_mac_trans);
	n = send(client_fd,send_c_mac_trans, strlen(send_c_mac_trans)+1, 0);
	
	//server에서 보낸 {“MAC” : “FF”}수신
	n = recv(client_fd, recv_data, sizeof(recv_data), 0);//체크
	json_object *token1 = json_tokener_parse(recv_data);//받은 문자열을 json형식으로 parse
	
	//hex_S_MAC 받아오기
	json_object *find_s_mac = json_object_object_get(token1,"MAC");//key값 P_N으로 object를 찾는다
	U8* hex_s_mac = json_object_get_string(find_s_mac); // value 값을 얻어서 문자열 hex_s_mac로 return 한다.
	
	//mac_prime = HMACmk(s_trans1)
	int mac_prime_Len;
	unsigned char mac_prime[EVP_MAX_MD_SIZE];
	HMAC_CTX_reset(hctx);//CTX 초기화
	HMAC_Init(hctx, digest, SHA256_DIGEST_LENGTH, evpmd);//선택한 해쉬함수와 key로 초기 세팅
	HMAC_Update(hctx, tmp, strlen(tmp)); // update str, tmp= s_trans1
	HMAC_Final(hctx, mac_prime, &mac_prime_Len); //결과물을 md에 return (binary_string)
	
	//비교용 빅넘만들기
	BIGNUM * bn_mac_prime = BN_new();
	BN_bin2bn(mac_prime,mac_prime_Len,bn_mac_prime);

	//S_MAC = MAC
	BIGNUM * bn_s_mac = BN_new(); //hex상태인 hex_s_mac을 bn을 통해 bin로 바꾸기
	BN_hex2bn(&bn_s_mac,hex_s_mac);// hex2bn
	U8* bin_s_mac = (U8*)calloc(BN_num_bytes(bn_s_mac),sizeof(U8));
	BN_bn2bin(bn_s_mac,bin_s_mac);//bin_s_mac 생성
	
	//빅넘으로비교하자,,
	if(BN_cmp(bn_mac_prime,bn_s_mac)==0){
		printf("Mac Verification Success\n");
	}
	else{
		 printf("Mac Verification Fail");
	}
	
	unsigned char const a = 0x00;
	unsigned char const b = 0x01;
	unsigned char const c = 0x02;
	unsigned char const d = 0x03;
	
	U8 *kc=(U8*)calloc(SHA256_DIGEST_LENGTH,sizeof(U8));
	U8 *kc_prime=(U8*)calloc(SHA256_DIGEST_LENGTH,sizeof(U8));
	U8 *ks=(U8*)calloc(SHA256_DIGEST_LENGTH,sizeof(U8));
	U8 *ks_prime=(U8*)calloc(SHA256_DIGEST_LENGTH,sizeof(U8));
	
	SHA256_Init(&hs);
	SHA256_Update(&hs, &a, 1);
	SHA256_Update(&hs, mk, SHA256_DIGEST_LENGTH);
	SHA256_Final(digest, &hs);
	memcpy(kc,digest,SHA256_DIGEST_LENGTH);

	SHA256_Init(&hs);
	SHA256_Update(&hs, &b, 1);
	SHA256_Update(&hs, mk, SHA256_DIGEST_LENGTH);
	SHA256_Final(digest, &hs);
	memcpy(kc_prime,digest,SHA256_DIGEST_LENGTH);

	
	SHA256_Init(&hs);
	SHA256_Update(&hs, &c, 1);
	SHA256_Update(&hs, mk, SHA256_DIGEST_LENGTH);
	SHA256_Final(digest, &hs);
	memcpy(ks,digest,SHA256_DIGEST_LENGTH);

	
	SHA256_Init(&hs);
	SHA256_Update(&hs, &d, 1);
	SHA256_Update(&hs, mk, SHA256_DIGEST_LENGTH);
	SHA256_Final(digest, &hs);
	memcpy(ks_prime,digest,SHA256_DIGEST_LENGTH);

	
	U8 *msg = "How are u?";
	U8 *ct=(U8*)calloc(16,sizeof(U8));
	
	AES_KEY s_enc_key;
    AES_set_encrypt_key(ks, 128, &s_enc_key);
 	AES_encrypt(msg, ct, &s_enc_key);
	BIGNUM * client_bn_ct = BN_new();
	BN_bin2bn(ct,16,client_bn_ct);
	U8* client_hex_ct;
	client_hex_ct = BN_bn2hex(client_bn_ct);
	
	//CT_MAC = HMACks_prime(CT)
	int ct_mac_Len;
	unsigned char ct_mac[EVP_MAX_MD_SIZE];
	HMAC_CTX_reset(hctx);//CTX 초기화
	HMAC_Init(hctx, ks_prime, SHA256_DIGEST_LENGTH, evpmd);//선택한 해쉬함수와 key로 초기 세팅
	HMAC_Update(hctx, ct, 16); // update str, tmp= s_trans1
	HMAC_Final(hctx, ct_mac, &ct_mac_Len); //결과물을 md에 return (binary_string)
	BIGNUM * client_bn_ct_mac = BN_new();
	BN_bin2bn(ct_mac,ct_mac_Len,client_bn_ct_mac);
	U8* client_hex_ct_mac;
	client_hex_ct_mac = BN_bn2hex(client_bn_ct_mac);
	
	json_object *ct_and_ctmac_trans = json_object_new_object();//변수 선언 및 할당
	json_object_object_add(ct_and_ctmac_trans,"CT",json_object_new_string(client_hex_ct));
	json_object_object_add(ct_and_ctmac_trans,"MAC",json_object_new_string(client_hex_ct_mac));
	U8* send_ct_ctmac_trans = json_object_to_json_string(ct_and_ctmac_trans);
	n = send(client_fd,send_ct_ctmac_trans, strlen(send_ct_ctmac_trans)+1, 0);
	
	//CT_MAC = HMACks_prime(CT)
	n = recv(client_fd, recv_data, sizeof(recv_data), 0);//체크
	json_object *token2 = json_tokener_parse(recv_data);//받은 문자열을 json형식으로 parse
	
	//ct,ct_mac 받아오기
	json_object *find_ct = json_object_object_get(token2,"CT");//key값 P_N으로 object를 찾는다
	U8* hex_ct = json_object_get_string(find_ct); // value 값을 얻어서 문자열 hex_ct로 return 한다.
	BIGNUM * bn_ct = BN_new();
	BN_hex2bn(&bn_ct,hex_ct);
	U8* bin_ct =(U8*)calloc(BN_num_bytes(bn_ct),sizeof(U8));
	BN_bn2bin(bn_ct,bin_ct);
	
	json_object *find_ct_mac = json_object_object_get(token2,"MAC");//key값 P_N으로 object를 찾는다
	U8* hex_ct_mac = json_object_get_string(find_ct_mac); // value 값을 얻어서 문자열 hex_ct_mac로 return 한다.
	//비교용 빅넘 생성 bn_ct_mac
	BIGNUM * bn_ct_mac = BN_new();
	BN_hex2bn(&bn_ct_mac,hex_ct_mac);
	
	
	//mac_prime2 = HMACkc_prime(CT(server에서보낸))
	int mac_prime2_Len;
	unsigned char mac_prime2[EVP_MAX_MD_SIZE];
	HMAC_CTX_reset(hctx);//CTX 초기화
	HMAC_Init(hctx, kc_prime, SHA256_DIGEST_LENGTH, evpmd);//선택한 해쉬함수와 key로 초기 세팅
	HMAC_Update(hctx, bin_ct, strlen(bin_ct)); // update str, tmp= s_trans1
	HMAC_Final(hctx, mac_prime2, &mac_prime2_Len); //결과물을 md에 return (binary_string)
	
	
	//비교용 빅넘 생성 mac_prime2 
	BIGNUM * bn_mac_prime2 = BN_new();
	BN_bin2bn(mac_prime2,mac_prime2_Len,bn_mac_prime2);
	U8 *decmsg = (U8*)calloc(16,sizeof(U8));
	//빅넘으로비교하자,,
	
	if(BN_cmp(bn_mac_prime2,bn_ct_mac)==0){
		printf("Mac Verification Success\n");
		AES_KEY c_dec_key;
		AES_set_decrypt_key(kc, 128, &c_dec_key);
		AES_decrypt(bin_ct,decmsg, &c_dec_key);
		printf("%s\n",decmsg);
	}
	else{
		 printf("Mac Verification Fail\n");
	}
	
	BN_free(bn_nc);BN_free(bn_ns);BN_free(bn_pmk);BN_free(bn_mk);
	BN_free(bn_send_c_trans1);	BN_free(bn_send_c_trans2);
	BN_free(bn_c_mac);BN_free(bn_mac_prime);BN_free(bn_s_mac);
	BN_free(client_bn_ct); BN_free(client_bn_ct_mac);
	BN_free(bn_ct); BN_free(bn_ct_mac);
	BN_free(bn_mac_prime2);
	
	free(mk);free(bin_pmk);free(pub_s_N2bin);free(bin_s_mac);free(hex_nc);
	free(kc);free(kc_prime);free(ks);free(ks_prime);
	free(ct);free(decmsg);free(bin_nc);
	
	PK2_free(pub_s);
	PK2_free(pub_ca);
	
    close(client_fd);
    return 0;
}
