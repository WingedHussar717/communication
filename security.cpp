#include "security.h"

using namespace std;
 
#define KEY_LENGTH  2048             // 密钥长度
#define PUB_KEY_FILE "pubkey.pem"    // 公钥路径
#define PRI_KEY_FILE "prikey.pem"    // 私钥路径
 
/*随机产生RSA公私钥*/
void GenerateRSAKey(std::string & out_pub_key, std::string & out_pri_key)
{
	size_t pri_len = 0; // 私钥长度
	size_t pub_len = 0; // 公钥长度
	char *pri_key =  nullptr; // 私钥
	char *pub_key =  nullptr; // 公钥
 
	// 生成密钥对
	RSA *keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);
 
	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());
 
    // 生成私钥
	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    // 注意------生成第1种格式的公钥
    //PEM_write_bio_RSAPublicKey(pub, keypair);
    // 注意------生成第2种格式的公钥（此处代码中使用这种）
	PEM_write_bio_RSA_PUBKEY(pub, keypair);
 
	// 获取长度  
	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);
 
	// 密钥对读取到字符串  
	pri_key = (char *)malloc(pri_len + 1);
	pub_key = (char *)malloc(pub_len + 1);
 
	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);
 
	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';
 
	out_pub_key = pub_key;
	out_pri_key = pri_key;
 
	// 将公钥写入文件
	std::ofstream pub_file(PUB_KEY_FILE, std::ios::out);
	if (!pub_file.is_open())
	{
		perror("pub key file open fail:");
		return;
	}
	pub_file << pub_key;
	pub_file.close();
 
	// 将私钥写入文件
	std::ofstream pri_file(PRI_KEY_FILE, std::ios::out);
	if (!pri_file.is_open())
	{
		perror("pri key file open fail:");
		return;
	}
	pri_file << pri_key;
	pri_file.close();
 
	// 释放内存
	RSA_free(keypair);
	BIO_free_all(pub);
	BIO_free_all(pri);
 
	free(pri_key);
	free(pub_key);
}

/*
@brief : 私钥加密
@para  : clear_text  -[i] 需要进行加密的明文
         pri_key     -[i] 私钥
@return: 加密后的数据
**/
string RsaPriEncrypt(const std::string &clear_text, std::string &pri_key)
{
	std::string encrypt_text;
	BIO *keybio = BIO_new_mem_buf((unsigned char *)pri_key.c_str(), -1);
	RSA* rsa = RSA_new();
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	if (!rsa)
	{
		BIO_free_all(keybio);
		return std::string("");
	}
 
	// 获取RSA单次可以处理的数据的最大长度
	int len = RSA_size(rsa);
 
	// 申请内存：存贮加密后的密文数据
	char *text = new char[len + 1];
	memset(text, 0, len + 1);
 
	// 对数据进行私钥加密（返回值是加密后数据的长度）
	int ret = RSA_private_encrypt(clear_text.length(), (const unsigned char*)clear_text.c_str(), (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0) {
		encrypt_text = std::string(text, ret);
	}
	cout << "!!!" << encrypt_text.length() <<endl;
	// 释放内存  
	free(text);
	BIO_free_all(keybio);
	RSA_free(rsa);
 
	return encrypt_text;
}

/*
@brief : 公钥解密
@para  : cipher_text -[i] 加密的密文
         pub_key     -[i] 公钥
@return: 解密后的数据
**/
string RsaPubDecrypt(const std::string & cipher_text, const std::string & pub_key)
{
	std::string decrypt_text;
	BIO *keybio = BIO_new_mem_buf((unsigned char *)pub_key.c_str(), -1);
	RSA *rsa = RSA_new();
	
	// 注意--------使用第1种格式的公钥进行解密
	//rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
	// 注意--------使用第2种格式的公钥进行解密（我们使用这种格式作为示例）
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	if (!rsa)
	{
		unsigned long err= ERR_get_error(); //获取错误号
		char err_msg[1024] = { 0 };
        ERR_error_string(err, err_msg); // 格式：error:errId:库:函数:原因
		printf("err msg: err:%ld, msg:%s\n", err, err_msg);
		BIO_free_all(keybio);
        return decrypt_text;
	}
 
	int len = RSA_size(rsa);
	char *text = new char[len + 1];
	memset(text, 0, len + 1);
	// 对密文进行解密
	int ret = RSA_public_decrypt(cipher_text.length(), (const unsigned char*)cipher_text.c_str(), (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0) {
		decrypt_text.append(std::string(text, ret));
	}
 
	// 释放内存  
	delete text;
	BIO_free_all(keybio);
	RSA_free(rsa);
 
	return decrypt_text;
}

string RsaPubEncrypt(const std::string &clear_text, std::string &pub_key)
{
	std::string encrypt_text;
	BIO *keybio = BIO_new_mem_buf((unsigned char *)pub_key.c_str(), -1);
	RSA* rsa = RSA_new();
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	if (!rsa)
	{
		BIO_free_all(keybio);
		return std::string("");
	}
 
	// 获取RSA单次可以处理的数据的最大长度
	int len = RSA_size(rsa);
 
	// 申请内存：存贮加密后的密文数据
	char *text = new char[len + 1];
	memset(text, 0, len + 1);
 
	// 对数据进行私钥加密（返回值是加密后数据的长度）
	int ret = RSA_public_encrypt(clear_text.length(), (const unsigned char*)clear_text.c_str(), (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0) {
		encrypt_text = std::string(text, ret);
	}
 
	// 释放内存  
	free(text);
	BIO_free_all(keybio);
	RSA_free(rsa);
 
	return encrypt_text;
}

/*
@brief : 公钥解密
@para  : cipher_text -[i] 加密的密文
         pub_key     -[i] 公钥
@return: 解密后的数据
**/
string RsaPriDecrypt(const std::string & cipher_text, const std::string & pri_key)
{
	std::string decrypt_text;
	BIO *keybio = BIO_new_mem_buf((unsigned char *)pri_key.c_str(), -1);
	RSA *rsa = RSA_new();
	
	// 注意--------使用第1种格式的公钥进行解密
	//rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
	// 注意--------使用第2种格式的公钥进行解密（我们使用这种格式作为示例）
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	if (!rsa)
	{
		unsigned long err= ERR_get_error(); //获取错误号
		char err_msg[1024] = { 0 };
        ERR_error_string(err, err_msg); // 格式：error:errId:库:函数:原因
		printf("err msg: err:%ld, msg:%s\n", err, err_msg);
		BIO_free_all(keybio);
        return decrypt_text;
	}
 
	int len = RSA_size(rsa);
	char *text = new char[len + 1];
	memset(text, 0, len + 1);
	// 对密文进行解密
	int ret = RSA_private_decrypt(cipher_text.length(), (const unsigned char*)cipher_text.c_str(), (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0) {
		decrypt_text.append(std::string(text, ret));
	}
 
	// 释放内存  
	delete text;
	BIO_free_all(keybio);
	RSA_free(rsa);
 
	return decrypt_text;
}
/*RSA私钥解密*/
string RsaPriDecrypt(const char* cipher_text, const std::string & pri_key)
{
	std::string decrypt_text;
	BIO *keybio = BIO_new_mem_buf((unsigned char *)pri_key.c_str(), -1);
	RSA *rsa = RSA_new();
	
	// 注意--------使用第1种格式的公钥进行解密
	//rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
	// 注意--------使用第2种格式的公钥进行解密（我们使用这种格式作为示例）
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	if (!rsa)
	{
		unsigned long err= ERR_get_error(); //获取错误号
		char err_msg[1024] = { 0 };
        ERR_error_string(err, err_msg); // 格式：error:errId:库:函数:原因
		printf("err msg: err:%ld, msg:%s\n", err, err_msg);
		BIO_free_all(keybio);
        return decrypt_text;
	}
 
	int len = RSA_size(rsa);
	char *text = new char[len + 1];
	memset(text, 0, len + 1);
	// 对密文进行解密
	int ret = RSA_private_decrypt(256, (const unsigned char*)cipher_text, (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0) {
		decrypt_text.append(std::string(text, ret));
	}
 
	// 释放内存  
	delete text;
	BIO_free_all(keybio);
	RSA_free(rsa);
 
	return decrypt_text;
}
/*计算SHA256哈希*/
string SHA256_Encrypt(const string text){
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	int point = 0;
	int length = text.length();
	int times = length /1024;
	string temp;
	unsigned char md[33];
	memset(md, 0, 33);
	for(int i = 0; i < times; i++){
		temp = text.substr(point, 1024);
		SHA256_Update(&ctx, temp.c_str(), 1024);
		point += 1024;
	}
	temp = text.substr(point, length - point);
	SHA256_Update(&ctx, temp.c_str(), temp.length());
	SHA256_Final(md, &ctx);
	temp = (char*)md;
	return temp;
}
/*计算SHA256哈希*/
char* SHA256Encrypt(const string text){
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	int point = 0;
	int length = text.length();
	int times = length /1024;
	string temp;
	unsigned char md[33];
	memset(md, 0, 33);
	for(int i = 0; i < times; i++){
		temp = text.substr(point, 1024);
		SHA256_Update(&ctx, temp.c_str(), 1024);
		point += 1024;
	}
	temp = text.substr(point, length - point);
	SHA256_Update(&ctx, temp.c_str(), temp.length());
	SHA256_Final(md, &ctx);
	return (char*)md;
}
/*字符转化为16进制*/
string stringToHex(const string& str) 
{
    string result="";
    string tmp;
    stringstream ss;
    for(int i=0;i<str.size();i++)
    {
        ss<<hex<<int(str[i])<<endl;
        ss>>tmp;
        if(tmp.length() == 8){
			result += tmp.substr(6,2);
		}
		else if(tmp.length() == 1){
			result += "0";
			result += tmp;
		}
		else{
			result+=tmp;
		}
    }
    return result;
}
/*CBC模式下的AES加密，重置消息长度
enc = 1， 为加密模式
enc = 0， 为解密模式*/
char* AES_CBC_Encrypt(const char*str, int &length, const string &user_key, const string &ivec, int enc){
	if(enc == 1){
		size_t leng = ((length + AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;  //对齐分组
		length = leng;
		unsigned char userkey[AES_BLOCK_SIZE];
 		unsigned char *iv = (unsigned char *)malloc(AES_BLOCK_SIZE);
  		unsigned char *encrypt_result = (unsigned char *)malloc(leng);
  		AES_KEY en_key;
  		memset((char*)userkey,'k',AES_BLOCK_SIZE);
 		memset((unsigned char*)iv,'0',AES_BLOCK_SIZE);
  		memset((unsigned char*)encrypt_result, 0, leng);	
		user_key.copy((char*)userkey, user_key.length(), 0);
		ivec.copy((char*)iv, ivec.length(), 0);
		AES_set_encrypt_key(userkey, AES_BLOCK_SIZE*8, &en_key);	
		AES_cbc_encrypt((const unsigned char*)str, encrypt_result, leng, &en_key, iv, AES_ENCRYPT);
		return (char*)encrypt_result;
	}
	else if(enc == 0){
		size_t leng = ((length + AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;  //对齐分组
		length = leng;
		unsigned char userkey[AES_BLOCK_SIZE];
 		unsigned char *iv = (unsigned char *)malloc(AES_BLOCK_SIZE);
  		unsigned char *decrypt_result = (unsigned char *)malloc(leng);
  		AES_KEY de_key;
  		memset((char*)userkey,'k',AES_BLOCK_SIZE);
 		memset((unsigned char*)iv,'0',AES_BLOCK_SIZE);
  		memset((unsigned char*)decrypt_result, 0, length);	
		user_key.copy((char*)userkey, user_key.length(), 0);
		ivec.copy((char*)iv, ivec.length(), 0);
		AES_set_decrypt_key(userkey, AES_BLOCK_SIZE*8, &de_key);	
		AES_cbc_encrypt((const unsigned char*)str, decrypt_result, leng, &de_key, iv, AES_DECRYPT);
		return (char*)decrypt_result;
	}
}
/*产生随机字符串*/
string StringRand(int length){
	srand(time(0));
	string rand_str;
	for(int i = 0; i < length; i++){
		int tmp = rand() % 128 + 1;
		rand_str += (char)tmp;
	}
	return rand_str;
}
 

/*int main(int argc, char**argv) {
  if(argc != 2) {
    printf("使用方法为：\n./cbc text\ntext为待加密的明文。\n");
    return -1;
  }

  unsigned char *data = (unsigned char*)argv[1];
  printf("原始数据：%s\n",data);

  size_t len = strlen((char*)data);
  printf("明文长度：%d\n",len);
  size_t length = ((len+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;  //对齐分组

  unsigned char userkey[AES_BLOCK_SIZE];
  unsigned char *iv1 = (unsigned char *)malloc(AES_BLOCK_SIZE);
  unsigned char *iv2 = (unsigned char *)malloc(AES_BLOCK_SIZE);
  unsigned char *encrypt_result = (unsigned char *)malloc(length);
  unsigned char *decrypt_result = (unsigned char *)malloc(length);
  AES_KEY en_key;
  AES_KEY de_key;
  memset((char*)userkey,'k',AES_BLOCK_SIZE);
  memset((unsigned char*)iv1,'m',AES_BLOCK_SIZE);
  memset((unsigned char*)iv2,'m',AES_BLOCK_SIZE);
  memset((unsigned char*)encrypt_result, 0, length);
  memset((unsigned char*)decrypt_result, 0, length);

  cout << userkey << endl;
  cout << iv1 << endl;
  cout << iv2 << endl;

  AES_set_encrypt_key(userkey, AES_BLOCK_SIZE*8, &en_key);
  printf("加密密钥：%d\n",en_key);
  AES_cbc_encrypt(data, encrypt_result, len, &en_key, iv1, AES_ENCRYPT);
  printf("加密结果：%s\n",encrypt_result);

  AES_set_decrypt_key(userkey, AES_BLOCK_SIZE*8, &de_key);
  printf("解密密钥：%d\n",de_key);
  AES_cbc_encrypt(encrypt_result, decrypt_result, len, &de_key, iv2, AES_DECRYPT);
  printf("解密结果：%s\n",decrypt_result);
}*/

/*int main(void){
	string str = "helloworld123456qwefqdscqefqveqecscqefqwcq";
	string user_key = "mmmmmmmmmmmmmmm";
	string ivec = "kkkkkkkkkkkkkkk";
	int length = ((str.length()+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;
	char* cipher = (char*)malloc(length);
	char* result = (char*)malloc(length);
	memset(cipher, 0, length);
	memset(result, 0, length);
	cipher = AES_CBC_Encrypt(str, user_key, ivec, AES_ENCRYPT);
	result = AES_CBC_Encrypt(cipher, user_key, ivec, AES_DECRYPT);
	printf("%s %d\n", cipher, strlen(cipher));
	printf("%s %d", result, strlen(result));
	return 0;
}*/

/*int main(void){
	string a;
	cin >> a;
	string b = SHA256_Encrypt(a);
	cout << b << endl;
	cout << b.length() << endl;
	return 0;
}*/