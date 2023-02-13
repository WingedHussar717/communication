#include<iostream>
#include<stdio.h>
#include<stdlib.h>
#include <fstream>
#include<sstream>
#include<math.h>
#include<string>
#include<cstring>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/sha.h>
#include<openssl/aes.h>
#include<openssl/err.h>

using namespace std;

/*随机产生RSA公私钥*/
void GenerateRSAKey(std::string & out_pub_key, std::string & out_pri_key);
/*RSA私钥加密*/
string RsaPriEncrypt(const std::string &clear_text, std::string &pri_key);
/*RSA公钥加密*/
string RsaPubEncrypt(const std::string &clear_text, std::string &pub_key);
/*RSA私钥解密*/
string RsaPriDecrypt(const std::string & cipher_text, const std::string & pri_key);
/*RSA私钥解密*/
string RsaPriDecrypt(const char* cipher_text, const std::string & pri_key);
/*RSA公钥解密*/
string RsaPubDecrypt(const std::string & cipher_text, const std::string & pub_key);
/*计算SHA256哈希*/
string SHA256_Encrypt(const string text);
/*计算SHA256哈希*/
char* SHA256Encrypt(const string text);
/*字符转化为16进制*/
string stringToHex(const string& str);
/*CBC模式下的AES加密*/
char* AES_CBC_Encrypt(const char* str, int &length, const string &user_key, const string &ivec, int enc);
/*产生随机字符串*/
string StringRand(int length);