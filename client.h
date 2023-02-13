#include<iostream>
#include<stdio.h>
#include<string>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>
#include<unistd.h>
#include"security.h"
#include"m_time.h"

using namespace std;

class Client{
    public:
    int m_sockfd;//服务器socket
        char m_ip[21];//服务器ipv4地址
        int m_port;//服务器端口
        char session_key[33];
        int uid;
        /*服务器初始化*/
        Client();
        /*关闭socket*/
        ~Client();

        /*连接服务器*/
        bool Connectn(const char *ip, const int port);
        
        /*发送消息*/
        int Send(int fd, const char *message);

        /*接受消息*/
        char *Recv(int fd);

        /* 登陆*/
        bool LogIn();
        
        /*注册，已弃用*/
        bool Register();

        /*交换会话密钥*/
        bool ExchSessionKey();

        /*安全发送*/
        bool SecureSend(int fd, const char* message);

        /*安全发送*/
        bool SecureSend(int fd, const char* message, int length);

        /*安全接收*/
        char* SecureRecv(int fd);

        /*处理入口*/
        int Screen();

        /*发送聊天消息*/
        bool SendRecord(int RID, char *message);

        /*请求获取收到的聊天消息*/
        bool CheckMail();

        /*请求获取SID发送的聊天消息*/
        bool ReadMail(int SID);
};