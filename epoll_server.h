#include<iostream>
#include<stdio.h>
#include<string>
#include<string.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>
#include<unistd.h>
#include<sys/epoll.h>
#include<unordered_map>
#include<fcntl.h>
#include"test_mysql.h"
#include"security.h"
#include"m_time.h"
#include"thread_pool.h"

using namespace std;

#define MAX_EVENT 10000
#define MAX_READY_EVENT 100

class Server{
    public:
        int m_socklen;//socket长度
        struct sockaddr_in m_clientaddr;//客户端的地址，端口信息
        struct sockaddr_in m_servaddr;//服务器的地址，端口信息
        int listenfd;//服务器监听socket
        int connfd;//服务器socket
        int max_event;//最大连接数
        int epollfd;//epoll的文件描述符
        struct epoll_event ev_create;
        struct epoll_event ev_ready[100];//注册事件、回传事件
        //unordered_map<int, int> fd_uid; //套接字-uid映射
        //unordered_map<int, char*> session_key;// 套接字-会话密钥映射
        SQL_Server sql_server;//数据库服务器
        /*服务器，数据库初始化*/
        Server();
        /*关闭监听Socket，断开和数据库服务器连接*/
        ~Server();

        /*服务器初始化，绑定端口*/
        bool InitServer(const unsigned int port);

        /*设置socket连接为非阻塞模式*/
        void SetNonblocking(int sockfd);

        /*接受连接，已弃用*/
        bool Accept();

        /*发送消息*/
        int Send(int fd, const char *message);

        /*接受消息*/
        char *Recv(int fd);



        /*交换会话密钥*/
        bool ExchSessionKey(int fd);
        /*消息处理，已弃用*/
        bool message_process(int fd, char *message);
        /*安全发送*/
        //bool SecureSend(int fd, const char* message);
        /*安全接收*/
        //char* SecureRecv(int fd);
        /*查询数据库，向RID发送给SID聊天信息，调用SecureSend()*/
        //bool SendRecords(int SID, int RID);
        /*查询数据库，向RID发送所收聊天信息*/
        //bool SendRecordsNumber(int RID);
        /*接受聊天信息，插入数据库*/
        //bool RecvRecords(char* message);

};

/*消息处理函数*/
bool message_process(int fd);
/*安全发送*/
bool SecureSend(int fd, const char* message);
/*安全接收*/
char* SecureRecv(int fd);
/*查询数据库，向RID发送给SID聊天信息，调用SecureSend()*/
bool SendRecords(int fd, int SID, int RID);
/*查询数据库，向RID发送所收聊天信息*/
bool SendRecordsNumber(int fd, int RID);
/*接受聊天信息，插入数据库*/
bool RecvRecords(int fd, char* message);
/*注册，登录*/
bool LoggedIn(char *message, int fd);