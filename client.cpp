#include "client.h"

using namespace std;

/*服务器初始化*/
Client::Client(){
    m_sockfd = -1;
    memset(m_ip, 0, sizeof(m_ip));
    m_port = 0;
    memset(session_key, 0, 33);
}
/*关闭socket*/
Client::~Client(){
    if(m_sockfd>0) close(m_sockfd);
    m_sockfd = -1;
    m_port = 0;
}

/*连接服务器*/
bool Client::Connectn(const char *ip, int port){
    //复制ip及端口
    strcpy(m_ip, ip);
    m_port=port;
    //创建地址结构
    struct hostent* h;
    struct sockaddr_in servaddr;
    //设置连接socket
    if ( (m_sockfd = socket(AF_INET,SOCK_STREAM,0) ) < 0) return false;
        if ( !(h = gethostbyname(m_ip)) )
    {
        close(m_sockfd);  m_sockfd = -1; return false;
    } 
    //初始化连接socket
    memset(&servaddr,0,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(m_port);  // 指定服务端的通讯端口
    memcpy(&servaddr.sin_addr,h->h_addr,h->h_length);
    //连接服务器
    connect(m_sockfd, (struct sockaddr *)&servaddr,sizeof(servaddr));
     return true;
}

/*发送消息*/
int Client::Send(int fd, const char *message){
    int leng = strlen(message);
    int length = htonl(leng);
    char *buffer;
    buffer = (char*)malloc(strlen(message) + 4);
    memset(buffer, 0, leng);
    int nleft, idx, nwritten;
    memcpy(buffer, &length, 4);
    memcpy(buffer + 4, message, leng);
    nleft = leng + 4;
    idx = 0;
    while(nleft > 0){
        if((nwritten = send(fd, buffer + idx, nleft, 0)) <= 0){
            return -1;
        }
        nleft -= nwritten;
        idx += nwritten;
    }
    return nwritten;
}

/*接受消息*/
char* Client::Recv(int fd){
    int nleft, nread, idx;
    int *length = (int*)malloc(sizeof(int));
    int leng;
    recv(fd, length, 4, 0);
    leng = ntohl(*length) + 1;
    char* buffer;
    buffer = (char *)malloc(leng + 1);
    memset(buffer, 0, leng);
    nleft = leng - 1;
    nread = 0;
    idx = 0;
    while(nleft > 0){
        if((nread = recv(fd, buffer + idx, nleft, 0)) <= 0){
            break;
        }
        idx += nread;
        nleft -= nread;
    }
    return buffer;
}

/*注册，已弃用*/
bool Client::Register(){
    string pub_key, pri_key;
    GenerateRSAKey(pub_key, pri_key);
    
}

/*交换会话密钥*/
bool Client::ExchSessionKey(){
    string pub_key, pri_key;
    string sess_key;
    char *cipher = (char*)malloc(256);
    /*产生RSA公私钥对，
    发送公钥*/
    GenerateRSAKey(pub_key, pri_key);
    Send(m_sockfd, pub_key.c_str());
    /*接受会话密钥密文，
    回送信息*/
    while(1){
        recv(m_sockfd, cipher, 256, 0);
        //cout << strlen(cipher) << endl;
        if(strlen(cipher) == 256){//接受会话密钥成功，回送成功
            Send(m_sockfd, "ok");
            break;
        }
        Send(m_sockfd, "nook");//回送失败，继续接受
    }
    /*解密会话密钥，
    保存*/
    sess_key = RsaPriDecrypt(cipher, pri_key);
    printf("xray = %d\n", sess_key.length());
    sess_key.copy(session_key, 32, 0);
}

/*安全发送*/
bool Client::SecureSend(int fd, const char* message){
    int length;
    /*计算消息长度*/
    length = strlen(message);
    /*使用会话密钥对消息进行对称加密，重置消息长度*/
    char *cipher = AES_CBC_Encrypt(message, length, session_key, " ", AES_ENCRYPT);
    
    /*将消息长度转化为网络字节序*/
    int leng = htonl(length);

    /*组装消息
    前4字节为消息长度
    后为消息加密内容*/
    char *buffer = (char*)malloc(length + 4);
    memset(buffer, 0, length + 4);
    int nleft, idx, nwritten;
    memcpy(buffer, &leng, 4);//拼装消息头
    memcpy(buffer + 4, cipher, length);//拼装消息内容
    nleft = length + 4;
    idx = 0;
    while(nleft > 0){//发送消息，超过缓冲区则多次发送
        if((nwritten = send(fd, buffer + idx, nleft, 0)) <= 0){
            return -1;
        }
        nleft -= nwritten;
        idx += nwritten;
    }
    return nwritten;
}

bool Client::SecureSend(int fd, const char* message, int length){
    char *cipher = AES_CBC_Encrypt(message, length, session_key, " ", AES_ENCRYPT);
    int leng = htonl(length);
    char *buffer = (char*)malloc(length + 4);
    memset(buffer, 0, length + 4);
    int nleft, idx, nwritten;
    memcpy(buffer, &leng, 4);
    memcpy(buffer + 4, cipher, length);
    nleft = length + 4;
    idx = 0;
    while(nleft > 0){
        if((nwritten = send(fd, buffer + idx, nleft, 0)) <= 0){
            return -1;
        }
        nleft -= nwritten;
        idx += nwritten;
    }
    free(cipher);
    free(buffer);
    return nwritten;
}

/*安全接收*/
char* Client::SecureRecv(int fd){
    int nleft, nread, idx;
    int *length = (int*)malloc(sizeof(int));
    int leng;
    /*获取消息头*/
    if(recv(fd, length, 4, 0) <= 0){
        return NULL;
    }
    /*将消息头转化为主机字节序，即为消息长度*/
    leng = ntohl(*length) + 1;
    char *buffer;
    buffer = (char*)malloc(leng);
    memset(buffer, 0, leng);
    nleft = leng - 1;
    nread = 0;
    idx = 0;
    /*获取消息，若错过缓冲区则多次获取*/
    while(nleft > 0){
        if((nread = recv(fd, buffer + idx, nleft, 0)) <= 0){
            break;
        }
        idx += nread;
        nleft -= nread;
    }
    /*解密消息，返回解密消息*/
    char *text = AES_CBC_Encrypt(buffer, leng, session_key, " ", AES_DECRYPT);
    return text;
}

/*处理入口*/
int Client::Screen(){
    ExchSessionKey();
    int command;
    /*0 = 退出登陆
    1 = 注册
    2 = 登录*/
    printf("input 0, quit program\n");
    printf("input 1, register\n");
    printf("input 2, logged in\n");
    scanf("%d", &command);
    if(command == 0){//quit
        return -1;
    }else if(command == 1){//register
        /*交换会话密钥*/
        //ExchSessionKey();
        string user_name;
        string user_code;
        /*获取用户名，密码*/
        char* name = (char*)malloc(20);
        char* code = (char*)malloc(65);
        memset(name, 0, 21);
        memset(code, 0, 65);
        char *message = (char*)malloc(86);
        printf("input user's name (maximun of 20 letters\n");
        cin >> user_name;
        printf("input usercode\n");
        cin >> user_code;
        user_name.copy(name, 20, 0);
        /*计算密码哈希
        并转换进制*/
        code = SHA256Encrypt(user_code);
        string tmp = stringToHex(code);
        /*拼装消息*/
        tmp.copy(code, 64, 0);
        memset(message, '1', 1);
        memcpy(message + 1, name, 20);
        memcpy(message + 21, code, 65);
        SecureSend(m_sockfd, message, 86);
        /*接收回送消息*/
        char *backmeg = SecureRecv(m_sockfd);
        if(strcmp(backmeg, "register error") != 0){//注册失败
            printf("%s\n", backmeg);
            return -1;
        }
        printf("%d\n", atoi(backmeg));//注册成功，打印服务器分发的UID
    }else if(command == 2){//loggedin
        /*交换会话密钥*/
        //ExchSessionKey();
        string tmp;
        /*获取登录uid和密码*/
        printf("input uid:\n");
        cin >> command; // temp use as uid
        uid = command;
        printf("input usercode\n");
        cin >> tmp; // usercode
        char *temp = (char*)malloc(65);
        memset(temp, 0, 65);
        /*计算密码哈希
        并转换进制*/
        temp = SHA256Encrypt(tmp);
        tmp = stringToHex(temp);
        char* message = (char *)malloc(77);
        memset(message, 0, 77);
        memset(message, '2', 1);
        /*拼装消息*/
        sprintf(message + 1, "%010d", command);
        tmp.copy(temp, 65, 0);
        memcpy(message + 11, temp, 65);
        memset(message + 75, 0, 1);
        printf("%s\n", message);
        SecureSend(m_sockfd, message);
        /*接收回送消息*/
        char* backmeg = SecureRecv(m_sockfd);
        if(strcmp(backmeg, "failed logged") == 0){//登录失败
            printf("error uid or code\n");
            return -1;
        }else{
            printf("%s\n", backmeg);//登录成功
        }
    }else{
        //error input, quit
        return -1;
    }
    while(1){
        /*0 = 退出
        3 = 发送消息
        4 = 检查收到的聊天消息
        5 = 接收SID发送的聊天消息*/
        printf("input 0, quit\n");
        printf("input 3, send message\n");
        printf("input 4, check mails\n");
        printf("input 5, read mails\n");
        scanf("%d", &command);
        if(command == 0){
            return -1;
        }else if(command == 3){
            int RID;
            char *message = (char*)malloc(256);
            memset(message, 0, 256);
            printf("input RecvUID\n");
            scanf("%d", &RID);
            printf("input message\n");
            scanf("%s", message);
            SendRecord(RID, message);
        }else if(command ==4){
            CheckMail();
        }else if(command == 5){
            int SID;
            printf("input SID\n");
            scanf("%d", &SID);
            ReadMail(SID);
        }
    }
}

/*发送聊天消息*/
bool Client::SendRecord(int RID, char *message){
    char *buffer = (char*)malloc(297);
    memset(buffer, 0, 297);
    time_t tmp_time;
    time(&tmp_time);
    buffer[0] = '3';
    sprintf(buffer  + 1, "%010d", uid);
    sprintf(buffer + 11, "%010d", RID);
    sprintf(buffer + 21, "%020d", tmp_time);
    sprintf(buffer + 41, "%s", message);
    SecureSend(m_sockfd, buffer);
    free(buffer);
}

/*请求获取收到的聊天消息*/
bool Client::CheckMail(){
    char *buffer = (char*)malloc(2);
    memset(buffer, 0, 2);
    buffer[0] = '4';
    SecureSend(m_sockfd, buffer);
    free(buffer);
    char *message = SecureRecv(m_sockfd);
    char *tmp = (char*)malloc(11);
    memset(tmp, 0, 11);
    memcpy(tmp, message, 10);
    int message_total_num = atoi(tmp);
    if(message_total_num == 0){
        printf("Nobody send message to you\n");
    }else{
        int cursor = 10;
        for(int i = 0; i < message_total_num; i++){
            int SID, message_num;
            memcpy(tmp, message + cursor, 10);
            SID = atoi(tmp);
            cursor += 10;
            memcpy(tmp , message + cursor, 10);
            message_num = atoi(tmp);
            cursor += 10;
            printf("UID = %d send %d message to you.\n", SID, message_num);
        }
    }
    free(tmp);
}

/*请求获取SID发送的聊天消息*/
bool Client::ReadMail(int SID){
    char *buffer = (char*)malloc(12);
    memset(buffer, 0, 12);
    buffer[0] = '5';
    sprintf(buffer + 1, "%010d", SID);
    SecureSend(m_sockfd, buffer);
    free(buffer);
    char *message = SecureRecv(m_sockfd);
    if(strcmp(message, "No message") == 0){
        printf("No message\n");
    }else{
        int message_total_num = atoi(message);
        printf("%d send %d messages to you\n", SID, message_total_num);
        for(int i = 0; i < message_total_num; i++){
            message = SecureRecv(m_sockfd);
            char *tmp_time = (char*)malloc(21);
            char *tmp_msg = (char*)malloc(256);
            memset(tmp_time, 0, 21);
            memset(tmp_msg, 0, 256);
            memcpy(tmp_time, message, 20);
            memcpy(tmp_msg, message + 20, 256);
            time_t t = atol(tmp_time);
            printf("%s: %s\n", ctime(&t), tmp_msg);
            free(tmp_msg);
            free(tmp_time);
        }
    }
}

int main(int argc ,char*argv[]){
    Client client;
    client.Connectn(argv[1], atoi(argv[2]));
    client.Screen();
}

/*int main(int argc ,char*argv[]){
    Client client;
    client.Connectn(argv[1], atoi(argv[2]));
    string pub_key, pri_key;
    string sess_key;
    char *cipher1 = (char*)malloc(256);
    GenerateRSAKey(pub_key, pri_key);
    client.Send(client.m_sockfd, pub_key.c_str());
    while(1){
        recv(client.m_sockfd, cipher1, 256, 0);
        if(strlen(cipher1) == 256){
            client.Send(client.m_sockfd, "ok");
            break;
        }
        client.Send(client.m_sockfd, "nook");
    }
    sess_key = RsaPriDecrypt(cipher1, pri_key);
    sess_key.copy(client.session_key, 32, 0);

    char *tmp_meg = (char*)malloc(11);
    memset(tmp_meg, 'a', 11);
    tmp_meg[10] = 0;
    tmp_meg[5] = 0;
    client.SecureSend(client.m_sockfd, tmp_meg, 11);
}*/
