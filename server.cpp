#include"server.h"

using namespace std;

Server::Server(){
    listenfd = -1;
    connfd = -1;
    m_socklen = 0;
    //连接数据库
    sql_server.ConnectDatabase();
    //初始化select模型
    FD_ZERO(&readfdset);    
    for(int i = 0; i < 1030; i++){
        fd_uid[i] = -1;
    }
    memset(session_key, 0, 33);
}

Server::~Server(){
    /*关闭监听socket*/
    if(listenfd>0)
    {
        close(listenfd);
        listenfd = -1;
    }
    if(connfd > 0)
    {
        close(connfd);
        connfd = -1;
    }
    /*关闭数据库连接*/
    sql_server.DisconnectDatabase();
}

/*服务器初始化，绑定端口。
端口值port。*/
bool Server::InitServer(const unsigned int port){
    int opt;
    unsigned int len = sizeof(opt);
    //设置监听socket
    if( (listenfd = socket(AF_INET, SOCK_STREAM, 0)) <= 0 )return false;
    //使端口直接重复使用，不必time wait
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, len);

    /*初始化服务器地址结构*/
    memset(&m_servaddr, 0, sizeof(m_servaddr));
    //设置ipv4
    m_servaddr.sin_family = AF_INET;
    //设置自由ip地址
    m_servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    //设置端口
    m_servaddr.sin_port = htons(port);
    //端口绑定
    if (bind(listenfd,(struct sockaddr *)&m_servaddr,sizeof(m_servaddr)) != 0 )
    {
        return false;
    }
    //设置监听，队列长度5
    if (listen(listenfd, 1024) != 0 )
    {
       return false;
    }
    //socket地址长度
    m_socklen = sizeof(struct sockaddr_in);
    //加入监听socket
    FD_SET(listenfd, &readfdset);
    maxfd = listenfd;
    return true;
}

/*接受连接，已弃用*/
bool Server::Accept(){
    //未设置监听socket，返回错误
    if (listenfd == -1) return false;
    m_socklen = sizeof(struct sockaddr_in);
    //接受连接
    if((connfd = accept(listenfd, (struct sockaddr*)&m_clientaddr, (socklen_t*)&m_socklen))<0)
    {
        return false;
    }
    FD_SET(listenfd, &readfdset);
    maxfd = listenfd;
    return true;
}

/*发送消息，已弃用*/
int Server::Send(int fd, const char *message){
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
    free(buffer);
    return nwritten;
}

/*接受消息，已弃用*/
char* Server::Recv(int fd){
    int nleft, nread, idx;
    int *length = (int*)malloc(sizeof(int));
    int leng;
    recv(fd, length, 4, 0);
    leng = ntohl(*length) + 1;
    char* buffer;
    buffer = (char *)malloc(leng);
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
    free(length);
    return buffer;
}
/*注册，登录*/
bool Server::LoggedIn(char *message){
    int mode; //mode = 0, register; mode =  1, logged in
    mode = message[0] - '0';    
    if(mode == 1){ // 注册
        char *user_name = (char*)malloc(21);
        char *user_code = (char*)malloc(65);
        memset(user_name, 0, 21);
        memset(user_code, 0, 65);
        int uid = sql_server.user_num;
        memcpy(user_name, message + 1, 20);
        memcpy(user_code, message + 21, 64);
        /*数据库插入用户信息*/
        if(sql_server.InsertUser(user_name, user_code) != 0){ // suceed in register
            char *backmeg = (char*)malloc(11);
            memset(backmeg, 0,  11);
            sprintf(backmeg, "%010d", uid);
            SecureSend(connfd, backmeg);//回送服务器分发的uid
            fd_uid[connfd] = uid;
            free(backmeg);
            return true;
        }else{ // fail to register
            char *backmeg = "register error";
            SecureSend(connfd, backmeg);
            return false;
        }
        free(user_name);
        free(user_code);
    }else if(mode == 2){ // logged in
        char *temp_uid = (char*)malloc(11);
        char *code = (char*)malloc(65);
        memset(temp_uid, 0, 11);
        memset(code, 0, 65);
        memcpy(temp_uid, message + 1, 10);
        memcpy(code, message + 11, 65);
        printf("%s\n", message);
        int uid = atoi(temp_uid);
        /*验证用户身份*/
        if(sql_server.VeriftUser(uid, code) != 0){//
            char *backmeg = (char*)malloc(22);
            memset(backmeg, 0, 22);
            sprintf(backmeg, "%010d", uid);
            strcpy(backmeg + 10, " logged in");
            fd_uid[connfd] = uid;
            SecureSend(connfd, backmeg);//回送登录成功消息
            free(backmeg);
            return true;
        }else{ // fail to register
            char *backmeg = "failed logged";
            SecureSend(connfd, backmeg);//回送登录失败消息
            return false;
        }
    }
}

/*交换会话密钥*/
bool Server::ExchSessionKey(int fd){
    /*接收公钥*/
    string pub_key = Recv(connfd);
    string sess_key, cipher;
    char *short_meg;
    while(1){ 
        /*产生有效的会话密钥*/
        while(1){
            sess_key = StringRand(32);
            cipher = RsaPubEncrypt(sess_key, pub_key);
            if(cipher.length()  == 256){
                break;
             }
        }
        /*发送有效的会话密钥直至成功*/
        send(connfd, cipher.c_str(), 256, 0);
        short_meg = Recv(connfd);
        if(strcmp(short_meg, "ok") == 0){
            break;
        }
    }
    /*保存会话密钥*/
    sess_key.copy(session_key[this->connfd], 32, 0);
}
/*安全发送*/
bool Server::SecureSend(int fd, const char* message){
    int length;
    /*计算消息长度*/
    length = strlen(message);
    /*使用会话密钥对消息进行对称加密，重置消息长度*/
    char *cipher = AES_CBC_Encrypt(message, length, session_key[this->connfd], " ", AES_ENCRYPT);
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
    free(buffer);
    return nwritten;
}

/*安全接收*/
char* Server::SecureRecv(int fd){
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
    leng = leng - 1;
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
    char *text = AES_CBC_Encrypt(buffer, leng, session_key[this->connfd], " ", AES_DECRYPT);
    free(buffer);
    free(length);
    return text;
}

/*查询数据库，向RID发送给SID聊天信息，调用SecureSend()*/
bool Server::SendRecords(int SID, int RID){
    if(sql_server.GetRecord(SID, RID) == false){//查询数据库失败
        char *message = (char*)malloc(11);
        memset(message, 0, 11);
        strcpy(message, "No message");
        SecureSend(connfd, message);//回送失败消息
        free(message);
    }else{//查询数据库成功
        int row_number = mysql_num_rows(sql_server.res);//聊天信息条数
        /*发送聊天消息条数*/
        char *message = (char*)malloc(276);
        memset(message, 0, 276);
        sprintf(message, "%010d", row_number);
        printf("%s\n", message);
        SecureSend(connfd, message);
        /*循环发送聊天消息*/
        for(int i = 0; i < row_number; i++){
            sql_server.row = mysql_fetch_row(sql_server.res);
            memset(message, 0, 276);
            sprintf(message, "%020d", atoi(sql_server.row[2]));
            strcpy(message + 20, sql_server.row[3]);
            printf("%s %s\n", message, message + 20);
            SecureSend(connfd, message);
        }
        free(message);
    }
    sql_server.DeleteRecord(SID, RID);
}

/*查询数据库，向RID发送所收聊天信息*/
bool Server::SendRecordsNumber(int RID){
    if(sql_server.GetRecordNumber(RID) == false){//查询数据库失败
        char *message = (char*)malloc(11);
        memset(message, 0, 11);
        sprintf(message, "%010d", 0);
        //printf("%s\n", message);
        SecureSend(connfd, message);//回送失败消息
        free(message);
    }else{//查询数据库成功
        int row_number = mysql_num_rows(sql_server.res);
        char *message = (char*)malloc(10 * (row_number * 2 + 1) + 1);
        memset(message, 0, 10 * (row_number * 2 + 1) + 1);
        int cursor = 10;
        int tmp;
        sprintf(message, "%010d", row_number);
        for(int i = 0; i < row_number; i++){//拼装SID和消息数量
            sql_server.row = mysql_fetch_row(sql_server.res);
            tmp = atoi(sql_server.row[0]);
            sprintf(message + cursor, "%010d", tmp);
            cursor += 10;
            tmp = atoi(sql_server.row[1]);
            sprintf(message + cursor, "%010d", tmp);
            cursor += 10;
        }
        //printf("%s %d %d\n", message, strlen(message), 10 * (row_number  * 2 + 1) + 1);
        /*安全发送消息*/
        SecureSend(connfd, message);
        free(message);
    }
}

/*接受聊天信息，插入数据库*/
bool Server::RecvRecords(char* message){
    //printf("%s\n", message);
    int SID, RID;
    long time;
    char *record = (char*)malloc(256);//聊天消息
    memset(record, 0, 256);
    char *tmp_ID = (char*)malloc(11);//SID 或者 RID
    memset(tmp_ID, 0, 11);
    char *tmp_time = (char*)malloc(21);//发信时间
    memset(tmp_time, 0, 21);
    /*获取各个字段*/
    memcpy(tmp_ID, message, 10); 
    SID = atoi(tmp_ID);
    memcpy(tmp_ID, message + 10, 10); 
    RID = atoi(tmp_ID);
    memcpy(tmp_time, message + 20, 20);
    time = atol(tmp_time);
    strcpy(record, message + 40);
    /*插入聊天消息*/
    sql_server.InsertRecord(SID, RID, time, record);
    
    free(record);
    free(tmp_ID);
    free(tmp_time);
}

int main(int argc, char *argv[]){
    Server server;
    server.InitServer(atoi(argv[1]));
    //server.Accept();
    while(1){
        fd_set tmpfdset = server.readfdset;//复制监听fdset
        int infds = select(server.maxfd + 1, &tmpfdset, NULL, NULL, NULL);
        if(infds < 0){//返回失败
            printf("select()  failed\n");
            perror("select()");
            break;
        }
        else {//有可读的socket
            for(int eventfd = 0; eventfd <= server.maxfd; eventfd++){//轮询查找可读的socket
                if(FD_ISSET(eventfd, &tmpfdset) <= 0){//非可读socket，继续循环
                    continue;
                }
                if(eventfd == server.listenfd){//可读的socket为监听socket，处理新连接，交换密钥
                    socklen_t len = sizeof(server.m_clientaddr);
                    server.connfd = accept(server.listenfd, (struct sockaddr*)&server.m_clientaddr, &len);//获取连接上来的Socket
                    if(server.connfd < 0){
                        printf("accept failed\n");
                        continue;
                    }
                    printf("client(socket = %d) connected\n", server.connfd);
                    /*增加会话密钥交换
                    1.交换会话密钥
                    2.安全接受uid
                    3.安全接受UserCode
                    4.检验登陆
                    5.更新会话密钥*/
                    server.ExchSessionKey(server.connfd);
                    char *message = server.SecureRecv(server.connfd);
                    server.LoggedIn(message);
                    /*更新fdset，及maxfd*/
                    FD_SET(server.connfd, &server.readfdset);
                    if(server.maxfd < server.connfd){
                        server.maxfd = server.connfd;
                    }
                    continue;
                }
                else{//可读的为其他socket
                    /*安全接受消息*/
                    char *buffer = server.SecureRecv(eventfd);
                    if(buffer == NULL){//若缓冲区为空，则判断连接断开
                        printf("client(eventfd = %d) disconnected\n", eventfd);
                        close(eventfd);
                        /*将该socket置零*/
                        FD_CLR(eventfd, &server.readfdset);
                        /*重置socket最大上限*/
                        if(eventfd == server.maxfd){
                            for(int i = server.maxfd; i > 0; i--){
                                if(FD_ISSET(i, &server.readfdset)){
                                    server.maxfd = i;
                                    break;
                                }
                            }                            
                        }
                        continue;
                    }
                    else{
                        server.connfd = eventfd;
                        /*判断消息处理模式*/
                        if(buffer[0] == '1'){//获取connfd发送的聊天消息
                            server.RecvRecords(buffer + 1);
                        }else if(buffer[0] == '2'){//发送connfd对应的RID的消息数量
                            server.SendRecordsNumber(server.fd_uid[server.connfd]);
                        }else if(buffer[0] == '3'){//发送connfd对应RID和SID的消息
                            char *tmp_SID = (char*)malloc(11);
                            memset(tmp_SID, 0, 11);
                            memcpy(tmp_SID, buffer + 1, 10);
                            server.SendRecords(atoi(tmp_SID), server.fd_uid[server.connfd]);
                        }
                    }
                }
            }
        }
    }
}

/*int main(int argc ,char*argv[]){
    Server server;
    server.InitServer(atoi(argv[1]));
    char *message = (char*)malloc(296);
    sprintf(message, "%010d", 1);
    sprintf(message + 10, "%010d", 2);
    time_t t;
    time(&t);
    long x = t;
    printf("%d\n", x);
    sprintf(message + 20, "%020d", x);
    sprintf(message + 40, "%s", "sdfadfadsfadfasdf  df,.sdf");
    server.RecvRecords(message);
}*/

/*int main(int argc ,char*argv[]){
    Server server;
    server.InitServer(atoi(argv[1]));
    server.Accept();
    string pub_key = server.Recv(server.connfd);
    cout << pub_key.length() << endl;
    string sess_key;
    string cipher;
    char *short_meg;
    while(1){
        while(1){
            sess_key = StringRand(32);
            cipher = RsaPubEncrypt(sess_key, pub_key);
            if(cipher.length() == 256){
                cout << cipher.length() << endl;
                cout << stringToHex(cipher) << endl;
                break;
            }
            else{
                cout << "!" << endl;
            }
        }
        cout << send(server.connfd, cipher.c_str(), 256, 0);
        short_meg = server.Recv(server.connfd);
        cout << "short = " << short_meg << endl;
        if(strcmp(short_meg, "ok") == 0){
            cout << "OK " << endl;
            break;
        }
    }
    //sess_key.copy(server.session_key, 32, 0);
    char *text = server.SecureRecv(server.connfd);
    for(int i = 0; i < 11; i++){
        printf("%d ", text[i]);
    }
    cout << endl;
    return 0;
}*/