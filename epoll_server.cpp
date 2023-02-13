#include"epoll_server.h"

using namespace std;

Server server;
thread_pool *n_pool;

unordered_map<int, int> fd_uid; //套接字-uid映射
unordered_map<int, char*> session_key;// 套接字-会话密钥映射

Server::Server(){
    listenfd = -1;
    connfd = -1;
    m_socklen = 0;
    max_event = MAX_EVENT;
    //连接数据库
    sql_server.ConnectDatabase();
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
    //设置监听，队列长度1024
    if (listen(listenfd, 1024) != 0 )
    {
       return false;
    }

    //创建epoll对象，设置监听fd边缘触发
    epollfd = epoll_create(max_event);
    ev_create.events = EPOLLET | EPOLLIN;
    ev_create.data.fd = listenfd;
    memset(ev_ready, 0, sizeof(struct epoll_event) * MAX_READY_EVENT);
    //注册监听事件
    epoll_ctl(epollfd, EPOLL_CTL_ADD, listenfd, &ev_create);
    //socket地址长度
    m_socklen = sizeof(struct sockaddr_in);
}

/*设置socket连接为非阻塞模式*/
void Server::SetNonblocking(int sockfd){
    //获取sockfd的状态
    int opts = fcntl(sockfd, F_GETFL);
    if(opts < 0){
        perror("fcntl F_GETFL error\n");
        exit(1);
    }

    //设置sockfd为非阻塞
    opts = (opts | O_NONBLOCK);
    if(fcntl(sockfd, F_SETFL, opts) < 0){
        perror("fcntl F_SETFL error\n");
        exit(1);
    }
}

/*注册，登录*/
bool LoggedIn(char *message, int fd){
    int mode; //mode = 0, register; mode =  1, logged in
    mode = message[0] - '0';    
    if(mode == 1){ // 注册
        char *user_name = (char*)malloc(21);
        char *user_code = (char*)malloc(65);
        memset(user_name, 0, 21);
        memset(user_code, 0, 65);
        int uid = server.sql_server.user_num;
        memcpy(user_name, message + 1, 20);
        memcpy(user_code, message + 21, 64);
        /*数据库插入用户信息*/
        if(server.sql_server.InsertUser(user_name, user_code) != 0){ // suceed in register
            char *backmeg = (char*)malloc(11);
            memset(backmeg, 0,  11);
            sprintf(backmeg, "%010d", uid);
            SecureSend(fd, backmeg);//回送服务器分发的uid
            fd_uid[fd] = uid;
            free(backmeg);
            return true;
        }else{ // fail to register
            char *backmeg = "register error";
            SecureSend(fd, backmeg);
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
        if(server.sql_server.VeriftUser(uid, code) != 0){//
            char *backmeg = (char*)malloc(22);
            memset(backmeg, 0, 22);
            sprintf(backmeg, "%010d", uid);
            strcpy(backmeg + 10, " logged in");
            fd_uid[fd] = uid;
            SecureSend(fd, backmeg);//回送登录成功消息
            free(backmeg);
            return true;
        }else{ // fail to register
            char *backmeg = "failed logged";
            SecureSend(fd, backmeg);//回送登录失败消息
            return false;
        }
    }
}

/*交换会话密钥*/
bool Server::ExchSessionKey(int fd){
    /*接收公钥*/
    string pub_key = Recv(fd);
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
        send(fd, cipher.c_str(), 256, 0);
        short_meg = Recv(fd);
        if(strcmp(short_meg, "ok") == 0){
            break;
        }
    }
    /*保存会话密钥*/
    char *temp_ptr = (char*)malloc(33 * sizeof(char));
    memset(temp_ptr, 0, 33);
    sess_key.copy(temp_ptr, 32, 0);
    session_key[fd] = temp_ptr;
    printf("xray = %d\n", strlen(temp_ptr));
    return true;
}


/*接受消息*/
char* Server::Recv(int fd){
    int nleft, nread, idx;
    int *length = (int*)malloc(sizeof(int));
    int leng;
    int tmp;
    char* buffer;

    //循环读取，避免边缘触发导致的漏读
    while(1){
        tmp = recv(fd, length, 4, 0);
        if(tmp < 0){ //读取错误或无数据，循环读取
            continue;
        }else{ //连接断开，跳出循环
            break;
        }
    }

    //接收消息头
    leng = ntohl(*length) + 1;
    buffer = (char *)malloc(leng);
    memset(buffer, 0, leng);
    nleft = leng - 1;
    nread = 0;
    idx = 0;

    //读取消息
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

/*查询数据库，向RID发送给SID聊天信息，调用SecureSend()*/
bool SendRecords(int fd, int SID, int RID){
    if(server.sql_server.GetRecord(SID, RID) == false){//查询数据库失败
        char *message = (char*)malloc(11);
        memset(message, 0, 11);
        strcpy(message, "No message");
        SecureSend(fd, message);//回送失败消息
        free(message);
    }else{//查询数据库成功
        int row_number = mysql_num_rows(server.sql_server.res);//聊天信息条数
        /*发送聊天消息条数*/
        char *message = (char*)malloc(276);
        memset(message, 0, 276);
        sprintf(message, "%010d", row_number);
        printf("%s\n", message);
        SecureSend(fd, message);
        /*循环发送聊天消息*/
        for(int i = 0; i < row_number; i++){
            server.sql_server.row = mysql_fetch_row(server.sql_server.res);
            memset(message, 0, 276);
            sprintf(message, "%020d", atoi(server.sql_server.row[2]));
            strcpy(message + 20, server.sql_server.row[3]);
            printf("%s %s\n", message, message + 20);
            SecureSend(fd, message);
        }
        free(message);
    }
   server.sql_server.DeleteRecord(SID, RID);
}

/*查询数据库，向RID发送所收聊天信息*/
bool SendRecordsNumber(int fd, int RID){
    if(server.sql_server.GetRecordNumber(RID) == false){//查询数据库失败
        char *message = (char*)malloc(11);
        memset(message, 0, 11);
        sprintf(message, "%010d", 0);
        //printf("%s\n", message);
        SecureSend(fd, message);//回送失败消息
        free(message);
    }else{//查询数据库成功
        int row_number = mysql_num_rows(server.sql_server.res);
        char *message = (char*)malloc(10 * (row_number * 2 + 1) + 1);
        memset(message, 0, 10 * (row_number * 2 + 1) + 1);
        int cursor = 10;
        int tmp;
        sprintf(message, "%010d", row_number);
        for(int i = 0; i < row_number; i++){//拼装SID和消息数量
            server.sql_server.row = mysql_fetch_row(server.sql_server.res);
            tmp = atoi(server.sql_server.row[0]);
            sprintf(message + cursor, "%010d", tmp);
            cursor += 10;
            tmp = atoi(server.sql_server.row[1]);
            sprintf(message + cursor, "%010d", tmp);
            cursor += 10;
        }
        //printf("%s %d %d\n", message, strlen(message), 10 * (row_number  * 2 + 1) + 1);
        /*安全发送消息*/
        SecureSend(fd, message);
        free(message);
    }
}

/*接受聊天信息，插入数据库*/
bool RecvRecords(int fd, char* message){
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
    server.sql_server.InsertRecord(SID, RID, time, record);
    
    free(record);
    free(tmp_ID);
    free(tmp_time);
}

/*消息处理函数*/
bool message_process(int fd){
    //读取信息
    char *message = SecureRecv(fd);
    if(message == NULL){
        return false;
    }

    //判断消息头
    if(message[0] == '1' || message[0] == '2'){
        LoggedIn(message, fd);
    }else if(message[0] == '3'){
        RecvRecords(fd, message + 1);
    }else if(message[0] == '4'){
        SendRecordsNumber(fd, fd_uid[fd]);
    }else if(message[0] == '5'){
        char *tmp_SID = (char*)malloc(11);
        memset(tmp_SID, 0, 11);
        memcpy(tmp_SID, message + 1, 10);
        SendRecords(fd, atoi(tmp_SID), fd_uid[fd]);
    }
}

/*安全发送*/
bool SecureSend(int fd, const char* message){
    int length;
    /*计算消息长度*/
    length = strlen(message);
    /*使用会话密钥对消息进行对称加密，重置消息长度*/
    char *cipher = AES_CBC_Encrypt(message, length, session_key[fd], " ", AES_ENCRYPT);
    
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
char* SecureRecv(int fd){
    int nleft, nread, idx;
    int *length = (int*)malloc(sizeof(int));
    int leng;
    char *buffer;
    /*循环获取消息头，避免ET漏读*/
    while(1){
        int tmp = recv(fd, length, 4, 0);
        if(tmp == 0){//连接断开
            epoll_ctl(server.epollfd, EPOLL_CTL_DEL, fd, NULL);//删除连接
            printf("client(eventfd = %d) disconnected\n", fd);
            close(fd);
            return NULL;
        }else if(tmp < 0){//读取错误或无消息
            if(errno == EINTR){
                continue;
            }else{
                return NULL;
            }
        }else{//正常读取
            leng = ntohl(*length) + 1;
            buffer = (char*)malloc(leng);
            memset(buffer, 0, leng);
            nleft = leng - 1;
            leng = leng - 1;
            nread = 0;
            idx = 0;
            break;
        }
    }
    /*读取消息*/
    while(nleft > 0){
        if((nread = recv(fd, buffer + idx, nleft, 0)) == 0){//连接断开
            epoll_ctl(server.epollfd, EPOLL_CTL_DEL, fd, NULL);
            printf("client(eventfd = %d) disconnected\n", fd);
            close(fd);
            break;
        }else if(nread < 0){//连接错误或无消息
            if(errno == EINTR){
                continue;
            }else{
                break;
            }
        }else{
            idx += nread;
            nleft -= nread;
        }
    }
    /*解密消息，返回解密消息*/
    char *text = AES_CBC_Encrypt(buffer, leng, session_key[fd], " ", AES_DECRYPT);
    free(buffer);
    free(length);
    return text;
}

int main(int argc, char *argv[]){
    server.InitServer(atoi(argv[1]));
    n_pool = n_pool->thread_pool_create(4, 20);
    while(1){
        int infds = epoll_wait(server.epollfd, server.ev_ready, 100, -1);
        for(int i = 0; i < infds; i++){
            if( (server.ev_ready[i].events & EPOLLERR) || (server.ev_ready[i].events & EPOLLHUP) || (!(server.ev_ready[i].events & EPOLLIN)) ){
                close(server.ev_ready[i].data.fd);
                continue;
            }else if(server.ev_ready[i].data.fd == server.listenfd){
                    socklen_t len = sizeof(server.m_clientaddr);
                    server.connfd = accept(server.listenfd, (struct sockaddr*)&server.m_clientaddr, &len);//获取连接上来的Socket
                    server.SetNonblocking(server.connfd);//设置新连接为非阻塞
                    server.ev_create.events = EPOLLIN | EPOLLET;//设置新连接为边缘触发
                    server.ev_create.data.fd = server.connfd;
                    printf("client(socket = %d) connected\n", server.connfd);
                    /*更新会话密钥*/
                    server.ExchSessionKey(server.connfd);
                    //新连接加入监听
                    epoll_ctl(server.epollfd, EPOLL_CTL_ADD, server.connfd, &server.ev_create);
            }else{
                //连接有消息，向线程池发布任务
                n_pool->thread_pool_post(n_pool, NULL, server.ev_ready[i].data.fd);
            }
        }
    }
}