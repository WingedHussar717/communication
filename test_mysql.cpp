#include"test_mysql.h"
#include"security.h"

using namespace std;

/*连接到数据库*/
bool SQL_Server::ConnectDatabase(){
    user_num = 0;
    mysql_init(&mysql);
    const char host[] = "localhost";
	const char user[] = "root";
	const char psw[] = "ilxxy224";
	const char database[] = "user";
	const int port = 3306;
    if(mysql_real_connect(&mysql, host, user, psw, database, port, NULL, 0)){
        cout << "Connected..." << endl;
        return true;
    }else{
        cout << "Error connecting to database" << mysql_error(&mysql) << endl;
        return false;
    }
}

/*从数据库断开连接*/
void SQL_Server::DisconnectDatabase(){
    mysql_free_result(res);
    mysql_close(&mysql);
}

/*插入用户信息*/
bool SQL_Server::InsertUser(char* uname, const char *code){
    string message;
    message = "insert into user values ('" + to_string(user_num) + "' ,'" + uname + "' ,'" + code + "' ,'" + "');"; 
    printf("%s\n", message.c_str());
    if(mysql_query(&mysql, message.c_str())){
        printf("Query failed (%s)\n", mysql_error(&mysql));
        return false;
    }
    else{
        printf("Create new user!\n");
        user_num ++;
        return true;
    }
}

/*修改用户密码*/
bool SQL_Server::ModifyUserCode(int uid, char *old_code, char *new_code){
    string message;
    char *tmp = ProcessStr(old_code);
    char *temp = ProcessStr(new_code);
    message.append("update user set UserCode = '");
    message.append(temp);
    message.append("'");
    message.append(" where UserCode = '");
    message.append(tmp);
    message.append("';");
    //printf("%s\n", message.c_str());
    if(mysql_query(&mysql, message.c_str())){
        printf("Query failed (%s)\n", mysql_error(&mysql));
        return false;
    }
    else{
        printf("Succeed in editing\n");
        return true;
    }
}

/*验证用户信息*/
bool SQL_Server::VeriftUser(int uid, const char *code){
    string message;
    char *tmp = ProcessStr(code);
    message.append("select * from user where UserID = '");
    message.append(to_string(uid));
    message.append("' AND UserCode = '");
    message.append(tmp);
    message.append("';");
    printf("%s\n", message.c_str());
    if(mysql_query(&mysql, message.c_str())){
        printf("Query failed (%s)\n", mysql_error(&mysql));
        return false;
    }
    else{
        printf("Query success\n");
    }
    res = mysql_store_result(&mysql);
    //printf("affect rows = %d\n", mysql_affected_rows(&mysql));
    if(mysql_affected_rows(&mysql) == 1){
        printf("Verify success\n");
        return true;
    }
    else{
        printf("Verify failed\n");
        return false;
    }
}

/*插入聊天信息*/
bool SQL_Server::InsertRecord(int SID, int RID, long time, char *message){
    string query;
    query = "insert into chat_records values('" + to_string(SID) + "' ,'" + to_string(RID) + "' ,'" + to_string(time) + "', '" + message + "');";
    if(mysql_query(&mysql, query.c_str())){
        printf("Query failed (%s)\n", mysql_error(&mysql));
        return false;
    }
    else{
        printf("Insert records successfully!\n");
        return true;
    }
}

/*删除SID发送给RID的聊天信息*/
bool SQL_Server::DeleteRecord(int SID, int RID){
    string query;
    query = "delete from chat_records where RecvUID = '" + to_string(RID) + "' AND SendUID = '" + to_string(SID) + "';";
    if(mysql_query(&mysql, query.c_str())){
        printf("Query failed (%s)\n", mysql_error(&mysql));
        return false;
    }
    else{
        printf("Delete records successfully!\n");
        return true;
    }
}

/*获取SID发送给RID的聊天信息*/
bool SQL_Server::GetRecord(int SID, int RID){
    string query;
    query = "select * from chat_records where RecvUID = '" + to_string(RID) + "' AND SendUID = '" + to_string(SID) + "' order by time;";
    if(mysql_query(&mysql, query.c_str())){
        printf("Query failed (%s)\n", mysql_error(&mysql));
        return false;
    }
    else{
        printf("Query success\n");
    }
    res = mysql_store_result(&mysql);
    return true;
}

/*获取RID收到的聊天信息数量的SID*/
int SQL_Server::GetRecordNumber(int RID){
    string query;
    query = "select SendUID, count(SendUID) from chat_records where RecvUID = '" + to_string(RID) + "' group by SendUID"; 
    if(mysql_query(&mysql, query.c_str())){
        printf("Query failed (%s)\n", mysql_error(&mysql));
        return false;
    }
    else{
        printf("GetRecordNumber success\n");
    }
    res = mysql_store_result(&mysql);
    return true;
}

/*截取字符串*/
char *substr(char *str, int left_border, int length){
    if(length > strlen(str)){
        length = strlen(str);
    }
    char *buffer;
    buffer = (char *)malloc(length + 1);
    memset(buffer, 0, length + 1);
    for(int i = 0; i < length; i++){
        buffer[i] = str[i + left_border];
    }
    return buffer;
}

/*字符串处理，将 ' 替换为 “ */
char *ProcessStr(const char* str){
    int length = strlen(str);
    char* temp_str = (char*)malloc(length + 1);
    temp_str[length] = 0;
    for(int i = 0; i < length; i++){
        if(str[i] == 39){
            temp_str[i] = '"';
        }else{
            temp_str[i] = str[i];
        }
    }
    return temp_str;
}