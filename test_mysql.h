#include<iostream>
#include<stdio.h>
#include<string.h>
#include<mysql/mysql.h>
#include<time.h>

using namespace std;

class SQL_Server{
    public:
    MYSQL mysql; //数据库连接句柄
    MYSQL_FIELD *fd; //字段信息
    char field[32][32];  //存字段名二维数组
    MYSQL_RES *res; //这个结构代表返回行的一个查询结果集
    MYSQL_ROW row; //一个行数据的类型安全(type-safe)的表示，表示数据行的列
    int user_num; //用户数量
    
    public:
    /*连接到数据库*/
    bool ConnectDatabase();
    /*从数据库断开连接*/
    void DisconnectDatabase();
    /*插入用户信息*/
    bool InsertUser(char*uname, const char *code);
    /*验证用户信息*/
    bool VeriftUser(int uid, const char *code);
    /*修改用户密码*/
    bool ModifyUserCode(int uid, char *old_code, char *new_code);
    /*更新会话密钥，已弃用*/
    bool UpdateSessionKey(int uid, const char *session_key);
    /*插入聊天信息*/
    bool InsertRecord(int SID, int RID, long time, char *message);
    /*删除SID发送给RID的聊天信息*/
    bool DeleteRecord(int SID, int RID);
    /*获取SID发送给RID的聊天信息*/
    bool GetRecord(int SID, int RID);
    /*获取RID收到的聊天信息数量的SID*/
    int GetRecordNumber(int RID);
};

/*截取字符串*/
char *substr(char *str, int left_border, int length);
/*字符串处理，将'替换为“*/
char *ProcessStr(const char* str);