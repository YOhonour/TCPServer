#pragma once
#include <iostream>
#include "WinSock2.h"
#include "Windows.h"
#include <iphlpapi.h>
#include<queue>
#include"LoginUtil.h"
#include <time.h>
#include<mutex>
#include<thread>

#pragma comment(lib,"iphlpapi")
#pragma comment(lib,"Ws2_32")

#define usrNameNotKonw 441
#define pwdError 442
#define MAX_CLIENT 1000
#define MAX_BUF_SIZE 65535
#define SUCCESS 200
#define MAX_SILENCE_TIME 1800 //最长静音时间30分钟
#define MAX_FILE_PACK_SIZE 64000



using namespace std;


typedef string usrName;

int getIPAddrFromHost();
void prtIP(ULONG ulHostIP);
typedef struct TcpThreadParam
{
	SOCKET socket;
	SOCKET MsgSocket = 0;
	sockaddr_in addr;
	time_t last_Msg_TIME;
}TCPThreadParam;


#define LoginReq 11
#define LoginResp 12
#define ReqLoginedUsrs 12
#define ReqLoginedUsrs 24
#define sendMsg 31
#define EXIT_sig 88
#define NAME_LEN 16
#define PWD_LEN 16


void TcpServeThread(TcpThreadParam param);
void prtIP(ULONG ulHostIP);
//TCP协议层传输的消息
typedef struct MsgHeader
{
	//状态码为200正常，状态码441为用户不存在，442为密码错误
	UCHAR Status_Code = 200;
	/*
	消息类型：
			11 登录请求 消息体(用户名-密码 16+16 Msg_LoginReqBody) 
			12 登录响应 只响应一个头部信息
			23 请求获取当前在线的用户 
			24 返回当前所有用户map序列化
			31 发送的信息
			32 查询自己的消息
			33 这是一条消息，他人发的
			41 发送文件请求
			42 确认文件
			43 发送文件
			88 终止连接
	*/
	UCHAR MsgType;
	//消息总长度
	UINT MsgBodyLen;
}MsgHeader;

std::string fileBaseFoderPath = "C:\\MyCode\\C++\\file\\server\\";
//请求询问发送文件头部
typedef struct FILESendRequest {
	char SendFrom_name[NAME_LEN];//发送者
	char SendTO_name[NAME_LEN]; //收方用户
	char FileName[32] = {'\0'};//文件名
}FILESendRequest;


//发送文件的头部，每个实体承载50000字节文件数据
typedef struct FILEBody {
	//int FileID;//文件id ，标识
	ULONG CorrentPacNO; //当前数据包号
	ULONG AllPackages; //总共数据包个数
	ULONG correntSize;//当前包大小
	char BITES[50000];//文件实体部分
}FILEBody;
//为发送文件构建的包
typedef struct FILEBodyForSend {
	MsgHeader msg_header;
	FILEBody fileBody;//文件包
}FILEBodyForSend;


typedef struct Msg_LoginReqBody {
	char usrName[NAME_LEN];//登录用户名
	char pwd[PWD_LEN];//密码
}Msg_LoginReqBody;

//这个结构体使用在消息发送线程，用于获取文件路径信息
typedef struct BigFileInfo {
	char fileName[32];
	char filePath[1024] = {'\0'};
};
//发送的信息
typedef struct MsgPoolEntity {
	char SendFrom_name[NAME_LEN];//发送者
	char SendTO_name[NAME_LEN]; //收方用户
	char msgType; //消息类型，1 文本 ，2 小文件，3 大文件 大文件的msg部分存文件在服务器的全路径名
	UINT msgLen; //消息长度
	char msg[50000] = {'\0'};//消息
}MsgPoolEntity;
typedef struct MSG_TO_Usr {
	MsgHeader msg_header;
	MsgPoolEntity msgPoolEntity;
}MSG_TO_Usr;

//发送用户登录信息
typedef struct MSG_UsrInfo {
	MsgHeader msg_header;
	char usrInfo[256] = {"\0"};
}MSG_UsrInfo;

MsgPoolEntity FileResv(TcpThreadParam param, FILESendRequest fileRequ);
MSG_UsrInfo getMSG_UsrInfo(std::string userName);

//发送用户登录信息
typedef struct MSGComfirm {
	MsgHeader msg_header;
	char userName[16] = { "\0" };
}MSGComfirm;
//文件发送
typedef struct FILERequest {
	MsgHeader msg_header;
	FILESendRequest requsBody;
}FILERequest;


//全局变量
std::map<usrName, TCPThreadParam> loginClient; //已登录用户名 TCP连接参数 
std::mutex mtx_login;
typedef std::queue<MsgPoolEntity> msgQueue;
std::map<string, string> usrInfo; //用户名 密码
long TcpClientCount = 0; //tcp连接数
std::map<usrName, msgQueue> usr_msg;//用户名对应的消息队列
std::mutex mtx_msgQueue;
std::unique_lock<mutex> lckQueue(mtx_msgQueue);//互斥锁
std::condition_variable cv_msgQueue;//消息条件变量

std::mutex mtx_msg;
std::unique_lock<mutex> lck(mtx_msg);//互斥锁
std::condition_variable cv_msg;//消息条件变量
std::mutex mtx_file;//文件操作互斥量
std::unique_lock<mutex> file_lck(mtx_file);
bool fileFlag = FALSE;//文件操作
std::map<usrName, SOCKET> MSGClient;//消息订阅
void MsgSend();
void SendBigFile(SOCKET des, MsgPoolEntity body);
//开启消息订阅Socket连接，登录后可以监听，成为消息服务器
int MSGServer() {
	USHORT ListenPort = 8849;//
	SOCKET MSGServerListenSocket = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN ListenAddr;
	memset(&ListenAddr, 0, sizeof(SOCKADDR_IN));
	ListenAddr.sin_family = AF_INET;
	ListenAddr.sin_port = htons(ListenPort);
	ListenAddr.sin_addr.S_un.S_addr = getIPAddrFromHost();
	//绑定TCP端口
	if (bind(MSGServerListenSocket, (sockaddr*)&ListenAddr, sizeof(ListenAddr)) == SOCKET_ERROR)
	{
		cerr << "\nFailed to bind the ListenSocket\n"
			<< "error code: " << WSAGetLastError() << endl;
		return -1;
	}
	//监听
	if ((listen(MSGServerListenSocket, SOMAXCONN)) == SOCKET_ERROR)
	{
		cerr << "\nFailed to listen the ListenSocket\n"
			<< "error code: " << WSAGetLastError() << endl;
		return -1;
	}
	cout << "TCP MSG Server Started On Port: " << ListenPort << endl << endl;
	SOCKET TcpMsgSocket;
	SOCKADDR_IN TcpMsgClientAddr;
	while (true)//一直接受来自客户端的连接请求，验证登录后，加入消息发送队列（对比消息发送队列）
	{
		int iSockAddrLen = sizeof(sockaddr);
		TcpMsgSocket = accept(MSGServerListenSocket, (sockaddr*)&TcpMsgClientAddr, &iSockAddrLen);
		char* tBuf = (char*)malloc(1024);
		recv(TcpMsgSocket, tBuf, 1024, 0);
		MSGComfirm* msgComfirm = (MSGComfirm*)tBuf;
		if (loginClient.count(msgComfirm->userName) == 0)//已登录用户map中没有，需要关闭本socket
		{
			closesocket(TcpMsgSocket);
		}
		else
		{
			MSGClient[msgComfirm->userName] = TcpMsgSocket;//加入用户
		}
	}
}