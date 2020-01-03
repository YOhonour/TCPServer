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
#define MAX_SILENCE_TIME 1800 //�����ʱ��30����
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
//TCPЭ��㴫�����Ϣ
typedef struct MsgHeader
{
	//״̬��Ϊ200������״̬��441Ϊ�û������ڣ�442Ϊ�������
	UCHAR Status_Code = 200;
	/*
	��Ϣ���ͣ�
			11 ��¼���� ��Ϣ��(�û���-���� 16+16 Msg_LoginReqBody) 
			12 ��¼��Ӧ ֻ��Ӧһ��ͷ����Ϣ
			23 �����ȡ��ǰ���ߵ��û� 
			24 ���ص�ǰ�����û�map���л�
			31 ���͵���Ϣ
			32 ��ѯ�Լ�����Ϣ
			33 ����һ����Ϣ�����˷���
			41 �����ļ�����
			42 ȷ���ļ�
			43 �����ļ�
			88 ��ֹ����
	*/
	UCHAR MsgType;
	//��Ϣ�ܳ���
	UINT MsgBodyLen;
}MsgHeader;

std::string fileBaseFoderPath = "C:\\MyCode\\C++\\file\\server\\";
//����ѯ�ʷ����ļ�ͷ��
typedef struct FILESendRequest {
	char SendFrom_name[NAME_LEN];//������
	char SendTO_name[NAME_LEN]; //�շ��û�
	char FileName[32] = {'\0'};//�ļ���
}FILESendRequest;


//�����ļ���ͷ����ÿ��ʵ�����50000�ֽ��ļ�����
typedef struct FILEBody {
	//int FileID;//�ļ�id ����ʶ
	ULONG CorrentPacNO; //��ǰ���ݰ���
	ULONG AllPackages; //�ܹ����ݰ�����
	ULONG correntSize;//��ǰ����С
	char BITES[50000];//�ļ�ʵ�岿��
}FILEBody;
//Ϊ�����ļ������İ�
typedef struct FILEBodyForSend {
	MsgHeader msg_header;
	FILEBody fileBody;//�ļ���
}FILEBodyForSend;


typedef struct Msg_LoginReqBody {
	char usrName[NAME_LEN];//��¼�û���
	char pwd[PWD_LEN];//����
}Msg_LoginReqBody;

//����ṹ��ʹ������Ϣ�����̣߳����ڻ�ȡ�ļ�·����Ϣ
typedef struct BigFileInfo {
	char fileName[32];
	char filePath[1024] = {'\0'};
};
//���͵���Ϣ
typedef struct MsgPoolEntity {
	char SendFrom_name[NAME_LEN];//������
	char SendTO_name[NAME_LEN]; //�շ��û�
	char msgType; //��Ϣ���ͣ�1 �ı� ��2 С�ļ���3 ���ļ� ���ļ���msg���ִ��ļ��ڷ�������ȫ·����
	UINT msgLen; //��Ϣ����
	char msg[50000] = {'\0'};//��Ϣ
}MsgPoolEntity;
typedef struct MSG_TO_Usr {
	MsgHeader msg_header;
	MsgPoolEntity msgPoolEntity;
}MSG_TO_Usr;

//�����û���¼��Ϣ
typedef struct MSG_UsrInfo {
	MsgHeader msg_header;
	char usrInfo[256] = {"\0"};
}MSG_UsrInfo;

MsgPoolEntity FileResv(TcpThreadParam param, FILESendRequest fileRequ);
MSG_UsrInfo getMSG_UsrInfo(std::string userName);

//�����û���¼��Ϣ
typedef struct MSGComfirm {
	MsgHeader msg_header;
	char userName[16] = { "\0" };
}MSGComfirm;
//�ļ�����
typedef struct FILERequest {
	MsgHeader msg_header;
	FILESendRequest requsBody;
}FILERequest;


//ȫ�ֱ���
std::map<usrName, TCPThreadParam> loginClient; //�ѵ�¼�û��� TCP���Ӳ��� 
std::mutex mtx_login;
typedef std::queue<MsgPoolEntity> msgQueue;
std::map<string, string> usrInfo; //�û��� ����
long TcpClientCount = 0; //tcp������
std::map<usrName, msgQueue> usr_msg;//�û�����Ӧ����Ϣ����
std::mutex mtx_msgQueue;
std::unique_lock<mutex> lckQueue(mtx_msgQueue);//������
std::condition_variable cv_msgQueue;//��Ϣ��������

std::mutex mtx_msg;
std::unique_lock<mutex> lck(mtx_msg);//������
std::condition_variable cv_msg;//��Ϣ��������
std::mutex mtx_file;//�ļ�����������
std::unique_lock<mutex> file_lck(mtx_file);
bool fileFlag = FALSE;//�ļ�����
std::map<usrName, SOCKET> MSGClient;//��Ϣ����
void MsgSend();
void SendBigFile(SOCKET des, MsgPoolEntity body);
//������Ϣ����Socket���ӣ���¼����Լ�������Ϊ��Ϣ������
int MSGServer() {
	USHORT ListenPort = 8849;//
	SOCKET MSGServerListenSocket = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN ListenAddr;
	memset(&ListenAddr, 0, sizeof(SOCKADDR_IN));
	ListenAddr.sin_family = AF_INET;
	ListenAddr.sin_port = htons(ListenPort);
	ListenAddr.sin_addr.S_un.S_addr = getIPAddrFromHost();
	//��TCP�˿�
	if (bind(MSGServerListenSocket, (sockaddr*)&ListenAddr, sizeof(ListenAddr)) == SOCKET_ERROR)
	{
		cerr << "\nFailed to bind the ListenSocket\n"
			<< "error code: " << WSAGetLastError() << endl;
		return -1;
	}
	//����
	if ((listen(MSGServerListenSocket, SOMAXCONN)) == SOCKET_ERROR)
	{
		cerr << "\nFailed to listen the ListenSocket\n"
			<< "error code: " << WSAGetLastError() << endl;
		return -1;
	}
	cout << "TCP MSG Server Started On Port: " << ListenPort << endl << endl;
	SOCKET TcpMsgSocket;
	SOCKADDR_IN TcpMsgClientAddr;
	while (true)//һֱ�������Կͻ��˵�����������֤��¼�󣬼�����Ϣ���Ͷ��У��Ա���Ϣ���Ͷ��У�
	{
		int iSockAddrLen = sizeof(sockaddr);
		TcpMsgSocket = accept(MSGServerListenSocket, (sockaddr*)&TcpMsgClientAddr, &iSockAddrLen);
		char* tBuf = (char*)malloc(1024);
		recv(TcpMsgSocket, tBuf, 1024, 0);
		MSGComfirm* msgComfirm = (MSGComfirm*)tBuf;
		if (loginClient.count(msgComfirm->userName) == 0)//�ѵ�¼�û�map��û�У���Ҫ�رձ�socket
		{
			closesocket(TcpMsgSocket);
		}
		else
		{
			MSGClient[msgComfirm->userName] = TcpMsgSocket;//�����û�
		}
	}
}