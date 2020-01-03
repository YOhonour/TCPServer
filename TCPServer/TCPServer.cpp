#include "TCPServer.h"
#include<thread>
using namespace std;


void heartBeatCheak() {
	while (true)
	{
		time_t now;
		time(&now);
		for (auto& kv : loginClient) {
			if ((now - kv.second.last_Msg_TIME) > MAX_SILENCE_TIME) {// 判断沉默时间是否超时
				closesocket(kv.second.socket);//超时关闭Socket
				MSGClient.erase(kv.first);//关闭消息订阅
				/*
				问题 1:需要关闭服务线程 
					 2.服务线程此时被accept阻塞
					 3.被阻塞无法收到(检测)关闭信号
				*/
			}
		}
		Sleep(5 * 60);//5分钟检查一次活动SOCKET
	}
}
int heartBeatCheak1(TcpThreadParam Param) {
	time_t now;
	time(&now);
	if ((now - Param.last_Msg_TIME) > MAX_SILENCE_TIME) {// 判断沉默时间是否超时
		return -1;
	}
	return 1;
}
int main()
{
	//初始化用户map
	initUserInfoMap(usrInfo);
	for (auto& kv : usrInfo) {
		msgQueue q;
		usr_msg[kv.first] = q;
	}
	cout << "请输入绑定端口：";
	USHORT ListenPort = 8848;
	//cin >> ListenPort;

	//初始化winsock2环境
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		cerr << "\nFailed to initialize the winsock 2 stack\n"
			<< "error code: " << WSAGetLastError() << endl;
		return -1;
	}
	//监听Socket，流式套接字
	SOCKET ListenSocket = socket(AF_INET, SOCK_STREAM, 0);
	//填充本地TCP Socket地址结构
	SOCKADDR_IN ListenAddr;
	memset(&ListenAddr, 0, sizeof(SOCKADDR_IN));
	ListenAddr.sin_family = AF_INET;
	ListenAddr.sin_port = htons(ListenPort);
	ListenAddr.sin_addr.S_un.S_addr = getIPAddrFromHost();
	
	//绑定TCP端口
	if (bind(ListenSocket, (sockaddr*)&ListenAddr, sizeof(ListenAddr)) == SOCKET_ERROR)
	{
		cerr << "\nFailed to bind the ListenSocket\n"
			<< "error code: " << WSAGetLastError() << endl;
		return -1;
	}

	//监听
	if ((listen(ListenSocket, SOMAXCONN)) == SOCKET_ERROR)
	{
		cerr << "\nFailed to listen the ListenSocket\n"
			<< "error code: " << WSAGetLastError() << endl;
		return -1;
	}
	cout << "TCP Server Started On TCP Port: " << ListenPort << endl << endl;
	SOCKET TcpSocket;
	SOCKADDR_IN TcpClientAddr;
	//开启心跳检测线程
	std::thread heartBeatThread{ heartBeatCheak };
	heartBeatThread.detach();
	//开启消息服务端口，创建订阅消息服务
	std::thread MSGServerThread{ MSGServer };
	MSGServerThread.detach();
	//开启消息监听，发送线程
	std::thread MSGRecvServerThread{ MsgSend };
	MSGRecvServerThread.detach();
	while (true)
	{
		int iSockAddrLen = sizeof(sockaddr);
		//在使用绑定的套接字，接收对方套接字
		TcpSocket = accept(ListenSocket, (sockaddr*)&TcpClientAddr, &iSockAddrLen);
		if ((TcpSocket) == SOCKET_ERROR) {
			cerr << "\nFailed to accept the client TCP Socket\n"
				<< "error code: " << WSAGetLastError() << endl;
				return -1;
		}
		cout << "Connection from TCP client " << inet_ntoa(TcpClientAddr.sin_addr) << ":" << ntohs(TcpClientAddr.sin_port) << " accepted\n" << endl;

		//TCP线程数达到上限，停止接受新的Client
		if (TcpClientCount >= MAX_CLIENT)
		{
			closesocket(TcpSocket);
			cout << "Connection from TCP client " << inet_ntoa(TcpClientAddr.sin_addr) << ":" << ntohs(TcpClientAddr.sin_port) << " refused for max client num\n" << endl;
			continue;
		}

		TcpThreadParam Param;
		Param.socket = TcpSocket;
		Param.addr = TcpClientAddr;
		
		//开启TCP服务线程
		std::thread t1{ TcpServeThread,Param };
		t1.detach();


	}

    std::cout << "Hello World!\n";
}

void prtIP(ULONG ulHostIP) {
	ulHostIP = ntohl(ulHostIP);
	ULONG ip1 = ulHostIP, ip2 = ulHostIP, ip3 = ulHostIP, ip4 = ulHostIP;


	ip1 = ip1 >> 24;
	ip2 = (ip2 << 8) >> 24;
	ip3 = (ip3 << 16) >> 24;
	ip4 = (ip4 << 24) >> 24;

	std::cout << ip1 << "." << ip2 << "." << ip3 << "." << ip4;
}

/*
获取网络字节序的ip地址
*/
int getIPAddrFromHost() {
	MIB_IPADDRTABLE* pIPAddrTable = (MIB_IPADDRTABLE*)malloc(sizeof(MIB_IPADDRTABLE));
	ULONG dwSize = 0, dwRetVel = 0;
	if (GetIpAddrTable(pIPAddrTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
		free(pIPAddrTable);
		//重新申请返回条数的IP表
		pIPAddrTable = (MIB_IPADDRTABLE*)malloc(sizeof(MIB_IPADDRTABLE) * dwSize);
	}
	if ((dwRetVel = GetIpAddrTable(pIPAddrTable, &dwSize, 0)) == NO_ERROR) {
		//std::cout << "IPTable中dwNumEntries为：" << pIPAddrTable->dwNumEntries << "\n";
		int ThedwNumEntries = pIPAddrTable->dwNumEntries;
		for (UINT i = 0; i < ThedwNumEntries; i++)
		{
			cout << "第" << i << "个IP地址为：" ;
			prtIP(((pIPAddrTable->table)+i)->dwAddr);
			cout << endl;
		}
		ThedwNumEntries--;
		std::cout << "请输入使用的IP地址序号" << "(0-" << ThedwNumEntries << ")：" << endl;
		int netNum = 0;
		//scanf_s("%d", &netNum);
		return pIPAddrTable->table[netNum].dwAddr;
	}

}

//TCP服务线程
void TcpServeThread(TcpThreadParam param) {
	std::string userName;
	char ServerTCPBuf[MAX_BUF_SIZE] = {'\0'};
	SOCKET TcpSocket = param.socket;
	SOCKADDR_IN TcpClientAddr = param.addr;

	//输出提示信息
	cout << "Thread: " << GetCurrentThreadId() << " is serving client from " << inet_ntoa(TcpClientAddr.sin_addr) << ":" << ntohs(TcpClientAddr.sin_port) << endl << endl;
	sprintf(ServerTCPBuf, "请登录(用户名:密码)");
	send(TcpSocket, ServerTCPBuf, strlen(ServerTCPBuf), 0);//发送
	memset(ServerTCPBuf, '\0', sizeof(ServerTCPBuf));//重置信息缓冲区
	param.last_Msg_TIME = time(NULL);
	int TCPBytesReceived;
	time_t CurSysTime;
	//接收登录信息
	Msg_LoginReqBody ReqBody;
	while (true)
	{
		TCPBytesReceived = recv(TcpSocket, ServerTCPBuf, sizeof(ServerTCPBuf), 0);
		//std::cout << "收到信息：" << ServerTCPBuf << endl;
		MsgHeader* pMsgHeader = (MsgHeader*)(ServerTCPBuf);
		
		if ((pMsgHeader->MsgType) == EXIT_sig)//判断是否为退出信号,如果是就退出信号
		{
			closesocket(TcpSocket);
			return;
		}
		Msg_LoginReqBody* pReqBody = (Msg_LoginReqBody*)(ServerTCPBuf + sizeof(MsgHeader));
		ReqBody = *pReqBody;
		UINT statusCode = doLogin(pReqBody->usrName, pReqBody->pwd, usrInfo);
		if (statusCode != SUCCESS)//不成功就发送信息
		{
			/*密码错误，发送信息*/
			MsgHeader hd;
			hd.MsgBodyLen = 0;
			hd.MsgType = LoginResp;
			hd.Status_Code = statusCode;
			send(TcpSocket, (char*)&hd, sizeof(MsgHeader), 0);
			memset(ServerTCPBuf, '\0', sizeof(ServerTCPBuf));//重置信息缓冲区
		}
		else//成功就进入接下来操作流程
		{
			//发送确认消息
			cv_msg.notify_all();//唤醒消息线程
			MsgHeader hd;
			hd.MsgBodyLen = 0;
			hd.MsgType = LoginResp;
			hd.Status_Code = 200;
			send(TcpSocket, (char*)&hd, sizeof(MsgHeader), 0);
			userName = pReqBody->usrName;//将用户名记录
			loginClient[userName] = param;
			msgQueue msgQ;
			//usr_msg[userName] = msgQ;//创建消息队列
			break;
		}
	}
	memset(ServerTCPBuf, '\0', sizeof(ServerTCPBuf));//重置信息缓冲区
	//登陆成功
	loginClient[userName].last_Msg_TIME = time(NULL);//更新用户时间
	cout << "用户"<< ReqBody.usrName <<"登陆成功" << endl;
	//向用户发送目前用户列表
	char usrInfoBuf[MAX_BUF_SIZE] = {"\0"};
	memset(usrInfoBuf, '\0', sizeof(usrInfoBuf));//重置发送信息缓冲区
	
	while (true)
	{
		memset(ServerTCPBuf, '\0', sizeof(ServerTCPBuf));//重置接收信息缓冲区
		cout << "开始监听" << endl;
		ZeroMemory(ServerTCPBuf, MAX_BUF_SIZE);
		recv(TcpSocket, ServerTCPBuf, sizeof(ServerTCPBuf), 0);
		if (!heartBeatCheak1(param))
		{
			//超时，关闭线程
			cout << "超时，关闭线程" << endl;
			break;
		}
		MsgHeader* msgHead = (MsgHeader*)ServerTCPBuf;
		loginClient[userName].last_Msg_TIME = time(NULL);//更新用户时间
		switch (msgHead->MsgType)
		{
		case(23): {
			//返回当前在线的用户Map字符串
			memset(usrInfoBuf, '\0', sizeof(usrInfoBuf));//重置信息缓冲区
			memcpy(usrInfoBuf, (char*) & (getMSG_UsrInfo(userName)), sizeof(MSG_UsrInfo));
			send(TcpSocket, usrInfoBuf, sizeof(MSG_UsrInfo), 0);
		}
				break;
		case 31: {//收到客户端发送的信息
		
			MSG_TO_Usr* msg_to_usr = (MSG_TO_Usr*)ServerTCPBuf;
			MsgPoolEntity* msgToSendBuf;
			msgToSendBuf = (MsgPoolEntity*)(ServerTCPBuf + sizeof(MsgHeader));
			string Uname = msgToSendBuf->SendTO_name;
			msgQueue msgQ = usr_msg.at(Uname);
			msgQ.push(*msgToSendBuf);
			usr_msg[Uname] = msgQ;
			//msgQueue msgQ1 = usr_msg.at(msgToSendBuf->SendTO_name);
			
			cv_msg.notify_all();//唤醒消息处理线程
		}
			   break;
		case 41: {
			FILESendRequest* fileRequ = (FILESendRequest*)(ServerTCPBuf + sizeof(MsgHeader));
			//文件接收方法
			MsgPoolEntity fileMsg = FileResv(param, *fileRequ);
			msgQueue msgQ = usr_msg.at(fileMsg.SendTO_name);
			msgQ.push(fileMsg);
			usr_msg[fileMsg.SendTO_name] = msgQ;
			cv_msg.notify_all();//唤醒消息处理线程
		}
			   break;
		case 88:{
			loginClient.erase(userName);
			MSGClient.erase(userName);
			cout << "用户 "<< userName <<" 退出通信" << endl;
			return;
		} 
		default:
			break;
		}
		memset(ServerTCPBuf, '\0', sizeof(ServerTCPBuf));//重置接收信息缓冲区
	}
}
//大文件文件接收方法
MsgPoolEntity FileResv(TcpThreadParam param,FILESendRequest fileRequ) {
	string fileName = fileRequ.FileName;//文件名
	MsgHeader hd;
	hd.MsgType = 42;
	char* fileResvBuf = (char*)malloc(MAX_BUF_SIZE * sizeof(char));
	send(param.socket, (char*)&hd, sizeof(MsgHeader), 0);//发送确认消息
	ZeroMemory(fileResvBuf, MAX_BUF_SIZE * sizeof(char));
	int ResvLen = 0;
	recv(param.socket, fileResvBuf, MAX_BUF_SIZE, 0);//接收第一个文件包
	ofstream file_out;//文件输出流
	string fileRealPath = fileBaseFoderPath + fileName;
	file_out.open(fileRealPath, ifstream::binary);
	FILEBody* pFILEBody = (FILEBody*)(fileResvBuf + sizeof(MsgHeader));
	file_out.write(pFILEBody->BITES, pFILEBody->AllPackages);

	send(param.socket, (char*)&hd, sizeof(MsgHeader), 0);//发送确认消息
	ULONG allPacks = pFILEBody->AllPackages;//文件包字节数
	cout << "开始接收文件，第一个包字节数为：" << allPacks << endl;
	while (1)
	{
		if (allPacks < 50000)
		{
			break;
		}
		ResvLen = recv(param.socket, fileResvBuf, MAX_BUF_SIZE, 0);//接收文件包
		pFILEBody = (FILEBody*)(fileResvBuf + sizeof(MsgHeader));
		file_out.write(pFILEBody->BITES, pFILEBody->AllPackages);
		//file_out.flush();
		send(param.socket, (char*)&hd, sizeof(MsgHeader), 0);//发送确认消息
		
		allPacks = pFILEBody->AllPackages;//文件包字节数
		cout << "接收文件，包字节数为：" << allPacks << endl;
	}
	cout << "文件接收完毕";
	MsgPoolEntity coEn;
	coEn.msgType = 3;
	memcpy(coEn.SendFrom_name, fileRequ.SendFrom_name, NAME_LEN);
	memcpy(coEn.SendTO_name, fileRequ.SendTO_name, NAME_LEN);
	BigFileInfo finfo;
	memcpy(finfo.fileName, fileRequ.FileName, 32);
	memcpy(finfo.filePath, fileRealPath.c_str(), fileRealPath.size());
	memcpy(coEn.msg, (char*)&finfo, sizeof(BigFileInfo));
	file_out.close();
	free(fileResvBuf);

	return coEn;
}

//消息发送线程，监听对应用户的消息队列，将消息发送到用户Socket
void MsgSend() {
	while (true)
	{
		int flag = -1;
		for (auto kv : usr_msg)
		{
			if (kv.second.size() != 0)
			{
				flag = 1;
			}
		}
		if (flag == -1)
		{
			cv_msg.wait(lck);
		}
		for (auto& kv : MSGClient) {
			//遍历消息服务Socket map，使用其用户名获取用户对应的消息队列，然后发送消息
			msgQueue thisQueue = usr_msg.at(kv.first);
			if (thisQueue.empty())
			{
				//如果队列为空就退出本次循环，遍历下一个用户的消息队列
				continue;
			}
			else {
				//遍历消息队列，拿出消息，发送消息
				while (thisQueue.size() != 0 )
				{
					MSG_TO_Usr usrmsg;
					usrmsg.msg_header.MsgType = 33;
					MsgPoolEntity body = std::move(thisQueue.front());//队首的消息
					thisQueue.pop();
					usr_msg[kv.first] = thisQueue;
					usrmsg.msgPoolEntity = body;
					if (body.msgType == 1 || body.msgType == 2)//判断是否为小文件或者文本消息，如果是就直接发送
					{
						send(kv.second, (char*)&usrmsg, sizeof(usrmsg), 0);//向客户端发送消息
					}
					else if(body.msgType == 3) //为发送大文件
					{
						SendBigFile(kv.second, body);
					}
					
				}
				
			}
			
		}
		
	}
}
//发送大文件
void SendBigFile(SOCKET des, MsgPoolEntity body) {
	//先发送一个文件发送询问请求
	FILERequest rq;
	rq.msg_header.MsgType = 41;
	char* reBuf = (char*)malloc(65535);
	ZeroMemory(reBuf, 65535);
	BigFileInfo* fileInfo = (BigFileInfo*)body.msg;
	memcpy(rq.requsBody.FileName, fileInfo->fileName, 32);
	memcpy(rq.requsBody.SendFrom_name, body.SendFrom_name, NAME_LEN);
	memcpy(rq.requsBody.SendTO_name, body.SendTO_name, NAME_LEN);
	send(des, (char*)&rq, sizeof(rq), 0);//发送文件询问请求
	recv(des, reBuf, 65535,0);
	//收到后判断是否为确认信息
	MsgHeader* hd = (MsgHeader*)reBuf;
	if (hd->MsgType != 42)
	{
		std::cout << "确认失败\n";
		return;
	}
	ifstream in;
	in.open(fileInfo->filePath, ifstream::binary);
	if (!in)
	{
		cerr << "源文件打开失败！" << endl;
		return;
	}
	MsgHeader* hdBuf = (MsgHeader*)malloc(sizeof(MsgHeader));
	while (1)
	{
		FILEBodyForSend Filesend;
		in.read(Filesend.fileBody.BITES, 50000 * sizeof(char));
		Filesend.fileBody.AllPackages = in.gcount();
		send(des, (char*)&Filesend, sizeof(Filesend), 0);
		recv(des, (char*)hdBuf, MAX_BUF_SIZE, 0);
		if (hdBuf->Status_Code != 200)
		{
			cout << "确认失败！" << endl;
			return;
		}
		if (in.gcount() < 50000)
		{

			cout << "文件读取完毕！" << endl;
			break;
		}
	}
	in.close();
	cout << "文件发送完毕！" << endl;
}
//构建向用户发送当前系统用户信息包
MSG_UsrInfo getMSG_UsrInfo(std::string userName) {
	MSG_UsrInfo UsrInfoToSend;
	char Buf[1024] = {"\0"};
	int len = 0;
	mapSerialization(usrInfo, Buf, &len);//获取反序列化的字符串
	UsrInfoToSend.msg_header.MsgType = 24;
	memcpy(UsrInfoToSend.usrInfo,Buf,len);
	cout << "向 " << userName << " 发送 " << (std::string)(Buf) << endl;
	return UsrInfoToSend;
}