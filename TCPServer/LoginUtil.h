#pragma once
#ifndef LOGINUTIL
#define LOGINUTIL

#include <iostream>
#include<map>
#include<fstream>
#include<io.h>
using namespace std;
#define MAX_Str_BUF_SIZE 1024
int doLogin(std::string usrName, std::string pwd, std::map<string, string> usrInfo) {

	if (usrInfo.find(usrName) != usrInfo.end())
	{
		if (usrInfo[usrName] == pwd)
		{
			return 200;
		}
		else {
			return 442;
		}
	}
	else {
		return 441;//�û���������
	}
}
void writFile(string buf) {
	std::string name = "E:\\WORK\\testFileDir\\123";
	ofstream out;
	out.open(name, ifstream::binary);
	if (!out)
	{
		cerr << "��ʧ�ܣ�" << endl;

	}
	out.write(buf.c_str(), buf.size());
	out.close();
}

//���л���Ŀ��map���ַ��������resultBuf�У����һ��Ϊ�ַ�������
void mapSerialization(map<string, string> mapSu, char* resultBuf, int* resultLen) {
	string buf;
	map<string, string>::iterator iterator1 = mapSu.begin();
	for (auto& kv : mapSu) {
		buf = buf + kv.first + ":" + kv.second + ";";
	}
	memcpy(resultBuf, (char*)buf.c_str(), buf.size() - 1);
	//	resultBuf = (char*)buf.c_str();
		//ȥ�����һ���ֺ�
	*resultLen = buf.size() - 1;
}

//�ָ�Ŀ���ַ��������ά������
int split(char dst[][80], char* str, const char* spl)
{
	int n = 0;
	char* result = NULL;
	result = strtok(str, spl);
	while (result != NULL)
	{
		strcpy(dst[n++], result);
		result = strtok(NULL, spl);
	}
	return n;
}


//����׼�ַ��������л�Ϊmap
void SerializationReverse(char* resBuf, map<string, string>& mapDes) {
	char usrInfo[20][80] = { '\0' };
	split(usrInfo, resBuf, ";");
	for (int i = 0; i < 20; i++) {
		if (usrInfo[i][0] == '\0')
		{
			break;
		}
		char tempS[2][80] = { '\0' };
		split(tempS, usrInfo[i], ":");
		mapDes[tempS[0]] = tempS[1];

	}
	cout << usrInfo;
}

//��ȡ�����ļ��е��ַ���
int initReadFile(char* desStr) {
	ifstream in;
	in.open("./usr.info");
	char buf[MAX_Str_BUF_SIZE];
	while (true)
	{
		in.read(buf, MAX_Str_BUF_SIZE);
		if (in.gcount() < MAX_Str_BUF_SIZE)
		{
			std::cout << "��ʼ�����" << std::endl;
			break;
		}
	}
	memcpy(desStr, buf, in.gcount());
	return in.gcount();
}

//��ʼ���û�map
void initUserInfoMap(map<string, string>& mapDes) {
	char usrInfo[MAX_Str_BUF_SIZE] = { '\0' };
	int size = initReadFile(usrInfo);
	SerializationReverse(usrInfo, mapDes);
}
void init(std::map<string, string> usrInfo) {
	std::cout << "��ʼ" << endl;
	/*string res = "lisi:123456;root:123456;wangwu:123456;zhangsan:123456";
	char *result = (char*)res.c_str();
	int len = (int)res.size();
	map<string, string> mmap;
	SerializationReverse(result, &(len), mmap);
	mmap.begin();*/

	//cout << result << endl;
	/*char usrInfo[MAX_Str_BUF_SIZE] = {'\0'};
	int size = initReadFile(usrInfo);
	cout << usrInfo << endl;*/

	initUserInfoMap(usrInfo);
	std::cout << "����" << endl;
}

#endif