#ifndef Server_h
#define Server_h
#include <iostream>
#include <string>
#include <vector>
#include <stdlib.h>
#include <thread>
#include <stdlib.h>
#include <sstream>
#include <fstream>
#include <stdio.h>
#include <thread>
#include <stdlib.h>
#include <typeinfo>
#include <ibe.h>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/string.hpp>
#include "../CommLib/NetComm/include/EtherReceiver.hpp"
#include "../CommLib/NetComm/include/EtherSender.hpp"
#include "../CommLib/NetComm/include/UDPSender.hpp"
#include "../CommLib/NetComm/include/UDPReceiver.hpp"
#include "../CryptoLib/include/Cryptor.hpp"
#include "./MQ.h"
#define STATE___init 0
#define STATE___final 1
#define STATE__reqRecved 2
#define STATE__queCreated 3
#define STATE__verifyReqFailed 4
#define STATE__queSent 5
#define STATE__queRespRecved 6
#define STATE__authRespCreated 7
#define STATE__verifyQueRespFailed 8


int CLIENT_NUM;
std::string SELF_IP_STR;
std::string GATEWAY_IP_STR;

class Server {
	private:
		AcAuthReq_G2S acAuthReq_g2s;
		AuthQu authQu;
		AuthQuAck authQuAck;
		AcAuthAns acAuthAns;
		int clientId_int;
		int serverId_int;

		bool breakListen;
		std::string CLIENT_IP_STR;

		ushort SELF_PORT;
		ushort GATEWAY_PORT;

		
	public: 
		int __currentState;
		ConcurrentQueue cq;

		unsigned char master_privkey[IBE_MASTER_PRIVKEY_LEN];
		unsigned char master_pubkey[IBE_MASTER_PUBKEY_LEN];
		unsigned char usr_privkey[IBE_USR_PRIVKEY_LEN];
		Server();
		~Server();
		void Sign(unsigned char* msg, unsigned char* sig, size_t msglen);
		bool Verify(unsigned char* msg, unsigned char* sig, size_t msglen, int verify_id);
		int receive();
		int receive_plus();
		int send(u_char* data_, int length_);
		void SMLMainServer();
		void initConfig(std::string client_ip, ushort self_port, ushort gate_port);
};

void initOverallConfig(int client_num, std::string server_ip, std::string gateway_ip){
	CLIENT_NUM = 2;
	SELF_IP_STR = "127.0.0.1";
	GATEWAY_IP_STR = "127.0.0.1";
	
}

int Id2Int(ip_address ip){
	int result;
	memcpy(&result, &ip, sizeof(int));
	int tempResult = ntohl(result);
	return tempResult;
}

void recv_thd(Server* server){
	server->receive();
}

void handle_thd(Server* server){
	server->SMLMainServer();
}

void run(Server* server){
	std::thread recv_t(&recv_thd, server);
	std::thread handle_t(&handle_thd, server);

	handle_t.join();
	recv_t.join();
}

//static int __currentState = STATE___init;
int main(int argc, char** argv) {
	ushort self_prefix = 6000;
	ushort gate_prefix = 8000;
	std::string client_ips[2];
	std::string filename = argv[1];
	std::ifstream inConf(filename.c_str());
	std::string s = "";
	while(getline(inConf,s)){
		int split_pos = s.find(",");
		std::string first = s.substr(split_pos);
		std::string second = s.substr(split_pos, sizeof(s));
		if(!first.compare("GATE_IP_STR")){
			GATEWAY_IP_STR = second;
		} else if(!first.compare("SERVER_IP_STR")){
			SELF_IP_STR = second;
		} else if(!first.compare("CLIENT_NUM")){
			CLIENT_NUM = atoi(second.c_str());
		} else if(!first.compare("RECV_PORT_PRE")){
			self_prefix = atoi(second.c_str());
		} else if(!first.compare("SND_PORT_PRE")){
			gate_prefix = atoi(second.c_str());
		} else if(!first.compare("IP2ID")){
			int second_split_pos = second.find(",");
			std::string sec = second.substr(second_split_pos);
			std::string third = second.substr(second_split_pos, sizeof(second));
			int id = atoi(third.c_str());
			client_ips[id] = sec;
		} else {
			std::cout << "ERROR: should not be here" << std::endl;
		}

	}
	initOverallConfig(CLIENT_NUM, SELF_IP_STR, GATEWAY_IP_STR);
	Server* server[6];
	// client_ips[0] = "127.0.0.10";
	// client_ips[1] = "127.0.0.11";
	std::cout << "CLIENT NUM: " << CLIENT_NUM << std::endl;
	for(int i = 0; i < CLIENT_NUM; i ++){
		server[i] = new Server();
		server[i]->initConfig(client_ips[i], self_prefix + i, gate_prefix + i);
		std::cout << "Server created" << std::endl;
	}
	std::thread handle_ts[CLIENT_NUM];
	std::thread recv_ts[CLIENT_NUM];
	for (int i = 0; i < CLIENT_NUM; i++) {
		recv_ts[i] = std::thread(&recv_thd, server[i]);
		handle_ts[i] = std::thread(&handle_thd, server[i]);
	}
	// std::cout << "Start handling" << std::endl;
	// for (int i = 0; i < CLIENT_NUM; i++) {
	// }
	for (int i = 0; i < CLIENT_NUM; i++) {
		handle_ts[i].join();
	}
	for (int i = 0; i < CLIENT_NUM; i++) {
		recv_ts[i].join();
	}
	for(int i = 0; i < CLIENT_NUM; i++){
		delete(server[i]);
	}
}
#endif

