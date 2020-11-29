#ifndef Gateway_h
#define Gateway_h
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
#include <time.h>
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
#include "../CommLib/NetComm/include/packet.hpp"
#include "./MQ.h"
#define STATE___init 0
#define STATE___final 1
#define STATE__reqMsgRecved 2
#define STATE__reqMsgSent 3
#define STATE__authQueRecved 4
#define STATE__authQueSent 5
#define STATE__queRespRecved 6
#define STATE__queRespSent 7
#define STATE__authRespRecved 8
#define MAX_CLIENT_NUM 6
std::string SELF_IP_STR = "127.0.0.1";
std::string SERVER_IP_STR = "127.0.0.1";
static pcap_t* devGateway;
std::map<int, int> clientIp2QIDMap;
int CLIENT_NUM;
u_char gateway_mac[6];
ConcurrentQueue cqs[MAX_CLIENT_NUM];
class Gateway {


	public: 
		int debugId;
		int hostId;
		int gateway;
		int server;		
		GwAnce gwAnce;
		AcAuthReq_C2G acAuthReq_c2g;
		AcAuthReq_G2S acAuthReq_g2s;
		AuthQuAck authQuAck;
		AuthQu authQu;
		AcAuthAns acAuthAns;

		int clientId_int;
		int gatewayId_int;
		int __currentState;
		ushort SELF_PORT;
		ushort SERVER_PORT;


        unsigned char master_privkey[IBE_MASTER_PRIVKEY_LEN];
        unsigned char master_pubkey[IBE_MASTER_PUBKEY_LEN];
        unsigned char usr_privkey[IBE_USR_PRIVKEY_LEN];

		Gateway();
		~Gateway();
		void Sign(unsigned char* msg, unsigned char* sig, size_t msglen);
		bool Verify(unsigned char* msg, unsigned char* sig, size_t msglen, int verify_id);
		int sendToHost(u_char* data_, int length_, u_char dmac[6]);
		int sendToServer();
		void SMLMainGateway();
		void recvFromServer();
		void initConfig(std::string client_ip_str, ushort self_port, ushort server_port);
};


int recvFromHost();
void receive_udp(Gateway* gw);
void recv_udp_thd(Gateway* gw);
void recv_ether_thd();
void receive_udp(Gateway* gw);
void handle_thd(Gateway* gw);
void gwAnce_thd(Gateway* gw);

void initOverallConfig(int client_num, std::string gate_ip_str, std::string server_ip_str){
	SELF_IP_STR = gate_ip_str;
	SERVER_IP_STR = server_ip_str;
	CLIENT_NUM = client_num;
	clientIp2QIDMap[inet_addr("127.0.0.10")] = 0;
	clientIp2QIDMap[inet_addr("127.0.0.11")] = 1;
	gateway_mac[0] = 0x48;
	gateway_mac[1] = 0x2a;
	gateway_mac[2] = 0xe3;
	gateway_mac[3] = 0x60;
	gateway_mac[4] = 0x31;
	gateway_mac[5] = 0xfa;
}



int main(int argc, char** argv) {

	std::string client_ips[2];
	ushort self_prefix = 8000;
	ushort server_prefix = 6000;
	std::ifstream inConf(argv[1]);
	std::string s = "";
	while(getline(inConf,s)){
		int split_pos = s.find(",");
		std::string first = s.substr(split_pos);
		std::string second = s.substr(split_pos, sizeof(s));
		if(!first.compare("GATE_IP_STR")){
			SELF_IP_STR = second;
		} else if(!first.compare("SERVER_IP_STR")){
			SELF_IP_STR = second;
		} else if(!first.compare("CLIENT_NUM")){
			CLIENT_NUM = atoi(second.c_str());
		} else if(!first.compare("RECV_PORT_PRE")){
			self_prefix = atoi(second.c_str());
		} else if(!first.compare("SND_PORT_PRE")){
			server_prefix = atoi(second.c_str());
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
	initOverallConfig(1, "127.0.0.1", "127.0.0.1");
	// this is for sending hellp packet, no need for initialized
	Gateway* gwAnceSender = new Gateway();
	gwAnceSender->debugId = 0;
	gwAnceSender->initConfig("0.0.0.0", 10000, 10000);

	Gateway* gates[CLIENT_NUM];
	std::cout << "start hello thread" << std::endl;
	std::thread sendHello_t(&gwAnce_thd, gwAnceSender);
	sendHello_t.detach();
	std::cout << "start hello thread end" << std::endl;
	
	// client_ips[0] = "127.0.0.10";
	// client_ips[1] = "127.0.0.11";
	std::thread recvEther_t(&recv_ether_thd);
	for(ushort i = 0; i < CLIENT_NUM; i++){
		// configure the port num here
		gates[i] = new Gateway();
		gates[i]->debugId = i + 1;
		gates[i]->initConfig(client_ips[i], self_prefix + i, server_prefix + i);
	}
	std::thread recvUdp_ts[CLIENT_NUM];
	std::thread handle_ts[CLIENT_NUM];
	
	for(int i = 0; i < CLIENT_NUM; i++){
		recvUdp_ts[i] = std::thread(&recv_udp_thd, gates[i]);
		handle_ts[i] = std::thread(&handle_thd, gates[i]);
	}

	for(int i = 0; i < CLIENT_NUM; i++){
		recvUdp_ts[i].join();
		handle_ts[i].join();
	}
	recvEther_t.join();
}
#endif

