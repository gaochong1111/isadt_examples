#include "../generatedHeader/Host.h"
#include <bitset>
bool macEqualToBroad(u_char mac[6]){
	for(int i = 0; i < 6; i ++){
		if(mac[i] != 0xff){
			return false;
		}
	}
	return true;
}

bool macEqualToSelf(u_char mac[6]){
	for(int i = 0; i < 6; i ++){
		if(mac[i] != (u_char)client_mac[i]){  
			return false;
		}
	}
	return true;
}

static void dataHandlerHostReceive(u_char* param, const struct pcap_pkthdr* header, const u_char* packetData){
	ether_header* eh;
	eh = (ether_header*)packetData;
	/*Configure your own prootcol number of ethernet frame*/
	if(ntohs(eh->type) == 0x888f && (macEqualToBroad(eh->h_dest) || macEqualToSelf(eh->h_dest))){
		std::cout << "INFO: ETHER RECEIVED:" << std::endl;
		auth_header* authHead = (auth_header*)((char*)packetData + sizeof(ether_header));
		u_char type_num = authHead->type;
		std::cout << "INFO: version: " << (int) authHead->version << std::endl;
		std::cout << "INFO: type num: " << (int)type_num << std::endl;
		if(type_num == 0x01){
			// broadcast
			std::cout << "INFO: client: broadcast received" << std::endl;
			char* saveData = (char*)malloc(sizeof(char)*100);
			memcpy(saveData, (char*)(packetData + sizeof(ether_header)), 100);
			cq.Push(saveData);
		} else if(type_num == 0x11){
			// response
			std::cout << "INFO: client: response received" << std::endl;
			char* saveData = (char*)malloc(sizeof(char)*100);
			memcpy(saveData, (char*)(packetData + sizeof(ether_header)), 100);
			cq.Push(saveData);
		} else if(type_num == 0x20){
			// authentication
			std::cout << "INFO: client: authqu received" << std::endl;
			char* saveData = (char*)malloc(sizeof(char)*100);
			memcpy(saveData, (char*)(packetData + sizeof(ether_header)), 100);
			// std::cout << "save" << std::endl;
			cq.Push(saveData);
			// std::cout << "client: authQu received" << std::endl;
			// if(tempDataHost != NULL){
			// 	free(tempDataHost);
			// }
			// tempDataHost = (char*)malloc(sizeof(char)*sizeof(AuthQu));
			// memcpy(tempDataHost, ((char*)packetData + sizeof(ether_header)), sizeof(AuthQu));
			// pcap_breakloop(devHost);
		} else {
			std::cout << "INFO: client: ignored" << std::endl;
		}
	}
}
int receive(){
	/*Configure your own implementation of length_*/
	int length_ = 0;
	u_char* data_ = (u_char*)malloc(length_*sizeof(u_char));
	u_char* dst_;	/*Add MAC Address here*/
	u_char mac[6];
	EtherReceiver er;
	pcap_if_t* dev = er.getDevice();
	char errbuf[500];
	pcap_t* selectedAdp = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
	devHost = selectedAdp;
	std::cout << dev->name << std::endl;
	/*Add self defined dataHandler to handle data received*/
	/*parameters: u_char* param, const struct pcap_pkthdr* header, const u_char* packetData*/
	er.listenWithHandler(devHost, dataHandlerHostReceive, data_);
	/*Add your own data processing logic here*/
	free(data_);
	int result;
	return result;

}
int Host::send(char* data_, int length, u_char dmac[6]){
	//2: request package
	//5: acknownledge
	/*Configure your own implementation of length_*/
	u_char mac[6];
	// set your client and gateway mac here
	// HEREEEEEEEEEEEEEEE
	mac[0] = client_mac[0];
	mac[1] = client_mac[1];
	mac[2] = client_mac[2];
	mac[3] = client_mac[3];
	mac[4] = client_mac[4];
	mac[5] = client_mac[5];
	EtherSender snd(mac);
	snd.getDevice();
	/*add your identifier of the sender*/
	std::cout << "INFO: send ether frame" << std::endl;
	int success =snd.sendEtherWithMac((u_char*)data_, length, dmac);
	int result;
	return result;

}
void Host::Sign(unsigned char* msg, unsigned char* sig, size_t msglen){
	 if (digital_sign(msg, msglen, usr_privkey, sig) == -1) {
         printf("ERROR: digital_sign failed\n");
     }
	 std::cout << "INFO: sign over" << std::endl;
}

bool Host::Verify(unsigned char* msg, unsigned char* sig, size_t msglen, int verify_id){
	if(digital_verify(sig, msg, msglen, verify_id, master_pubkey) == -1){
		std::cout << "ERROR: VERIFY FAILED !!!" << std::endl;
		return false;
	} else {
		std::cout << "INFO: VERIFY CORRECT..." << std::endl;
		return true;
	}
}
void Host::initConfig(){
	ibe_init();
	std::cout << "INFO: self ip str: " << SELF_IP_STR << std::endl;
	clientId_int = inet_addr(SELF_IP_STR.c_str());
	std::cout << "INFO: client id: " << std::hex << clientId_int<< std::endl;
	unsigned char mprik[IBE_MASTER_PRIVKEY_LEN] = {0x40, 0x8c, 0xe9, 0x67};
	unsigned char mpubk[IBE_MASTER_PUBKEY_LEN] = {0x31, 0x57, 0xcd, 0x29, 0xaf, 0x13, 0x83, 0xb7, 0x5e, 0xa0};
	memcpy(master_privkey, mprik, IBE_MASTER_PRIVKEY_LEN);
	memcpy(master_pubkey, mpubk, IBE_MASTER_PUBKEY_LEN);
	client_mac[0]= 0x48;
	client_mac[1]= 0x2a;
	client_mac[2]= 0xe3;
	client_mac[3]= 0x60;
	client_mac[4]= 0x31;
	client_mac[5]= 0xfa;
	std::cout << "INFO: start user key gen" << std::endl;
    userkey_gen(clientId_int, master_privkey, usr_privkey);
	std::cout << "INFO: start user key over" << std::endl;
}


int Id2Int(ip_address ip){
	int result;
	memcpy(&result, &ip, sizeof(int));
	int res = ntohl(result);
	return res;
}

bool Host::IPEqual(ip_address* ip1, int clientidnum){
		int tempip1 = 0;
		memcpy(&tempip1, ip1, sizeof(int));
		if(ntohl(tempip1) == clientidnum){
			   return true;
		} else {
			return false;
		}
}


void recv_thd(){
	// recv and push the data into que
	std::cout << "INFO: start recving" << std::endl;
	receive();
}

void handle_thd(char*& item, u_char type){
	while(true){
		char* tempItem;
		cq.Pop(tempItem);
		auth_header* temp_hdr = (auth_header*)tempItem;
		if(temp_hdr->type == type){
			item = tempItem;
			std::cout << item << std::endl;
			break;
		} else {
			free(tempItem);
		}
	}
}

void Host::SMLMainHost(){
	srand(NULL);
	initConfig();
	std::thread recv_t(&recv_thd);

	struct timeval start, end;


	while(__currentState != -100) {
		switch(__currentState){
			case STATE___init:{
				std::cout << "INFO: --------------------STATE___init" << std::endl;
					time_t t;
					
					char* item;
					u_char type = 0x01;
					handle_thd(item, type);
					memset(&gwAnce, 0, sizeof(GwAnce));
					memcpy(&gwAnce, item, sizeof(GwAnce));
					for(int i = 0; i < sizeof(GwAnce); i++){
						if(i % 16 == 0){
							std::cout << std::endl;
						}
						std::cout << " " << std::hex << (unsigned short)((char*)&gwAnce)[i];
					}
					if(!Verify((unsigned char*)&gwAnce, gwAnce.signature, sizeof(GwAnce) - 16, Id2Int(gwAnce.gateway_id))){
						
					} else {
					std::cout << "INFO: client: GwAnce received" << std::endl;
					memset(&acAuthReq_c2g, 0, sizeof(AcAuthReq_C2G));
					acAuthReq_c2g.auth_hdr.length = htons(sizeof(AcAuthReq_C2G) - sizeof(auth_header) - 16);
					acAuthReq_c2g.auth_hdr.serial_num = htonl(ntohl(gwAnce.auth_hdr.serial_num));
					acAuthReq_c2g.auth_hdr.timestamp = htonl(ntohl(gwAnce.auth_hdr.timestamp));
					acAuthReq_c2g.gateway_random_number = htonl(ntohl(gwAnce.gateway_random_number));
					acAuthReq_c2g.auth_hdr.type = 0x10;
					acAuthReq_c2g.auth_hdr.version = 1;
					//TODO: CONFIGURE THE CLIENT IP
					int tempId = htonl(clientId_int);
					memcpy(&acAuthReq_c2g.client_id, &tempId, sizeof(int));
					//TODO: CONFIGURE THE CLIENT MAC
					
					acAuthReq_c2g.client_mac[0] = client_mac[0];
					acAuthReq_c2g.client_mac[1] = client_mac[1];
					acAuthReq_c2g.client_mac[2] = client_mac[2];
					acAuthReq_c2g.client_mac[3] = client_mac[3];
					acAuthReq_c2g.client_mac[4] = client_mac[4];
					acAuthReq_c2g.client_mac[5] = client_mac[5];
					memcpy(&gatewayId_int, &gwAnce.gateway_id, sizeof(int));
					int converted = ntohl(gatewayId_int);
					int cc = htonl(converted);
					memcpy(&acAuthReq_c2g.gateway_id , &cc,  sizeof(int)); 
					// //TODO: add sign here
					// for(int i = 0; i < sizeof(AcAuthReq_C2G) - 16; i++){
					// 	if(i % 16 == 0){
					// 		std::cout << std::endl;
					// 	}
					// 	std::cout << " " << std::hex << (unsigned short)((char*)&acAuthReq_c2g)[i];
					// }

					Sign((unsigned char*)&acAuthReq_c2g, acAuthReq_c2g.client_signature, sizeof(AcAuthReq_C2G) - 16);
					// for(int i = 0; i < 16; i++){
					// 	std::cout << std::hex << (ushort)acAuthReq_c2g.client_signature[i] << std::endl;
					// }
				__currentState = STATE__reqMsgCreated;
				}
				break;}
			case STATE___final:{
				__currentState = -100;
				std::cout << "INFO: --------------------STATE___final" << std::endl;
				break;}
			case STATE__reqMsgCreated:{
				std::cout << "INFO: --------------------STATE__reqMsgCreated" << std::endl;
					
					char* sendData = (char*)malloc(sizeof(AcAuthReq_C2G) * sizeof(char));
					memcpy(sendData, &acAuthReq_c2g, sizeof(AcAuthReq_C2G));
					
					
					// std::cout << "send: " << std::oct << sendData << std::endl;
					// CONFIGURE THE DMAC BY HELLO PACKET
					u_char* dmac = gwAnce.gateway_mac;
					// for(int i = 0; i < 6; i++){
					// 	std::cout << std::hex << (u_short)dmac[i] << " ";
					// }
					std::cout << "INFO: REQUEST:" << std::endl;
					gettimeofday(&start, NULL);
					send(sendData, sizeof(AcAuthReq_C2G), dmac);

				
					free(sendData);
				__currentState = STATE__reqSent;
				
				break;}
			case STATE__reqSent:{
				std::cout << "INFO: --------------------STATE__reqSent" << std::endl;
				
				char* item;
				u_char type = 0x20;
				handle_thd(item, type);
				
				memcpy(&authQu, item, sizeof(AuthQu));
				__currentState = STATE__queRecieved;
				break;}
			case STATE__queRecieved:{
				std::cout << "INFO: --------------------STATE__queRecieved" << std::endl;
				//TODO add verify here
				if(!Verify((unsigned char*)&authQu, (unsigned char*)authQu.server_signature, sizeof(AuthQu) - 16, Id2Int(authQu.server_id))){
					__currentState = STATE__verifyAuthQueFailed;
				} else {
					std::cout << "INFO: identity judgement" << std::endl;
					if(!this->IPEqual(&authQu.client_id, this->clientId_int)){
						std::cout << "ERROR: receive client id error" << std::endl;
					} else {
						std::cout << "INFO: PASSED" << std::endl;
					}
					std::cout << "INFO: serial number consistency judgement" << std::endl;
					if(ntohl(authQu.auth_hdr.serial_num) != ntohl(gwAnce.auth_hdr.serial_num)){
						std::cout << "ERROR: serial_num inconsistent" << std::endl;
					} else {
						std::cout << "INFO: PASSED" << std::endl;
					}
					authQuAck.auth_hdr.version = 1;
					random_number_rs = ntohl(authQu.random_num_rs);
					authQuAck.auth_hdr.length = htons(sizeof(AuthQuAck) - sizeof(auth_header) - 16);
					authQuAck.auth_hdr.serial_num = htonl(ntohl(authQu.auth_hdr.serial_num));
					authQuAck.auth_hdr.timestamp = htonl(ntohl(authQu.auth_hdr.timestamp));
					authQuAck.auth_hdr.type = 0x21;
					int tempId = htonl(this->clientId_int);
					memcpy(&authQuAck.client_id, &tempId, sizeof(int));
					authQuAck.random_number_rs = htonl(ntohl(authQu.random_num_rs));
					std::cout << "INFO: authQuAck random rs: " << authQuAck.random_number_rs << std::endl;
					memset(authQuAck.client_signature, 0, 16);
					Sign((unsigned char*)&authQuAck, (unsigned char*)authQuAck.client_signature, sizeof(AuthQuAck) - 16);
					__currentState = STATE__queRespCreated;
				}
				break;}
			case STATE__queRespCreated:{
				std::cout << "INFO: --------------------STATE__queRespCreated" << std::endl;
					char* sendData = (char*)malloc(sizeof(AuthQuAck) * sizeof(char));

					memcpy(sendData, &authQuAck, sizeof(AuthQuAck));
					// CONFIGURE THE MAC HERE
					u_char dmac[6];
					for(int i = 0; i < 6; i++){
						dmac[i] = gwAnce.gateway_mac[i];
					}
					std::cout << "INFO: send: " << sendData << std::endl;
					send(sendData, sizeof(AuthQuAck), dmac);
					free(sendData);
				__currentState = STATE__queRespSent;
				
				break;
			}
			case STATE__verifyAuthQueFailed:{
				std::cout << "INFO: --------------------STATE__verifyAuthQueFailed" << std::endl;
				
				__currentState = STATE___final;
				
				break;}
			case STATE__queRespSent:{
				std::cout << "INFO: --------------------STATE__queRespSent" << std::endl;
				
				char* item;
				u_char type = 0x11;
				handle_thd(item, type);
					//receive();

				memcpy(&acAuthAns, item, sizeof(AcAuthAns));
				__currentState = STATE__respRecved;
				
				break;}
			case STATE__respRecved:{
				std::cout << "INFO: --------------------STATE__respRecved" << std::endl;

				//TODO: add verify
				if(Verify((unsigned char*)&acAuthAns, (unsigned char*)acAuthAns.server_signature, sizeof(AcAuthAns) - 16, Id2Int(acAuthAns.server_id))){
					//hostIpSk = SymDec(authRespMsg.secHostIpSk,hostIdSk);
					std::cout << "INFO: VERIFY CORRECT..." << std::endl;
					gettimeofday(&end, NULL);
					std::cout << "INFO: SUCCESS: SERVER CONNECTED" << std::endl;
					int timeused = 1000000*(end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
					std::cout << "INFO: TIME COST: " << std::dec << (int)timeused/1000 << "ms" << std::endl;
					__currentState = STATE___final;
				}
				else {
					
					std::cout << "INFO: VERIFY FAILED !!!" << std::endl;
					__currentState = STATE__verifyAuthRespFailed;
				}
				break;}
			case STATE__verifyAuthRespFailed:{
				std::cout << "INFO: --------------------STATE__verifyAuthRespFailed" << std::endl;
				
				__currentState = STATE___final;
				
				break;}
			default: break;
		}
	}
	recv_t.join();
}


