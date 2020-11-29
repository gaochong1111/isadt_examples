#include "../generatedHeader/Server.h"


Server::Server(){
	this->__currentState = STATE___init;
}

Server::~Server(){
	
}

int Server::receive(){
	/*Add IP Str and portNUm here*/
	std::string IPStr_ = SELF_IP_STR;
	u_short portNum_ = SELF_PORT;
	this->breakListen = true;
	UDPReceiver  er;
	/*allocation for dst_ here*/
	while(this->breakListen){

		char* item = (char*)malloc(1000*sizeof(char));
		
		std::cout << "INFO: recving info: IP: " << IPStr_ << " port: " << portNum_ << std::endl;
		int result = er.receivePacket((u_char*)item, IPStr_, portNum_);

		std::cout << "INFO: recv item: " << static_cast<const void *>(item) << std::endl;
		if(result == 0 || result == -1 || result == -2){
			std::cout << "ERROR: receivePacket Error: " << std::dec <<result << std::endl;
			this->breakListen = false;
		}
		auth_header* auth_hdr = (auth_header*)item;
		std::cout << "INFO: UDP PACKET RECV" << std::endl;
		if(auth_hdr->type == 0x10){
			std::cout << "INFO: server: acAuthReq_g2s recv" << std::endl;
			AcAuthReq_G2S* itemitem = (AcAuthReq_G2S*)item;
			// JUDGEMENT OF IP
			itemitem->client_id;
			memcpy(&acAuthReq_g2s, item, sizeof(AcAuthReq_G2S));
			std::cout << "INFO: recv: " << item << std::endl;
			this->cq.Push(item);
		} else if(auth_hdr->type = 0x21){
			std::cout << "INFO: authQuAck recv" << std::endl;
			memcpy(&authQuAck, item, sizeof(AuthQuAck));
			std::cout << "INFO: recv: " << item << std::endl;
			this->cq.Push(item);
		} else {
			std::cout << "INFO: IGNORED" << std::endl;
			free(item);
		}
	}
	return 0;
}



int Server::send(u_char* data_, int length_){
	/*Add Ip Str and portNum here*/
	std::string IPStr_ = GATEWAY_IP_STR;
	u_short portNum_ = GATEWAY_PORT;
	UDPSender snd;
	/*Add length and data content to send here*/
	int result = snd.sendPacket(data_, length_, IPStr_, portNum_);
	// std::cout << "udp send: " << data_ << std::endl;
	return result;
}


void Server::Sign(unsigned char* msg, unsigned char* sig, size_t msglen){
	if (digital_sign(msg, msglen, usr_privkey, sig) == -1) {
        printf("ERROR: digital_sign failed\n");
    }
	// std::cout << "sign over" << std::endl;
}

bool Server::Verify(unsigned char* msg, unsigned char* sig, size_t msglen, int verify_id){
	if(digital_verify(sig, msg, msglen, verify_id, master_pubkey) == -1){
		std::cout << "ERROR: VERIFY FAILED !!!" << std::endl;
		return false;
	} else {
		std::cout << "INFO: VERIFY CORRECT..." << std::endl;
		return true;
	}
}

void Server::initConfig(std::string client_ip, ushort self_port, ushort gate_port){
	// init the ibe library
	ibe_init();
	// set server ip which is set by overall init
	this->serverId_int = inet_addr(SELF_IP_STR.c_str());
	// set client ip, gateway port and self port: respected to the object
	this->CLIENT_IP_STR = client_ip;
	this->SELF_PORT = self_port;
	this->GATEWAY_PORT = gate_port;
	this->clientId_int = inet_addr(CLIENT_IP_STR.c_str());
	// init the master private key and master public key
	unsigned char mprik[IBE_MASTER_PRIVKEY_LEN] = {0x40, 0x8c, 0xe9, 0x67};
	unsigned char mpubk[IBE_MASTER_PUBKEY_LEN] = {0x31, 0x57, 0xcd, 0x29, 0xaf, 0x13, 0x83, 0xb7, 0x5e, 0xa0};
	memcpy(this->master_privkey, mprik, IBE_MASTER_PRIVKEY_LEN);
	memcpy(this->master_pubkey, mpubk, IBE_MASTER_PUBKEY_LEN);
	// if (masterkey_gen(master_privkey, master_pubkey) == -1) {
    //         printf("masterkey_gen failed\n");
    // }
	// generate usr private key according to its serverId listening to
	// std::cout << "start user key gen" << std::endl;
    userkey_gen(this->serverId_int, this->master_privkey, this->usr_privkey);
	// std::cout << "start user key over" << std::endl;
	
}




void Server::SMLMainServer(){
	std::cout << "INFO: Server started" << std::endl;
	srand(NULL);
	//initConfig();
	while(__currentState != -100) {
		switch(__currentState){
			case STATE___init:{

				std::cout << "INFO: --------------------STATE___init" << std::endl;
				AcAuthReq_G2S* acAuthReq_g2s_result;
				while(true){
					char* item;
					std::cout << "INFO: pop" << std::endl;
					this->cq.Pop(item);
					std::cout << "INFO: pop over. item: " << static_cast<const void *>(item) << std::endl;
					auth_header* auth_hdr = (auth_header*) item;
					if(auth_hdr->type == 0x10){
						AcAuthReq_G2S tempItem;
						memcpy(&tempItem, item, sizeof(AcAuthReq_G2S));
						free(item);
						//std::cout << "tempItem: " << static_cast<const void *>(tempItem) << std::endl;
						int recvClientId = 0;
						memcpy(&recvClientId, &tempItem.client_id, sizeof(int));
						std::cout << std::hex << ntohl(recvClientId) << std::endl;
						std::cout << std::hex << this->clientId_int << std::endl;
						if(ntohl(recvClientId) == this->clientId_int){
							std::cout << "INFO: recvClient Id = clientId_int" << std::endl;
							acAuthReq_g2s_result= &tempItem;
							break;
						} else {
						}
					} else {
						free(item);
					}
				}
				std::cout << "INFO: out of the loop" << std::endl;
				memcpy(&this->acAuthReq_g2s, acAuthReq_g2s_result, sizeof(AcAuthReq_G2S));
				std::cout << "INFO: udp packet received" << std::endl;
				// free(acAuthReq_g2s_result);
				__currentState = STATE__reqRecved;
				break;
			}
			case STATE___final:
			{
				__currentState = -100;
				std::cout << "INFO: --------------------STATE___final" << std::endl;
				this->breakListen = false;
				break;
			}
			case STATE__reqRecved:
			{
				std::cout << "INFO: --------------------STATE__reqRecved" << std::endl;
				if(!Verify((unsigned char*)&acAuthReq_g2s, (unsigned char*)acAuthReq_g2s.gateway_signature, sizeof(AcAuthReq_G2S) - 16, Id2Int(acAuthReq_g2s.gateway_id))){
					__currentState = STATE__verifyReqFailed;
				}
				else {
					//clientId_int = Id2Int(acAuthReq_g2s.client_id);
					authQu.auth_hdr.length = htonl(sizeof(AuthQu) - sizeof(auth_header) - 16);
					authQu.auth_hdr.serial_num = htonl(ntohl(acAuthReq_g2s.auth_hdr.serial_num));
					authQu.auth_hdr.timestamp = htonl(ntohl(acAuthReq_g2s.auth_hdr.timestamp));
					authQu.auth_hdr.type = 0x20;
					authQu.auth_hdr.version = 1;
					int tempClientId = htonl(clientId_int);
					memcpy(&authQu.client_id, &tempClientId, sizeof(int));
					authQu.random_num_rs = htonl(clientId_int); 
					int tempServerId = htonl(serverId_int);
					memcpy(&authQu.server_id, &tempServerId, sizeof(int));
					Sign((unsigned char*)&authQu, authQu.server_signature, sizeof(AuthQu) - 16);
				__currentState = STATE__queCreated;
				}
				break;
			}
				
			case STATE__queCreated:
			{
				
					std::cout << "INFO: --------------------STATE__queCreated" << std::endl;
					char* sendData;
					sendData = (char*)malloc(sizeof(AuthQu));
					memcpy(sendData, &authQu, sizeof(AuthQu));
					send((u_char*)sendData, sizeof(AuthQu));
					free(sendData);
					__currentState = STATE__queSent;

				
				break;
			}
			case STATE__verifyReqFailed:{
				std::cout << "INFO: --------------------STATE__verifyReqFailed" << std::endl;
				
				__currentState = STATE___final;
				
				break;}
			case STATE__queSent:{
				std::cout << "INFO: --------------------STATE__queSent" << std::endl;
				
				AuthQuAck* authQuAck_result;
				AcAuthReq_G2S* acAuthReq_g2s_result;
				while(true){
					char* item;
					this->cq.Pop(item);
					auth_header* auth_hdr = (auth_header*) item;
					if(auth_hdr->type == 0x21){
						AcAuthReq_G2S* tempItem = (AcAuthReq_G2S*) item;
						int recvClientId = 0;
						memcpy(&recvClientId, &tempItem->client_id, sizeof(int));
						std::cout << std::hex << "INFO: " << ntohl(recvClientId) << std::endl;
						std::cout << std::hex << "INFO: " <<this->clientId_int << std::endl;
						if(ntohl(recvClientId) == this->clientId_int){
							authQuAck_result = (AuthQuAck*) tempItem;
							break;
						} else {
							free(item);
						}
					} else if(auth_hdr->type = 0x10){
						AcAuthReq_G2S* tempItem = (AcAuthReq_G2S*) item;
						int recvClientId = 0;
						memcpy(&recvClientId, &tempItem->client_id, sizeof(int));
						if(ntohl(recvClientId) == this->clientId_int){
							acAuthReq_g2s_result= tempItem;
							memcpy(&acAuthReq_g2s, acAuthReq_g2s_result, sizeof(AcAuthReq_G2S));
							__currentState = STATE__reqRecved;
							break;
						}
					} else {
						free(item);
					}
				}
				memcpy(&authQuAck, authQuAck_result, sizeof(AuthQuAck));
				std::cout << "INFO: udp packet received" << std::endl;
				free(authQuAck_result);
				__currentState = STATE__queRespRecved;
				
				break;}
			case STATE__queRespRecved:{
				std::cout << "INFO: --------------------STATE__queRespRecved" << std::endl;

				if(!Verify((unsigned char*)&authQuAck, (unsigned char*)authQuAck.client_signature, sizeof(AuthQuAck) - 16, Id2Int(authQuAck.client_id))){
					__currentState = STATE__verifyQueRespFailed;
				}
				else {
					bool result = true;
					std::cout << "INFO: Serial number test" << std::endl;
					if(ntohl(authQuAck.auth_hdr.serial_num) == ntohl(authQu.auth_hdr.serial_num)){
						std::cout << "INFO: PASSED" << std::endl;
					} else {
						result = false;
						std::cout << "ERROR: FAILED" << std::endl;
					}
					std::cout << "INFO: Timestamp test" << std::endl;
					if(ntohl(authQuAck.auth_hdr.timestamp) == ntohl(authQu.auth_hdr.timestamp)){
						std::cout << "INFO: PASSED" << std::endl;
					} else {
						result = false;
						std::cout << "ERROR: FAILED" << std::endl;
					}
					std::cout << "INFO: Random number test"  << std::endl;
					if(ntohl(authQuAck.random_number_rs) == ntohl(authQu.random_num_rs)){
						std::cout << "INFO: PASSED: " <<  ntohl(authQuAck.random_number_rs) << " and " << ntohl(authQu.random_num_rs)<< std::endl;
					} else {
						result = false;
						std::cout << "ERROR: FAILED: " <<  ntohl(authQuAck.random_number_rs) << " and " << ntohl(authQu.random_num_rs)<< std::endl;
					}
					if(!result){
						std::cout << "ERROR: entries matching problem of authQuAck" << std::endl;
					}
					acAuthAns.auth_hdr.length = htonl(sizeof(AcAuthAns) - sizeof(auth_header) - 16);
					acAuthAns.auth_hdr.serial_num = htonl(ntohl(authQuAck.auth_hdr.serial_num));
					acAuthAns.auth_hdr.timestamp = htonl(ntohl(authQuAck.auth_hdr.timestamp));
					acAuthAns.auth_hdr.type =  0x11;
					acAuthAns.auth_hdr.version = 1;
					int resultInt = result;
					int tempClientId = 0;
					memcpy(&tempClientId, &authQuAck.client_id, sizeof(int));
					int temptempClient = htonl(ntohl(tempClientId));
					memcpy(&acAuthAns.client_id, &temptempClient, sizeof(int));
					acAuthAns.auth_result = htonl(resultInt);
					acAuthAns.authorization = htonl(0);
					memcpy(&acAuthAns.client_ip_and_mask[0], &temptempClient, sizeof(int));
					int mask= 0xffffff00;
					int tempMask = htonl(mask);
					memcpy(&acAuthAns.client_ip_and_mask[1], &tempMask, sizeof(int));
					int tempGateId = 0;
					memcpy(&tempGateId, & acAuthReq_g2s.gateway_id, sizeof(int));
					int temptempGateId = htonl(ntohl(tempGateId));
					memcpy(&acAuthAns.gateway_ip, &temptempGateId, sizeof(int));
					// TODO: set prikey here.
					memcpy(&acAuthAns.client_ip_prikey, &usr_privkey, 14);
					acAuthAns.random_num_rs = htonl(ntohl(authQuAck.random_number_rs));
					int tempServerId = htonl(serverId_int);
					memcpy(&acAuthAns.server_id, &tempServerId, sizeof(int));
					Sign((unsigned char*)&acAuthAns, (unsigned char*)&acAuthAns.server_signature, sizeof(AcAuthAns) - 16);
				__currentState = STATE__authRespCreated;
				}
				break;}
			case STATE__authRespCreated:{
				std::cout << "INFO: --------------------STATE__authRespCreated" << std::endl;
				char* sendData = (char*)malloc(sizeof(AcAuthAns));
				memcpy(sendData, &acAuthAns, sizeof(AcAuthAns));
				send((u_char*)sendData, sizeof(AcAuthAns));
				__currentState = STATE___final;
				
				break;}
			case STATE__verifyQueRespFailed:{
				std::cout << "INFO: --------------------STATE__verifyQueRespFailed" << std::endl;
				
				__currentState = STATE___final;
				this->breakListen = false;
				break;}
			default: break;
		}
	}
}

