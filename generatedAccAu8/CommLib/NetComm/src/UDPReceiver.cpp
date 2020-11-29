#include "../include/UDPReceiver.hpp"


UDPReceiver::UDPReceiver(/* args */)
{
}

int UDPReceiver::receivePacket(u_char* dst, std::string ipStr, u_short portNum)
{
    std::cout << "INFO: receive Packet" << std::endl;
    int this_fd, ret;
    struct sockaddr_in target_addr;
    this_fd = socket(AF_INET, SOCK_DGRAM, 0);
    std::cout << "INFO: this_fd: " << this_fd << std::endl;
    if(this_fd < 0)
    {
        close(this_fd);
        std::cout << "ERROR: create socket failed: " << errno << std::endl;
		return 0;
    }
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    in_addr_t addr_dst;
    inet_aton(ipStr.c_str(), (in_addr*)&addr_dst);
    target_addr.sin_addr.s_addr = (uint32_t)addr_dst;
    target_addr.sin_port = htons(portNum);
    ret = bind(this_fd, (struct sockaddr*)&target_addr, sizeof(target_addr));
    if(ret < 0)
    {
        std::cout << "ERROR: bind failure:" <<errno<< std::endl;
        close(this_fd);
		return -1;
    }
    char recvBuf[1000];
    socklen_t len = 1000;
    struct sockaddr_in recv_target_addr;
    memset(recvBuf, 0, 1000);
    int count;
    std::cout << "INFO: receive from" << std::endl;
    count = recvfrom(this_fd, recvBuf, 1000, 0, (struct sockaddr*) &recv_target_addr, &len);
    std::cout << "INFO: receive from ends" << std::endl;
    if (count == -1) {
		std::cout << "ERROR: recv data failed: " << errno << std::endl;
        close(this_fd);
		return -2;
	}
    std::cout << "INFO: RECV BUF:" << recvBuf << std::endl;
    memcpy(dst, recvBuf, 1000);
    close(this_fd);
    return 1;
}

UDPReceiver::~UDPReceiver()
{
}
