#include <iostream>
#include <string>
#include <cstdlib>
#include <stdio.h>
#include <cassert>
#include "ASock.hpp"
#include "../../msg_defines.h"

///////////////////////////////////////////////////////////////////////////////
class EchoClient : public asock::ASock
{
  private:
    bool OnRecvedCompleteData(asock::Context* context_ptr,char* data_ptr, size_t len); 
};

///////////////////////////////////////////////////////////////////////////////
bool EchoClient:: OnRecvedCompleteData(asock::Context* context_ptr,char* data_ptr, size_t len) {
    //user specific : - your whole data has arrived.
    char packet[asock::DEFAULT_PACKET_SIZE];
    memcpy(&packet, data_ptr + CHAT_HEADER_SIZE, len - CHAT_HEADER_SIZE);
    packet[len - CHAT_HEADER_SIZE] = '\0';
    std::cout << "server response [" << packet << "]\n";
    return true;
}

///////////////////////////////////////////////////////////////////////////////
int main(int argc, char* argv[]) {
    EchoClient client;
    //max message length is approximately 1024 bytes...
    if(!client.InitUdpClient("127.0.0.1", 9990, 1024 ) ) {
        std::cerr <<"["<< __func__ <<"-"<<__LINE__ <<"] error! "<< client.GetLastErrMsg() <<"\n"; 
        return 1;
    }
    std::cout << "client started" << "\n";
    std::string user_msg  {""}; 
    while( client.IsConnected() ) {
        std::cin.clear();
        getline(std::cin, user_msg); 
        int msg_len = user_msg.length();
        if(msg_len>0) {
            ST_MY_HEADER header;
            snprintf(header.msg_len, sizeof(header.msg_len), "%d", msg_len );
            char* complete_packet_data = new  char [1024] ;
            memcpy(complete_packet_data, (char*)&header,  sizeof(ST_MY_HEADER));
            memcpy(complete_packet_data+sizeof(ST_MY_HEADER), user_msg.c_str(),user_msg.length() );
            if(! client.SendToServer(complete_packet_data ,sizeof(ST_MY_HEADER)+  user_msg.length()) ) {
                std::cerr <<"["<< __func__ <<"-"<<__LINE__ <<"] error! " << client.GetLastErrMsg() <<"\n"; 
                delete [] complete_packet_data;
                return 1;
            }
            delete [] complete_packet_data;
        }
    }//while
    std::cout << "client exit...\n";
    return 0;
}

