# ASock #

### What ###

A C++11 header-only, simple and easy cross-platform c++ socket server/client framework especially convenient for handling TCP fixed-length header and variable-length body. Of course, it also supports udp and domain socket.

- The framework calls the user-specified callback.
- For TCP, the total size of user data is passed to the framework via a callback, and the framework does TCP buffering automatically.
- No repeat send calls until all are sent. When send returns WSAEWOULDBLOCK / EWOULDBLOCK / EAGAIN, It will be added to the queue and sent later.
- linux, os x : tcp, udp, domain socket using epoll and kqueue.
- windows : tcp, udp using winsock.


### Install ###

Just copy all `*.hpp` header files to your project. And include `ASock.hpp`

### Usage ###

#### tcp echo server ####


```cpp
// msg_defines.h
// See the sample folder for all examples.  
// This is an inheritance usage.  
// you can find composition usage and udp, domain socket example too.

// user specific data
typedef struct _ST_MY_CHAT_HEADER_ {
    char msg_len[10+1];
} ST_MY_HEADER ;
#define CHAT_HEADER_SIZE sizeof(ST_MY_HEADER)
```

```cpp
// echo_server.cpp

#include <iostream>
#include <cassert>
#include <csignal>

#include "ASock.hpp"
#include "../../msg_defines.h"

class EchoServer : public asock::ASock {
  private:
    size_t  OnCalculateDataLen(asock::Context* context_ptr);
    bool    OnRecvedCompleteData(asock::Context* context_ptr, char* data_ptr, size_t len ) ;
    void    OnClientConnected(asock::Context* context_ptr) ; 
    void    OnClientDisconnected(asock::Context* context_ptr) ; 
};

size_t EchoServer::OnCalculateDataLen(asock::Context* context_ptr) {
    //---------------------------------------------------
    //user specific : 
    //calculate your complete packet length here using buffer data.
    //---------------------------------------------------
    if(context_ptr->recv_buffer.GetCumulatedLen() < (int)CHAT_HEADER_SIZE ) {
        return asock::MORE_TO_COME ; //more to come 
    }
    ST_MY_HEADER header ;
    context_ptr->recv_buffer.PeekData(CHAT_HEADER_SIZE, (char*)&header); 
    size_t supposed_total_len = std::atoi(header.msg_len) + CHAT_HEADER_SIZE;
    assert(supposed_total_len<=context_ptr->recv_buffer.GetCapacity());
    return supposed_total_len ;
}

bool EchoServer::OnRecvedCompleteData(asock::Context* context_ptr, 
                                         char* data_ptr, size_t len ) {
    //user specific : - your whole data has arrived.
    char packet[asock::DEFAULT_PACKET_SIZE];
    memcpy(&packet, data_ptr + CHAT_HEADER_SIZE, len - CHAT_HEADER_SIZE);
    packet[len - CHAT_HEADER_SIZE] = '\0';
    std::cout << "recved [" << packet << "]\n";
    // this is echo server
    if(! SendData(context_ptr, data_ptr, len) ) {
        std::cerr <<"["<< __func__ <<"-"<<__LINE__ <<"] error! "<< GetLastErrMsg() <<"\n"; 
        return false;
    }
    return true;
}

void EchoServer::OnClientConnected(asock::Context* context_ptr) {
    std::cout << "client connected : socket fd ["<< context_ptr->socket <<"]\n";
}

void EchoServer::OnClientDisconnected(asock::Context* context_ptr) {
    std::cout << "client disconnected : socket fd ["<< context_ptr->socket <<"]\n";
}

int main(int argc, char* argv[]) {
    //max client is 100000, 
    //max message length is approximately 1024 bytes...
    EchoServer echoserver; 
    if(!echoserver.InitTcpServer("127.0.0.1", 9990, 1024 /*,default=100000*/)) {
        std::cerr <<"["<< __func__ <<"-"<<__LINE__ <<"] error! "<< echoserver.GetLastErrMsg() <<"\n"; 
        return 1;
    }
    std::cout << "server started" << "\n";
    while( echoserver.IsServerRunning() ) {
		std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::cout << "server exit...\n";
    return 0;
}

```

#### tcp echo client ####

```cpp
#include <iostream>
#include <string>
#include <cstdlib>
#include <stdio.h>
#include <cassert>
#include "ASock.hpp"
#include "../../msg_defines.h"

class EchoClient : public asock::ASock
{
  private:
    size_t  OnCalculateDataLen(asock::Context* context_ptr); 
    bool    OnRecvedCompleteData(asock::Context* context_ptr, 
                                 char* data_ptr, size_t len); 
    void    OnDisconnectedFromServer() ; 
};

size_t EchoClient::OnCalculateDataLen(asock::Context* context_ptr) {
    //user specific : calculate your complete packet length 
    if( context_ptr->recv_buffer.GetCumulatedLen() < (int)CHAT_HEADER_SIZE ) {
        return asock::MORE_TO_COME ; //more to come 
    }
    ST_MY_HEADER header ;
    context_ptr->recv_buffer.PeekData(CHAT_HEADER_SIZE, (char*)&header);  
    size_t supposed_total_len = std::atoi(header.msg_len) + CHAT_HEADER_SIZE;
    assert(supposed_total_len<=context_ptr->recv_buffer.GetCapacity());
    return supposed_total_len ;
}

bool EchoClient:: OnRecvedCompleteData(asock::Context* context_ptr, 
                                       char* data_ptr, size_t len) {
    //user specific : - your whole data has arrived.
    char packet[asock::DEFAULT_PACKET_SIZE];
    memcpy(&packet, data_ptr + CHAT_HEADER_SIZE, len - CHAT_HEADER_SIZE);
    packet[len - CHAT_HEADER_SIZE] = '\0';
    std::cout << "server response [" << packet << "]\n";
    return true;
}

void EchoClient::OnDisconnectedFromServer() {
    std::cout << "* server disconnected ! \n";
    exit(1);
}

int main(int argc, char* argv[]) {
    EchoClient client;
    //connect timeout is 10 secs.
    //max message length is approximately 1024 bytes...
    if(!client.InitTcpClient("127.0.0.1", 9990, 10, 1024 ) ) {
        std::cerr <<"["<< __func__ <<"-"<<__LINE__ 
                  <<"] error! "<< client.GetLastErrMsg() <<"\n"; 
        return 1;
    }
    std::string user_msg  {""}; 
    while( client.IsConnected() ) {
        std::cin.clear();
        getline(std::cin, user_msg); 
        int msg_len = user_msg.length();
        if(msg_len>0) {
            ST_MY_HEADER header;
            snprintf(header.msg_len, sizeof(header.msg_len), "%d", (int)msg_len );
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
    } //while
    return 0;
}
```

#### sample compile ####

```sh
git clone https://github.com/jeremyko/ASock.git
cd ASock
mkdir build && cd build 
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 ..
make  # or msbuild(windows)
```
```

