#include "libstuff.h"
#include "SSSLState.h"

#include <mbedtls/certs.h>

STCPServer::STCPServer(const string& host) {
    // Initialize
    if (!host.empty()) {
        openPort(host);
    }
}

STCPServer::~STCPServer() {
    // Close all ports
    closePorts();
}

STCPServer::Port* STCPServer::openPort(const string& host) {
    // Open a port on the requested host
    SASSERT(SHostIsValid(host));
    Port port;
    port.host = host;
    port.s = S_socket(host, true, true, false);
    SASSERT(port.s >= 0);
    lock_guard <decltype(portListMutex)> lock(portListMutex);
    list<Port>::iterator portIt = portList.insert(portList.end(), port);
    return &*portIt;
}

void STCPServer::closePorts(list<Port*> except) {
    // Are there any ports to close?
    lock_guard <decltype(portListMutex)> lock(portListMutex);
    if (!portList.empty()) {
        // Loop across and close all ports not excepted.
        auto it = portList.begin();
        while (it != portList.end()) {
            if  (find(except.begin(), except.end(), &(*it)) == except.end()) {
                // Close this port
                ::close(it->s);
                SINFO("Close ports closing " << it->host << ".");
                it = portList.erase(it);
            } else {
                SINFO("Close ports skipping " << it->host << ": in except list.");
                it++;
            }
        }
    } else {
        SHMMM("Ports already closed.");
    }
}

STCPManager::Socket* STCPServer::acceptSocket(Port*& portOut) {
    // Initialize to 0 in case we don't accept anything. Note that this *does* overwrite the passed-in pointer.
    portOut = 0;
    Socket* socket = nullptr;

    // See if we can accept on any port
    lock_guard <decltype(portListMutex)> lock(portListMutex);
    for (Port& port : portList) {
        // Try to accept on the port and wrap in a socket
        
        sockaddr_in addr;
        SDEBUG("Port List addr " << addr << " port " << port.host);

        string domain;
        uint16_t listenport = 0;
        if (!SParseHost(port.host, domain, listenport)) {
            STHROW("invalid host: " + port.host);
        }
        // TO DO resolve domain names

        //unsigned int ip = inet_addr(domain.c_str());

        int s = S_accept(port.s, addr, false);

        
            
        if (s > 0) {
            if (listenport == 8810 || listenport == 8820 || listenport == 8830) {
                int ret;
                socket = new Socket(s, Socket::CONNECTED);

                SX509* x509;

                x509 = SX509Open();

                socket->ssl = SSSLOpen(s, x509);
                SDEBUG("SSL object for peer client created"); 

                SDEBUG("Accepting SSL socket from '" << addr << "' on port '" << port.host << "'");

                ret = SSSLServerHandshake(socket->ssl);
                SDEBUG("SERVER Handshake Loop " << SSSLError(ret));
                

                SDEBUG("Server handshake Loop done -- returned " << SSSLError(ret));

                if(ret>=0) {
                    ret = SSSLServerPostHandshake(socket->ssl);
                }
                
                socket->addr = addr;
                socketList.push_back(socket);

                // Try to read immediately
                //S_recvappend(socket->s, socket->recvBuffer);
                SSSLRecvAppend(socket->ssl, socket->recvBuffer);

                SDEBUG("Received " << socket->recvBuffer);

                // Record what port it was accepted on
                portOut = &port;
                
            } else {
                // Received a socket, wrap
                SDEBUG("Accepting socket from '" << addr << "' on port '" << port.host << "'");
                socket = new Socket(s, Socket::CONNECTED);
                socket->addr = addr;
                socketList.push_back(socket);

                // Try to read immediately
                S_recvappend(socket->s, socket->recvBuffer);

                // Record what port it was accepted on
                portOut = &port;
            }
        }
    }

    return socket;
}

void STCPServer::prePoll(fd_map& fdm) {
    // Call the base class
    STCPManager::prePoll(fdm);

    // Add the ports
    lock_guard <decltype(portListMutex)> lock(portListMutex);
    for (Port& port : portList) {
        SFDset(fdm, port.s, SREADEVTS);
    }
}

void STCPServer::postPoll(fd_map& fdm) {
    // Process all the existing sockets.
    // FIXME: Detect port failure
    STCPManager::postPoll(fdm);
}
