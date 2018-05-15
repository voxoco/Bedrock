#include "libstuff.h"
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

        // int ret, len;
        mbedtls_net_context listen_fd, client_fd;
        // unsigned char buf[1024];
        const char *pers = "ssl_server";

        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config conf;
        mbedtls_x509_crt srvcert;
        mbedtls_pk_context pkey;


        mbedtls_net_init( &listen_fd );
        mbedtls_net_init( &client_fd );
        mbedtls_ssl_init( &ssl );
        mbedtls_ssl_config_init( &conf );

        mbedtls_x509_crt_init( &srvcert );
        mbedtls_pk_init( &pkey );
        mbedtls_entropy_init( &entropy );
        mbedtls_ctr_drbg_init( &ctr_drbg );

        mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_srv_crt,
                          mbedtls_test_srv_crt_len );
        mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_cas_pem,
                          mbedtls_test_cas_pem_len );
        mbedtls_pk_parse_key( &pkey, (const unsigned char *) mbedtls_test_srv_key,
                         mbedtls_test_srv_key_len, NULL, 0 );

        mbedtls_net_bind( &listen_fd, NULL, std::to_string(listenport).c_str(), MBEDTLS_NET_PROTO_TCP );
        mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) );
        mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT );
        mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );  

        mbedtls_ssl_conf_ca_chain( &conf, srvcert.next, NULL );
        mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey );
        mbedtls_ssl_setup( &ssl, &conf );

        int s = mbedtls_net_accept( &listen_fd, &client_fd,
                                    NULL, 0, NULL );
        mbedtls_ssl_set_bio( &ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL );
        mbedtls_ssl_handshake( &ssl );

        

        


        // int s = S_accept(port.s, addr, false);
        if (s > 0) {
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
