// Implementazione delle funzioni write() e send() per il supporto UDP
// Da includere in libproxychains.c

// Intercettazione della funzione write() per gestire socket UDP
HOOKFUNC(ssize_t, write, int fd, const void *buf, size_t count) {
    INIT();
    PFUNC();
    
    // Verifichiamo se questo socket è un UDP socket con relay configurato
    int socktype;
    socklen_t optlen = sizeof(socktype);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &socktype, &optlen) == 0) {
        if (socktype == SOCK_DGRAM) {
            PDEBUG("write() chiamata su socket UDP (fd=%d)\n", fd);
            
            // Controlliamo se esiste un'associazione UDP per questo socket
            udp_relay_data *relay_info = get_udp_relay_info(fd);
            if (relay_info && relay_info->in_use) {
                PDEBUG("write() su socket UDP (fd=%d) con relay UDP configurato\n", fd);
                
                // Utilizziamo sendto() per inviare i dati attraverso il relay UDP
                // In questo caso, l'indirizzo di destinazione è NULL perché il socket è "connesso"
                return sendto(fd, buf, count, 0, NULL, 0);
            }
        }
    }
    
    // Se non è un socket UDP o non ha relay configurato, chiamiamo write() originale
    return true_write(fd, buf, count);
}

// Intercettazione della funzione send() per gestire socket UDP
HOOKFUNC(ssize_t, send, int sockfd, const void *buf, size_t len, int flags) {
    INIT();
    PFUNC();
    
    // Verifichiamo se questo socket è un UDP socket con relay configurato
    int socktype;
    socklen_t optlen = sizeof(socktype);
    if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &socktype, &optlen) == 0) {
        if (socktype == SOCK_DGRAM) {
            PDEBUG("send() chiamata su socket UDP (fd=%d)\n", sockfd);
            
            // Controlliamo se esiste un'associazione UDP per questo socket
            udp_relay_data *relay_info = get_udp_relay_info(sockfd);
            if (relay_info && relay_info->in_use) {
                PDEBUG("send() su socket UDP (fd=%d) con relay UDP configurato\n", sockfd);
                
                // Utilizziamo sendto() per inviare i dati attraverso il relay UDP
                // In questo caso, l'indirizzo di destinazione è NULL perché il socket è "connesso"
                return sendto(sockfd, buf, len, flags, NULL, 0);
            }
        }
    }
    
    // Se non è un socket UDP o non ha relay configurato, chiamiamo send() originale
    return true_send(sockfd, buf, len, flags);
}