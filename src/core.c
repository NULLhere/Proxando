/***************************************************************************
                          core.c  -  description
                             -------------------
    begin                : Tue May 14 2002
    copyright            :  netcreature (C) 2002
    email                : netcreature@users.sourceforge.net
 ***************************************************************************
 *     GPL *
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>

// Dichiarazione extern per accedere alla modalità UDP forzata
extern int proxychains_force_udp_mode;

#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>

#include "core.h"
#include "common.h"
#include "rdns.h"
#include "mutex.h"

// Array per memorizzare le associazioni UDP
udp_relay_data udp_relays[MAX_UDP_SOCKETS];

// Mutex per proteggere l'array udp_relays
static pthread_mutex_t udp_relay_mutex = PTHREAD_MUTEX_INITIALIZER;

// Thread-local storage per i dati specifici di ogni thread
static pthread_key_t tls_key;
static pthread_once_t tls_key_once = PTHREAD_ONCE_INIT;

// Funzione di inizializzazione chiamata una sola volta
static void tls_key_init(void) {
    pthread_key_create(&tls_key, free);
}

// Funzione per ottenere i dati thread-local
thread_local_data* thread_get_data(void) {
    thread_local_data *data;
    
    // Assicuriamoci che la key sia inizializzata
    pthread_once(&tls_key_once, tls_key_init);
    
    // Ottieni i dati del thread o creali se non esistono
    data = pthread_getspecific(tls_key);
    if (!data) {
        data = calloc(1, sizeof(thread_local_data));
        if (data) {
            data->had_chain_failure = 0;
            pthread_setspecific(tls_key, data);
        }
    }
    
    return data;
}

// Funzione per impostare il flag di fallimento della catena
void set_chain_failure(void) {
    thread_local_data *data = thread_get_data();
    if (data) {
        data->had_chain_failure = 1;
    }
}

// Funzione per salvare l'associazione UDP
int save_udp_relay_info(int sockfd, const struct sockaddr *relay_addr, socklen_t relay_len,
                       const struct sockaddr *target_addr, socklen_t target_len, int control_sock) {
    int i, free_slot = -1;
    
    pthread_mutex_lock(&udp_relay_mutex);
    
    // Verifica se esiste già un'associazione per questo socket di controllo
    for (i = 0; i < MAX_UDP_SOCKETS; i++) {
        if (udp_relays[i].in_use && udp_relays[i].control_sock == control_sock) {
            // Aggiorna l'associazione esistente
            // Attenzione: non modificare la porta originale! Potrebbe essere in network byte order
            memcpy(&udp_relays[i].udp_relay, relay_addr, relay_len);
            udp_relays[i].udp_relay_len = relay_len;
            // Aggiorniamo il socket client
            udp_relays[i].client_sock = sockfd;
            
            // Debug del valore porta prima di salvarlo (solo per IPv4)
            if (relay_addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in*)relay_addr;
                uint16_t exact_port = sin->sin_port;  // SALVIAMO LA PORTA ESATTA
                PDEBUG("exact_port (save_udp_relay_info) = 0x%04x (%d)\n", exact_port, (int)exact_port);
                
                // FONDAMENTALE: Salviamo la porta esatta (senza conversioni)
                udp_relays[i].exact_relay_port = exact_port;
                PDEBUG("udp_relays[i].exact_relay_port = 0x%04x (%d)\n", udp_relays[i].exact_relay_port, (int)udp_relays[i].exact_relay_port);
                
                PDEBUG("AGGIORNAMENTO - UDP relay port: 0x%04x, salvata porta esatta\n", 
                      sin->sin_port);
            } else if (relay_addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)relay_addr;
                uint16_t exact_port = sin6->sin6_port;  // SALVIAMO LA PORTA ESATTA
                
                // FONDAMENTALE: Salviamo la porta esatta (senza conversioni)
                udp_relays[i].exact_relay_port = exact_port;
                
                PDEBUG("AGGIORNAMENTO - UDP relay port IPv6: 0x%04x, salvata porta esatta\n", 
                      sin6->sin6_port);
            }
            
            memcpy(&udp_relays[i].target, target_addr, target_len);
            udp_relays[i].target_len = target_len;
            pthread_mutex_unlock(&udp_relay_mutex);
            return i;
        }
        
        // Trova il primo slot libero
        if (!udp_relays[i].in_use && free_slot == -1) {
            free_slot = i;
        }
    }
    
    // Se non esiste già un'associazione, creane una nuova
    if (free_slot != -1) {
        udp_relays[free_slot].in_use = 1;
        udp_relays[free_slot].control_sock = control_sock;
        udp_relays[free_slot].client_sock = sockfd;
        
        PDEBUG("New UDP relay: control_sock=%d, client_sock=%d\n", control_sock, sockfd);
        
        // Debug del valore porta prima di salvarlo (solo per IPv4)
        if (relay_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in*)relay_addr;
            uint16_t exact_port = sin->sin_port;  // SALVIAMO LA PORTA ESATTA
            
            // FONDAMENTALE: Salviamo la porta esatta (senza conversioni)
            udp_relays[free_slot].exact_relay_port = exact_port;
            
            PDEBUG("CREAZIONE - UDP relay port: 0x%04x, salvata porta esatta\n", 
                  exact_port);
        } else if (relay_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)relay_addr;
            uint16_t exact_port = sin6->sin6_port;  // SALVIAMO LA PORTA ESATTA
            
            // FONDAMENTALE: Salviamo la porta esatta (senza conversioni)
            udp_relays[free_slot].exact_relay_port = exact_port;
            
            PDEBUG("CREAZIONE - UDP relay port IPv6: 0x%04x, salvata porta esatta\n", 
                  exact_port);
        }
        
        // Copia esatta senza manipolazione della porta
        memcpy(&udp_relays[free_slot].udp_relay, relay_addr, relay_len);
        udp_relays[free_slot].udp_relay_len = relay_len;
        memcpy(&udp_relays[free_slot].target, target_addr, target_len);
        udp_relays[free_slot].target_len = target_len;
        pthread_mutex_unlock(&udp_relay_mutex);
        return free_slot;
    }
    
    pthread_mutex_unlock(&udp_relay_mutex);
    return -1; // Nessuno slot libero
}

// Funzione per ottenere l'associazione UDP basata sul socket (sia client che di controllo)
udp_relay_data *get_udp_relay_info(int sockfd) {
    int i;
    
    PDEBUG("Looking for UDP relay info for socket %d\n", sockfd);
    pthread_mutex_lock(&udp_relay_mutex);
    
    // Prima cerchiamo un'associazione diretta con il socket di controllo
    for (i = 0; i < MAX_UDP_SOCKETS; i++) {
        if (udp_relays[i].in_use) {
            PDEBUG("Checking UDP relay[%d]: control_sock=%d, client_sock=%d\n", 
                   i, udp_relays[i].control_sock, udp_relays[i].client_sock);
        }
        
        // Verifichiamo se corrisponde al socket di controllo o al socket client
        if (udp_relays[i].in_use && 
            (udp_relays[i].control_sock == sockfd || udp_relays[i].client_sock == sockfd)) {
            
            PDEBUG("Found UDP relay for socket %d at index %d (control=%d, client=%d)\n", 
                   sockfd, i, udp_relays[i].control_sock, udp_relays[i].client_sock);
            pthread_mutex_unlock(&udp_relay_mutex);
            return &udp_relays[i];
        }
    }
    
    pthread_mutex_unlock(&udp_relay_mutex);
    PDEBUG("No UDP relay found for socket %d\n", sockfd);
    return NULL; // Nessuna associazione trovata
}

// Funzione per cancellare l'associazione UDP
void remove_udp_relay_info(int sockfd) {
    int i;
    
    PDEBUG("Removing UDP relay info for socket %d\n", sockfd);
    pthread_mutex_lock(&udp_relay_mutex);
    
    for (i = 0; i < MAX_UDP_SOCKETS; i++) {
        // MODIFICATO: Rimuoviamo l'associazione solo per i socket client (non di controllo)
        // In questo modo il socket di controllo TCP rimane attivo per mantenere l'associazione UDP
        // con il server SOCKS5 come richiesto dal protocollo
        if (udp_relays[i].in_use && udp_relays[i].client_sock == sockfd) {
            // Rimuovi l'associazione
            PDEBUG("Removing UDP relay at index %d (control=%d, client=%d)\n", 
                  i, udp_relays[i].control_sock, udp_relays[i].client_sock);
            udp_relays[i].in_use = 0;
            break;
        }
    }
    
    pthread_mutex_unlock(&udp_relay_mutex);
}

// Funzione per trovare l'indice dell'associazione UDP per un socket
int find_udp_relay_info(int sockfd) {
    int i;
    
    PDEBUG("Searching for UDP relay index for socket %d\n", sockfd);
    pthread_mutex_lock(&udp_relay_mutex);
    
    for (i = 0; i < MAX_UDP_SOCKETS; i++) {
        // Cerchiamo sia per socket di controllo che per socket client
        if (udp_relays[i].in_use && 
            (udp_relays[i].control_sock == sockfd || udp_relays[i].client_sock == sockfd)) {
            
            PDEBUG("Found UDP relay at index %d for socket %d (control=%d, client=%d)\n", 
                   i, sockfd, udp_relays[i].control_sock, udp_relays[i].client_sock);
            pthread_mutex_unlock(&udp_relay_mutex);
            return i;
        }
    }
    
    pthread_mutex_unlock(&udp_relay_mutex);
    PDEBUG("No UDP relay found for socket %d\n", sockfd);
    return -1; // Nessuna associazione trovata
}

extern int tcp_read_time_out;
extern int tcp_connect_time_out;
extern int proxychains_quiet_mode;
extern unsigned int proxychains_proxy_offset;
extern unsigned int remote_dns_subnet;

static int poll_retry(struct pollfd *fds, nfds_t nfsd, int timeout) {
        int ret;
        int time_remain = timeout;
        int time_elapsed = 0;

        struct timeval start_time;
        struct timeval tv;

        gettimeofday(&start_time, NULL);

        do {
                //printf("Retry %d\n", time_remain);
                ret = poll(fds, nfsd, time_remain);
                gettimeofday(&tv, NULL);
                time_elapsed = ((tv.tv_sec - start_time.tv_sec) * 1000 + (tv.tv_usec - start_time.tv_usec) / 1000);
                //printf("Time elapsed %d\n", time_elapsed);
                time_remain = timeout - time_elapsed;
        } while(ret == -1 && errno == EINTR && time_remain > 0);

        //if (ret == -1)
        //printf("Return %d %d %s\n", ret, errno, strerror(errno));
        return ret;
}

static void encode_base_64(char *src, char *dest, int max_len) {
        static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        int n, l, i;
        l = strlen(src);
        max_len = (max_len - 1) / 4;
        for(i = 0; i < max_len; i++, src += 3, l -= 3) {
                switch (l) {
                        case 0:
                                break;
                        case 1:
                                n = src[0] << 16;
                                *dest++ = base64[(n >> 18) & 077];
                                *dest++ = base64[(n >> 12) & 077];
                                *dest++ = '=';
                                *dest++ = '=';
                                break;
                        case 2:
                                n = src[0] << 16 | src[1] << 8;
                                *dest++ = base64[(n >> 18) & 077];
                                *dest++ = base64[(n >> 12) & 077];
                                *dest++ = base64[(n >> 6) & 077];
                                *dest++ = '=';
                                break;
                        default:
                                n = src[0] << 16 | src[1] << 8 | src[2];
                                *dest++ = base64[(n >> 18) & 077];
                                *dest++ = base64[(n >> 12) & 077];
                                *dest++ = base64[(n >> 6) & 077];
                                *dest++ = base64[n & 077];
                }
                if(l < 3)
                        break;
        }
        *dest++ = 0;
}

void proxychains_write_log(char *str, ...) {
        char buff[1024*4];
        va_list arglist;
        if(!proxychains_quiet_mode) {
                va_start(arglist, str);
                vsnprintf(buff, sizeof(buff), str, arglist);
                va_end(arglist);
                fprintf(stderr, "%s", buff);
                fflush(stderr);
        }
}

static int write_n_bytes(int fd, char *buff, size_t size) {
        int i = 0;
        size_t wrote = 0;
        for(;;) {
                i = write(fd, &buff[wrote], size - wrote);
                if(i <= 0)
                        return i;
                wrote += i;
                if(wrote == size)
                        return wrote;
        }
}

static int read_n_bytes(int fd, char *buff, size_t size) {
        int ready;
        size_t i;
        struct pollfd pfd[1];
        size_t bytes_read = 0;

        PDEBUG("read_n_bytes: tentativo di leggere %zu byte dal socket %d\n", size, fd);

        pfd[0].fd = fd;
        pfd[0].events = POLLIN;
        
        // Legge byte per byte, ma garantisce che leggiamo esattamente size byte
        for(i = 0; i < size; i++) {
                pfd[0].revents = 0;
                ready = poll_retry(pfd, 1, tcp_read_time_out);
                if(ready != 1 || !(pfd[0].revents & POLLIN)) {
                        PDEBUG("read_n_bytes: timeout o errore di poll dopo %zu byte\n", bytes_read);
                        if (bytes_read > 0) {
                                return bytes_read; // Ritorna i byte letti finora
                        }
                        return -1;
                }
                
                int res = read(fd, &buff[i], 1);
                if (res != 1) {
                        PDEBUG("read_n_bytes: errore di lettura dopo %zu byte: %s\n", 
                              bytes_read, strerror(errno));
                        if (bytes_read > 0) {
                                return bytes_read; // Ritorna i byte letti finora
                        }
                        return -1;
                }
                
                bytes_read++;
        }
        
        PDEBUG("read_n_bytes: letti con successo %zu byte\n", bytes_read);
        return (int) bytes_read;
}

static int timed_connect(int sock, const struct sockaddr *addr, socklen_t len) {
        int ret, value;
        socklen_t value_len;
        struct pollfd pfd[1];
        PFUNC();

        pfd[0].fd = sock;
        pfd[0].events = POLLOUT;
        fcntl(sock, F_SETFL, O_NONBLOCK);
        ret = true_connect(sock, addr, len);
        PDEBUG("\nconnect ret=%d\n", ret);
        
        if(ret == -1 && errno == EINPROGRESS) {
                ret = poll_retry(pfd, 1, tcp_connect_time_out);
                PDEBUG("\npoll ret=%d\n", ret);
                if(ret == 1) {
                        value_len = sizeof(socklen_t);
                        getsockopt(sock, SOL_SOCKET, SO_ERROR, &value, &value_len);
                        PDEBUG("\nvalue=%d\n", value);
                        if(!value)
                                ret = 0;
                        else
                                ret = -1;
                } else {
                        ret = -1;
                }
        } else {
#ifdef DEBUG
                if(ret == -1)
                        perror("true_connect");
#endif
                if(ret != 0)
                        ret = -1;
        }

        fcntl(sock, F_SETFL, !O_NONBLOCK);
        return ret;
}


#define INVALID_INDEX 0xFFFFFFFFU
#define BUFF_SIZE 1024  // used to read responses from proxies.
static int tunnel_to(int sock, ip_type ip, unsigned short port, proxy_type pt, char *user, char *pass, int socket_type) {
        char *dns_name = NULL;
        char hostnamebuf[MSG_LEN_MAX];
        size_t dns_len = 0;

        PFUNC();

        // we use ip addresses with 224.* to lookup their dns name in our table, to allow remote DNS resolution
        // the range 224-255.* is reserved, and it won't go outside (unless the app does some other stuff with
        // the results returned from gethostbyname et al.)
        // the hardcoded number 224 can now be changed using the config option remote_dns_subnet to i.e. 127
        if(!ip.is_v6 && proxychains_resolver >= DNSLF_RDNS_START && ip.addr.v4.octet[0] == remote_dns_subnet) {
                dns_len = rdns_get_host_for_ip(ip.addr.v4, hostnamebuf);
                if(!dns_len) goto err;
                else dns_name = hostnamebuf;
        }
        
        PDEBUG("host dns %s\n", dns_name ? dns_name : "<NULL>");

        size_t ulen = strlen(user);
        size_t passlen = strlen(pass);

        if(ulen > 0xFF || passlen > 0xFF || dns_len > 0xFF) {
                proxychains_write_log(LOG_PREFIX "error: maximum size of 255 for user/pass or domain name!\n");
                goto err;
        }

        int len;
        unsigned char buff[BUFF_SIZE];
        char ip_buf[INET6_ADDRSTRLEN];
        int v6 = ip.is_v6;
        
        switch (pt) {
                case RAW_TYPE: {
                        return SUCCESS;
                }
                break;
                case HTTP_TYPE:{
                        if(!dns_len) {
                                if(!inet_ntop(v6?AF_INET6:AF_INET,ip.addr.v6,ip_buf,sizeof ip_buf)) {
                                        proxychains_write_log(LOG_PREFIX "error: ip address conversion failed\n");
                                        goto err;
                                }
                                dns_name = ip_buf;
                        }
                        #define HTTP_AUTH_MAX ((0xFF * 2) + 1 + 1) /* 2 * 0xff: username and pass, plus 1 for ':' and 1 for zero terminator. */
                        char src[HTTP_AUTH_MAX];
                        char dst[(4 * HTTP_AUTH_MAX)];
                        if(ulen) {
                                snprintf(src, sizeof(src), "%s:%s", user, pass);
                                encode_base_64(src, dst, sizeof(dst));
                        } else dst[0] = 0;

                        uint16_t hs_port = ntohs(port);
                        len = snprintf((char *) buff, sizeof(buff),
                                       "CONNECT %s:%d HTTP/1.0\r\nHost: %s:%d\r\n%s%s%s\r\n",
                                        dns_name, hs_port,
                                        dns_name, hs_port,
                                        ulen ? "Proxy-Authorization: Basic " : dst,
                                        dst, ulen ? "\r\n" : dst);

                        if(len < 0 || len != send(sock, buff, len, 0))
                                goto err;

                        len = 0;
                        // read header byte by byte.
                        while(len < BUFF_SIZE) {
                                if(1 == read_n_bytes(sock, (char *) (buff + len), 1))
                                        len++;
                                else
                                        goto err;
                                if(len > 4 &&
                                   buff[len - 1] == '\n' &&
                                   buff[len - 2] == '\r' && buff[len - 3] == '\n' && buff[len - 4] == '\r')
                                        break;
                        }

                        // if not ok (200) or response greather than BUFF_SIZE return BLOCKED;
                        if(len == BUFF_SIZE || !(buff[9] == '2' && buff[10] == '0' && buff[11] == '0')) {
                                PDEBUG("HTTP proxy blocked: buff=\"%s\"\n", buff);
                                return BLOCKED;
                        }

                        return SUCCESS;
                }
                break;
                case SOCKS4_TYPE:{
                        if(v6) {
                                proxychains_write_log(LOG_PREFIX "error: SOCKS4 doesn't support ipv6 addresses\n");
                                goto err;
                        }
                        buff[0] = 4;    // socks version
                        buff[1] = 1;    // connect command
                        memcpy(&buff[2], &port, 2);     // dest port
                        if(dns_len) {
                                ip.addr.v4.octet[0] = 0;
                                ip.addr.v4.octet[1] = 0;
                                ip.addr.v4.octet[2] = 0;
                                ip.addr.v4.octet[3] = 1;
                        }
                        memcpy(&buff[4], &ip.addr.v4, 4);       // dest host
                        len = ulen + 1; // username
                        if(len > 1)
                                memcpy(&buff[8], user, len);
                        else {
                                buff[8] = 0;
                        }

                        // do socksv4a dns resolution on the server
                        if(dns_len) {
                                memcpy(&buff[8 + len], dns_name, dns_len + 1);
                                len += dns_len + 1;
                        }

                        if((len + 8) != write_n_bytes(sock, (char *) buff, (8 + len)))
                                goto err;

                        if(8 != read_n_bytes(sock, (char *) buff, 8))
                                goto err;

                        if(buff[0] != 0 || buff[1] != 90)
                                return BLOCKED;

                        return SUCCESS;
                }
                break;
                case SOCKS5_TYPE:{
                        int n_methods = ulen ? 2 : 1;
                        buff[0] = 5;    // version
                        buff[1] = n_methods ;   // number of methods
                        buff[2] = 0;    // no auth method
                        if(ulen) buff[3] = 2;    /// auth method -> username / password
                        if(2+n_methods != write_n_bytes(sock, (char *) buff, 2+n_methods))
                                goto err;

                        if(2 != read_n_bytes(sock, (char *) buff, 2))
                                goto err;

                        if(buff[0] != 5 || (buff[1] != 0 && buff[1] != 2)) {
                                if(buff[0] == 5 && buff[1] == 0xFF)
                                        return BLOCKED;
                                else
                                        goto err;
                        }

                        if(buff[1] == 2) {
                                // authentication
                                char in[2];
                                char out[515];
                                char *cur = out;
                                size_t c;
                                *cur++ = 1;     // version
                                c = ulen & 0xFF;
                                *cur++ = c;
                                memcpy(cur, user, c);
                                cur += c;
                                c = passlen & 0xFF;
                                *cur++ = c;
                                memcpy(cur, pass, c);
                                cur += c;

                                if((cur - out) != write_n_bytes(sock, out, cur - out))
                                        goto err;


                                if(2 != read_n_bytes(sock, in, 2))
                                        goto err;
        /* according to RFC 1929 the version field for the user/pass auth sub-
           negotiation should be 1, which is kinda counter-intuitive, so there
           are some socks5 proxies that return 5 instead. other programs like
           curl work fine when the version is 5, so let's do the same and accept
           either of them. */
                                if(!(in[0] == 5 || in[0] == 1))
                                        goto err;
                                if(in[1] != 0)
                                        return BLOCKED;
                        }
                        int buff_iter = 0;
                        buff[buff_iter++] = 5;  // version
                        
                        // Se è UDP o se abbiamo forzato la modalità UDP, usiamo il comando UDP ASSOCIATE (3) invece di CONNECT (1)
                        if (socket_type == SOCK_DGRAM || proxychains_force_udp_mode) {
                            buff[buff_iter++] = 3;  // UDP ASSOCIATE command
                            PDEBUG("SOCKS5 UDP Association requested\n");
                        } else {
                            buff[buff_iter++] = 1;  // CONNECT command (per TCP)
                        }
                        
                        buff[buff_iter++] = 0;  // reserved

                        if(!dns_len) {
                                buff[buff_iter++] = v6 ? 4 : 1; // ip v4/v6
                                memcpy(buff + buff_iter, ip.addr.v6, v6?16:4);  // dest host
                                buff_iter += v6?16:4;
                        } else {
                                buff[buff_iter++] = 3;  //dns
                                buff[buff_iter++] = dns_len & 0xFF;
                                memcpy(buff + buff_iter, dns_name, dns_len);
                                buff_iter += dns_len;
                        }

                        memcpy(buff + buff_iter, &port, 2);     // dest port
                        buff_iter += 2;


                        if(buff_iter != write_n_bytes(sock, (char *) buff, buff_iter))
                                goto err;

                        // Leggiamo prima l'header SOCKS5 (4 byte)
                        if(4 != read_n_bytes(sock, (char *) buff, 4))
                                goto err;

                        // Verifichiamo che l'header sia corretto
                        if(buff[0] != 5 || buff[1] != 0)
                                goto err;

                        // Determiniamo la lunghezza dell'indirizzo in base al tipo
                        switch (buff[3]) {
                                case 1:
                                        len = 4;
                                        break;
                                case 4:
                                        len = 16;
                                        break;
                                case 3:
                                        len = 0;
                                        if(1 != read_n_bytes(sock, (char *) &len, 1))
                                                goto err;
                                        break;
                                default:
                                        goto err;
                        }

                        // Salviamo l'header SOCKS5 che abbiamo appena letto
                        char header[4];
                        memcpy(header, buff, 4);
                        
                        // Leggiamo l'indirizzo e la porta nella parte successiva del buffer
                        // Alcuni proxy SOCKS5 non conformi potrebbero restituire una risposta incompleta
                        // Tentiamo di leggere fino alla fine anche se la risposta è più corta
                        int bytes_read = read_n_bytes(sock, (char *) buff + 4, len + 2);
                        if(bytes_read <= 0)
                                goto err;
                                
                        // Avvisiamo se la risposta è incompleta
                        if(bytes_read != len + 2) {
                            PDEBUG("AVVISO: Risposta SOCKS5 incompleta, letti %d byte invece di %d attesi\n", 
                                  bytes_read, len + 2);
                                  
                            // Proviamo a leggere i byte rimanenti della risposta
                            int remaining = (len + 2) - bytes_read;
                            if (remaining > 0) {
                                PDEBUG("Tentativo di leggere i restanti %d byte...\n", remaining);
                                int more_bytes = read_n_bytes(sock, (char *) buff + 4 + bytes_read, remaining);
                                
                                if (more_bytes > 0) {
                                    PDEBUG("Letti ulteriori %d byte\n", more_bytes);
                                    bytes_read += more_bytes;
                                }
                            }
                        }
                                
                        // Ripristiniamo l'header all'inizio del buffer
                        memcpy(buff, header, 4);
                        
                        // Verifichiamo se abbiamo almeno l'indirizzo e la porta per IPv4
                        int total_bytes = bytes_read + 4; // Aggiungiamo l'header
                        
                        // Per il comando UDP ASSOCIATE, salviamo l'indirizzo e la porta restituiti dal server
                        if (socket_type == SOCK_DGRAM || proxychains_force_udp_mode) {
                            PDEBUG("SOCKS5 UDP Association established\n");
                            
                            // Stampiamo il dump completo dei byte della risposta con interpretazione
                            PDEBUG("UDP ASSOCIATE RESPONSE RAW BYTES: ");
                            int expected_bytes = 0;
                            
                            // Calcola lunghezza attesa in base al tipo di indirizzo
                            if (buff[3] == 1) { // IPv4
                                expected_bytes = 10; // 4 (header) + 4 (IPv4) + 2 (porta)
                            } else if (buff[3] == 3) { // Domain
                                expected_bytes = 7 + buff[4]; // 4 (header) + 1 (len) + n (domain) + 2 (porta)
                            } else if (buff[3] == 4) { // IPv6
                                expected_bytes = 22; // 4 (header) + 16 (IPv6) + 2 (porta)
                            }
                            
                            printf("(Totale: %d byte, Attesi: %d byte)\n", total_bytes, expected_bytes);
                            
                            // Header SOCKS5 (4 byte)
                            printf("SOCKS5 HEADER: ");
                            if (total_bytes >= 4) {
                                printf("VER=%02x REP=%02x RSV=%02x ATYP=%02x", 
                                      (unsigned char)buff[0], 
                                      (unsigned char)buff[1], 
                                      (unsigned char)buff[2], 
                                      (unsigned char)buff[3]);
                            } else {
                                printf("INCOMPLETO (solo %d byte)", total_bytes);
                            }
                            printf("\n");
                            
                            // Indirizzo
                            printf("INDIRIZZO: ");
                            if (buff[3] == 1 && total_bytes >= 8) { // IPv4
                                printf("%d.%d.%d.%d", 
                                      (unsigned char)buff[4], 
                                      (unsigned char)buff[5], 
                                      (unsigned char)buff[6], 
                                      (unsigned char)buff[7]);
                            } else if (buff[3] == 4 && total_bytes >= 20) { // IPv6
                                printf("IPv6 (16 byte)");
                            } else if (buff[3] == 3 && total_bytes >= 5) { // Domain
                                int domain_len = buff[4];
                                printf("Domain (lunghezza: %d)", domain_len);
                            } else {
                                printf("NON RICONOSCIUTO o INCOMPLETO");
                            }
                            printf("\n");
                            
                            // Porta
                            printf("PORTA RAW: ");
                            int port_offset = 0;
                            if (buff[3] == 1) { // IPv4
                                port_offset = 8;
                            } else if (buff[3] == 4) { // IPv6
                                port_offset = 20;
                            } else if (buff[3] == 3) { // Domain
                                port_offset = 5 + buff[4];
                            }
                            
                            if (total_bytes >= port_offset + 2) {
                                printf("%02x %02x = ", 
                                      (unsigned char)buff[port_offset], 
                                      (unsigned char)buff[port_offset + 1]);
                                      
                                uint16_t port_value = ((unsigned char)buff[port_offset] << 8) | 
                                                      (unsigned char)buff[port_offset + 1];
                                printf("%d (decimale)", port_value);
                            } else {
                                printf("INCOMPLETA (necessari %d byte, disponibili solo %d)", 
                                      port_offset + 2, total_bytes);
                            }
                            printf("\n");
                            
                            // Dump completo per confronto
                            printf("DUMP COMPLETO: ");
                            for (int i = 0; i < total_bytes; i++) {
                                printf("%02x ", (unsigned char)buff[i]);
                            }
                            printf("\n");
                            
                            // La risposta contiene l'indirizzo e la porta per inviare i datagrammi UDP
                            // Estrazione dell'indirizzo IP del relay UDP
                            struct sockaddr_storage udp_relay_addr;
                            memset(&udp_relay_addr, 0, sizeof(udp_relay_addr));
                            
                            // Recuperiamo l'indirizzo del proxy per usarlo come fallback
                            struct sockaddr_in proxy_addr;
                            socklen_t proxy_addr_len = sizeof(proxy_addr);
                            if (getpeername(sock, (struct sockaddr *)&proxy_addr, &proxy_addr_len) != 0) {
                                // Se fallisce, imposta l'indirizzo localhost
                                proxy_addr.sin_family = AF_INET;
                                proxy_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                                PDEBUG("Failed to get proxy address, using 127.0.0.1\n");
                            }
                            
                            unsigned short udp_port = 0;
                            if (buff[3] == 1) { // IPv4
                                struct sockaddr_in *sin = (struct sockaddr_in*)&udp_relay_addr;
                                sin->sin_family = AF_INET;
                                memcpy(&sin->sin_addr.s_addr, buff + 4, 4);
                                // Debug per IPv4
                                char ipv4str[INET_ADDRSTRLEN];
                                if (bytes_read >= 4) {
                                    inet_ntop(AF_INET, buff + 4, ipv4str, sizeof(ipv4str));
                                } else {
                                    strcpy(ipv4str, "INCOMPLETO");
                                }
                                PDEBUG("Raw IPv4 address from response: %s\n", ipv4str);
                                
                                // Controlliamo se abbiamo ricevuto una risposta incompleta
                                // Per IPv4, ci aspettiamo almeno 10 byte: 
                                // 4 (header) + 4 (IPv4) + 2 (porta)
                                if (total_bytes < 10) {
                                    PDEBUG("RISPOSTA INCOMPLETA: ricevuti solo %d byte, necessari almeno 10 byte\n", total_bytes);
                                    PDEBUG("Proveremo ad attendere più dati...\n");
                                    
                                    // Prova a leggere i dati rimanenti
                                    int bytes_to_read = 10 - total_bytes;
                                    int extra_bytes = recv(sock, buff + total_bytes, bytes_to_read, 0);
                                    
                                    if (extra_bytes > 0) {
                                        total_bytes += extra_bytes;
                                        PDEBUG("Letti altri %d byte, ora totale: %d\n", extra_bytes, total_bytes);
                                        // Aggiorniamo anche bytes_read per mantenere tutto coerente
                                        bytes_read += extra_bytes;
                                    } else {
                                        PDEBUG("Nessun dato aggiuntivo disponibile\n");
                                    }
                                }
                                
                                // Estrai la porta network byte order (big endian)
                                // Leggiamo i 2 byte della porta manualmente per evitare problemi di alignment
                                int port_offset = 8; // 4 (header) + 4 (IPv4 address)
                                
                                uint16_t port_be = 0;
                                
                                // Verifichiamo che ci siano abbastanza byte per leggere la porta
                                if (bytes_read + 4 >= 10) { // Header (4) + bytes letti deve essere almeno 10
                                    // Stampa byte per byte per debug
                                    PDEBUG("IPv4 PORT BYTES at offset %d: %02x %02x\n", 
                                          port_offset,
                                          (unsigned char)buff[port_offset], 
                                          (unsigned char)buff[port_offset + 1]);
                                    
                                    // FONDAMENTALE: Costruzione della porta dai byte in network byte order
                                // Il protocollo SOCKS5 invia porta in network byte order (big endian)
                                // Quando leggiamo byte per byte, dobbiamo assemblarli mantenendo questo ordine
                                port_be = ((unsigned char)buff[port_offset] << 8) | 
                                          (unsigned char)buff[port_offset + 1];
                                PDEBUG("port_be iniziale = 0x%04x (%d)\n", port_be, (int)port_be);
                                    
                                // Debug: mostra i valori in vari formati per chiarezza
                                PDEBUG("IPv4 PORT HEX VALUE: 0x%04x\n", port_be);
                                PDEBUG("IPv4 PORT DECIMAL: %d\n", (int)port_be);
                                PDEBUG("IPv4 PORT DECIMAL (ntohs): %d\n", (int)ntohs(port_be));
                                PDEBUG("BYTE SINGOLI: %02x %02x (primo byte << 8 | secondo byte)\n", 
                                     (unsigned char)buff[port_offset], (unsigned char)buff[port_offset + 1]);
                                    
                                // MODIFICA: Invertire i byte della porta
                                // Dato che stiamo riscontrando un problema di byte order, invertiamo esplicitamente
                                udp_port = ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
                                PDEBUG("port_be originale = 0x%04x (%d)\n", port_be, (int)port_be);
                                PDEBUG("udp_port dopo inversione = 0x%04x (%d)\n", udp_port, (int)udp_port);
                                } else {
                                    // Se la risposta è incompleta e non contiene la porta,
                                    // usiamo una porta standard o quella del proxy stesso come fallback
                                    PDEBUG("Risposta incompleta, porta non disponibile\n");
                                    
                                    // Otteniamo la porta del proxy
                                    struct sockaddr_in proxy_addr;
                                    socklen_t proxy_addr_len = sizeof(proxy_addr);
                                    if (getpeername(sock, (struct sockaddr *)&proxy_addr, &proxy_addr_len) == 0) {
                                        udp_port = proxy_addr.sin_port; // Usa la porta del proxy come fallback
                                        PDEBUG("Usando la porta del proxy come fallback: %u\n", ntohs(udp_port));
                                    } else {
                                        // Se non riusciamo ad ottenere la porta del proxy, usiamo una porta standard UDP
                                        udp_port = htons(35555); // Porta UDP generica
                                        PDEBUG("Usando porta standard fallback: 35555\n");
                                    }
                                }
                                
                                sin->sin_port = udp_port;
                                PDEBUG("sin->sin_port (prima assegnazione) = 0x%04x (%d)\n", sin->sin_port, (int)sin->sin_port);
                                
                                // Controllo per indirizzi non validi (come 0.0.0.0 o 189.188.0.1)
                                if (sin->sin_addr.s_addr == 0 || 
                                    sin->sin_addr.s_addr == htonl(INADDR_ANY) || 
                                    sin->sin_addr.s_addr == htonl(INADDR_BROADCAST)) {
                                    PDEBUG("Invalid relay address returned, using proxy address instead\n");
                                    sin->sin_addr.s_addr = proxy_addr.sin_addr.s_addr;
                                }
                                
                                // Se l'indirizzo è 189.188.0.1 (valore osservato nei log), ignoriamo anche questo
                                if (sin->sin_addr.s_addr == inet_addr("189.188.0.1")) {
                                    PDEBUG("Detected problematic relay address 189.188.0.1, using proxy address\n");
                                    sin->sin_addr.s_addr = proxy_addr.sin_addr.s_addr;
                                }
                            } else if (buff[3] == 4) { // IPv6
                                struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&udp_relay_addr;
                                sin6->sin6_family = AF_INET6;
                                memcpy(&sin6->sin6_addr, buff + 4, 16);
                                
                                // Debug dell'indirizzo IPv6
                                char ipv6str[INET6_ADDRSTRLEN];
                                inet_ntop(AF_INET6, buff + 4, ipv6str, sizeof(ipv6str));
                                PDEBUG("Raw IPv6 address from response: %s\n", ipv6str);
                                
                                // Per debug, dobbiamo stampare i byte prima di tutto
                                // I byte della porta sono gli ultimi 2 byte della risposta
                                int port_offset = 20; // 4 (header) + 16 (IPv6 address)
                                
                                // Stampa byte per byte per chiarezza
                                PDEBUG("IPv6 PORT BYTES at offset %d: %02x %02x\n", 
                                       port_offset,
                                       (unsigned char)buff[port_offset], 
                                       (unsigned char)buff[port_offset + 1]);
                                
                                // Creiamo la porta direttamente dai byte
                                uint16_t port_be = 0;
                                port_be = ((unsigned char)buff[port_offset] << 8) | 
                                           (unsigned char)buff[port_offset + 1];
                                
                                // Debug: mostra esadecimale della porta
                                printf("PORT HEX VALUE MANUAL CONSTRUCTION: 0x%04x\n", port_be);
                                printf("PORT DECIMAL: %d\n", (int)port_be);
                                
                                // Assegniamo la porta in network byte order (è già così)
                                udp_port = port_be;
                                sin6->sin6_port = udp_port;
                                
                                PDEBUG("IPv6 PORT DECIMAL VALUE (NETWORK BYTE ORDER): %u\n", udp_port);
                                PDEBUG("IPv6 PORT DECIMAL VALUE (HOST BYTE ORDER): %u\n", ntohs(udp_port));
                                
                                PDEBUG("IPv6 address port from response: %d\n", ntohs(udp_port));
                                
                                // Controlla se l'indirizzo IPv6 è :: (tutti zeri)
                                struct in6_addr zero_addr;
                                memset(&zero_addr, 0, sizeof(zero_addr));
                                if (memcmp(&sin6->sin6_addr, &zero_addr, sizeof(struct in6_addr)) == 0) {
                                    // Indirizzo IPv6 non valido (::), torniamo a IPv4 usando l'indirizzo del proxy
                                    PDEBUG("IPv6 address is :: (any), using proxy IPv4 address with UDP port %d\n", 
                                           ntohs(sin6->sin6_port));
                                    
                                    // Se l'indirizzo è :: ma la porta è valida (non zero), preserviamo la porta
                                    uint16_t udp_relay_port = sin6->sin6_port;
                                    
                                    // Cambiamo a IPv4 e usiamo l'indirizzo del proxy
                                    udp_relay_addr.ss_family = AF_INET;
                                    struct sockaddr_in *sin = (struct sockaddr_in*)&udp_relay_addr;
                                    sin->sin_addr.s_addr = proxy_addr.sin_addr.s_addr;
                                    
                                    // Usiamo la porta restituita dal proxy se è diversa da zero
                                    if (udp_relay_port != 0) {
                                        sin->sin_port = udp_relay_port;
                                        PDEBUG("Using proxy address with relay port: %s:%d\n", 
                                               inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
                                    } else {
                                        sin->sin_port = proxy_addr.sin_port;
                                        PDEBUG("Using proxy address with proxy port: %s:%d\n", 
                                               inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
                                    }
                                }
                            } else if (buff[3] == 3) { // DNS
                                // Per domini, usiamo direttamente l'indirizzo del proxy
                                PDEBUG("DNS address type in relay response, using proxy address\n");
                                udp_relay_addr.ss_family = AF_INET;
                                struct sockaddr_in *sin = (struct sockaddr_in*)&udp_relay_addr;
                                sin->sin_addr.s_addr = proxy_addr.sin_addr.s_addr;
                                memcpy(&udp_port, buff + 5 + buff[4], 2);
                                PDEBUG("udp_port dopo memcpy DNS = 0x%04x (%d)\n", udp_port, (int)udp_port);
                                sin->sin_port = udp_port;
                                PDEBUG("sin->sin_port (seconda assegnazione) = 0x%04x (%d)\n", sin->sin_port, (int)sin->sin_port);
                            }
                            
                            // Verifica della porta UDP
                            if (udp_port == 0) {
                                // Se il proxy restituisce porta 0, proviamo diverse opzioni
                                PDEBUG("Proxy returned port 0, trying different options\n");
                                
                                // Opzione 1: Usa la porta del proxy
                                // Alcuni proxy usano la stessa porta sia per TCP che per UDP
                                if (proxy_addr.sin_port != 0) {
                                    PDEBUG("Using proxy TCP port: %d\n", ntohs(proxy_addr.sin_port));
                                    if (udp_relay_addr.ss_family == AF_INET) {
                                        ((struct sockaddr_in*)&udp_relay_addr)->sin_port = proxy_addr.sin_port;
                                    } else if (udp_relay_addr.ss_family == AF_INET6) {
                                        ((struct sockaddr_in6*)&udp_relay_addr)->sin6_port = proxy_addr.sin_port;
                                    }
                                } 
                                // Opzione 2: Usa la porta di destinazione
                                // Alcuni proxy inoltrano direttamente senza specificare la propria porta
                                else if (port != 0) {
                                    PDEBUG("Using destination port: %d\n", ntohs(port));
                                    if (udp_relay_addr.ss_family == AF_INET) {
                                        ((struct sockaddr_in*)&udp_relay_addr)->sin_port = port;
                                    } else if (udp_relay_addr.ss_family == AF_INET6) {
                                        ((struct sockaddr_in6*)&udp_relay_addr)->sin6_port = port;
                                    }
                                }
                                // Opzione 3: Usa una porta predefinita standard per SOCKS5
                                else {
                                    PDEBUG("Using default SOCKS5 port 1080\n");
                                    uint16_t default_port = htons(1080);
                                    if (udp_relay_addr.ss_family == AF_INET) {
                                        ((struct sockaddr_in*)&udp_relay_addr)->sin_port = default_port;
                                    } else if (udp_relay_addr.ss_family == AF_INET6) {
                                        ((struct sockaddr_in6*)&udp_relay_addr)->sin6_port = default_port;
                                    }
                                }
                            }
                            
                            // Stampiamo informazioni di debug
                            char ip_str[INET6_ADDRSTRLEN];
                            void *addr_ptr = NULL;
                            uint16_t display_port = 0; // Solo per visualizzazione
                            
                            if (udp_relay_addr.ss_family == AF_INET) {
                                struct sockaddr_in *sin = (struct sockaddr_in*)&udp_relay_addr;
                                addr_ptr = &sin->sin_addr;
                                inet_ntop(AF_INET, addr_ptr, ip_str, sizeof(ip_str));
                                // Non convertiamo la porta per uso interno, ma solo per la visualizzazione
                                // CORRETTO: Non convertire la porta per uso interno
                                // sin->sin_port è già il valore corretto inviato dal server SOCKS5
                                // Lo mostriamo sia in formato esadecimale che in formato decimale
                                PDEBUG("SOCKS5 UDP relay: IPv4 %s, porta HEX: 0x%04x (senza conversioni)\n", 
                                       ip_str, sin->sin_port);
                                
                                // DEBUG AVANZATO: Mostriamo i singoli byte della porta
                                unsigned char* port_bytes = (unsigned char*)&sin->sin_port;
                                PDEBUG("PORTA TCP BYTES: %02x %02x (mostrati in ordine memoria)\n",
                                      port_bytes[0], port_bytes[1]);
                            } else if (udp_relay_addr.ss_family == AF_INET6) {
                                struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&udp_relay_addr;
                                addr_ptr = &sin6->sin6_addr;
                                inet_ntop(AF_INET6, addr_ptr, ip_str, sizeof(ip_str));
                                // Non convertiamo la porta per uso interno, ma solo per la visualizzazione
                                display_port = ntohs(sin6->sin6_port);
                                PDEBUG("SOCKS5 UDP relay: IPv6 [%s]:%d (porta originale: 0x%04x)\n", 
                                       ip_str, display_port, sin6->sin6_port);
                            }
                            
                            // Debug aggiuntivo per comprendere meglio il flusso dei dati
                            char target_ip_str[INET6_ADDRSTRLEN];
                            if (!v6) {
                                inet_ntop(AF_INET, ip.addr.v4.octet, target_ip_str, sizeof(target_ip_str));
                                PDEBUG("Original UDP target: %s:%d\n", target_ip_str, ntohs(port));
                            } else {
                                inet_ntop(AF_INET6, ip.addr.v6, target_ip_str, sizeof(target_ip_str));
                                PDEBUG("Original UDP target: [%s]:%d\n", target_ip_str, ntohs(port));
                            }
                            
                            // Prepara le informazioni di destinazione target
                            struct sockaddr_storage target_addr;
                            memset(&target_addr, 0, sizeof(target_addr));
                            socklen_t target_len = 0;
                            
                            if (!v6) { // IPv4
                                struct sockaddr_in *sin = (struct sockaddr_in*)&target_addr;
                                sin->sin_family = AF_INET;
                                sin->sin_port = port;
                                memcpy(&sin->sin_addr.s_addr, ip.addr.v4.octet, 4);
                                target_len = sizeof(struct sockaddr_in);
                            } else { // IPv6
                                struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&target_addr;
                                sin6->sin6_family = AF_INET6;
                                sin6->sin6_port = port;
                                memcpy(&sin6->sin6_addr, ip.addr.v6, 16);
                                target_len = sizeof(struct sockaddr_in6);
                            }
                            
                            // Debug: stampa il valore della porta in vari formati prima di salvare
                            if (udp_relay_addr.ss_family == AF_INET) {
                                struct sockaddr_in *sin = (struct sockaddr_in*)&udp_relay_addr;
                                uint16_t original_port = sin->sin_port; // Valore originale in network byte order
                                
                                PDEBUG("original_port prima del salvataggio = 0x%04x (%d)\n", 
                                       original_port, (int)original_port);
                            }
                            
                            // Salva l'associazione per uso futuro nelle funzioni sendto e recvfrom
                            int relay_idx = save_udp_relay_info(sock, 
                                                             (struct sockaddr *)&udp_relay_addr, 
                                                             udp_relay_addr.ss_family == AF_INET ? 
                                                                sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                                                             (struct sockaddr *)&target_addr,
                                                             target_len,
                                                             sock);
                            
                            if (relay_idx >= 0) {
                                PDEBUG("Saved UDP relay info at index %d for socket %d\n", relay_idx, sock);
                            } else {
                                PDEBUG("Failed to save UDP relay info for socket %d\n", sock);
                            }
                        }

                        return SUCCESS;
                }
                break;
        }

        err:
        return SOCKET_ERROR;
}

#define TP " ... "
#define DT "Dynamic chain"
#define ST "Strict chain"
#define RT "Random chain"
#define RRT "Round Robin chain"

static int start_chain(int *fd, proxy_data * pd, char *begin_mark) {
        int v6 = pd->ip.is_v6;

        *fd = socket(v6?PF_INET6:PF_INET, SOCK_STREAM, 0);
        if(*fd == -1)
                goto error;
        
        char ip_buf[INET6_ADDRSTRLEN];
        if(!inet_ntop(v6?AF_INET6:AF_INET,pd->ip.addr.v6,ip_buf,sizeof ip_buf))
                goto error;

        proxychains_write_log(LOG_PREFIX "%s " TP " %s:%d ",
                              begin_mark, ip_buf, htons(pd->port));
        pd->ps = PLAY_STATE;
        struct sockaddr_in addr = {
                .sin_family = AF_INET,
                .sin_port = pd->port,
                .sin_addr.s_addr = (in_addr_t) pd->ip.addr.v4.as_int
        };
        struct sockaddr_in6 addr6 = {
                .sin6_family = AF_INET6,
                .sin6_port = pd->port,
        };
        if(v6) memcpy(&addr6.sin6_addr.s6_addr, pd->ip.addr.v6, 16);
        if(timed_connect(*fd, (struct sockaddr *) (v6?(void*)&addr6:(void*)&addr), v6?sizeof(addr6):sizeof(addr))) {
                pd->ps = DOWN_STATE;
                goto error1;
        }
        pd->ps = BUSY_STATE;
        return SUCCESS;
        error1:
        proxychains_write_log(TP " timeout\n");
        error:
        if(*fd != -1) {
                close(*fd);
                *fd = -1;
        }
        return SOCKET_ERROR;
}

static proxy_data *select_proxy(select_type how, proxy_data * pd, unsigned int proxy_count, unsigned int *offset) {
        unsigned int i = 0, k = 0;
        
        // Se è specificato un ID proxy specifico, cerca solo quello
        extern int proxychains_selected_proxy_id;
        if(proxychains_selected_proxy_id > 0) {
                for(i = 0; i < proxy_count; i++) {
                        if(pd[i].proxy_id == proxychains_selected_proxy_id && pd[i].ps == PLAY_STATE) {
                                *offset = i;
                                return &pd[i];
                        }
                }
                // Se l'ID specificato non è trovato o non è disponibile
                PDEBUG("Proxy with ID %d not found or not available\n", proxychains_selected_proxy_id);
                return NULL;
        }
        
        // Logica di selezione normale quando nessun ID è specificato
        if(*offset >= proxy_count)
                return NULL;
        switch (how) {
                case RANDOMLY:
                        do {
                                k++;
                                i = rand() % proxy_count;
                        } while(pd[i].ps != PLAY_STATE && k < proxy_count * 100);
                        break;
                case FIFOLY:
                        for(i = *offset; i < proxy_count; i++) {
                                if(pd[i].ps == PLAY_STATE) {
                                        *offset = i;
                                        break;
                                }
                        }
                default:
                        break;
        }
        if(i >= proxy_count)
                i = 0;
        return (pd[i].ps == PLAY_STATE) ? &pd[i] : NULL;
}


static void release_all(proxy_data * pd, unsigned int proxy_count) {
        unsigned int i;
        for(i = 0; i < proxy_count; i++)
                pd[i].ps = PLAY_STATE;
        return;
}

static void release_busy(proxy_data * pd, unsigned int proxy_count) {
        unsigned int i;
        for(i = 0; i < proxy_count; i++)
                if(pd[i].ps == BUSY_STATE)
                        pd[i].ps = PLAY_STATE;
        return;
}

static unsigned int calc_alive(proxy_data * pd, unsigned int proxy_count) {
        unsigned int i;
        int alive_count = 0;
        release_busy(pd, proxy_count);
        for(i = 0; i < proxy_count; i++)
                if(pd[i].ps == PLAY_STATE)
                        alive_count++;
        return alive_count;
}


static int chain_step(int *ns, proxy_data * pfrom, proxy_data * pto) {
        int retcode = -1;
        char *hostname, *errmsg = 0;
        char hostname_buf[MSG_LEN_MAX];
        char ip_buf[INET6_ADDRSTRLEN];
        int v6 = pto->ip.is_v6;

        PFUNC();

        if(!v6 && proxychains_resolver >= DNSLF_RDNS_START && pto->ip.addr.v4.octet[0] == remote_dns_subnet) {
                if(!rdns_get_host_for_ip(pto->ip.addr.v4, hostname_buf)) goto usenumericip;
                else hostname = hostname_buf;
        } else {
        usenumericip:
                if(!inet_ntop(v6?AF_INET6:AF_INET,pto->ip.addr.v6,ip_buf,sizeof ip_buf)) {
                        pto->ps = DOWN_STATE;
                        errmsg = "<--ip conversion error!\n";
                        retcode = SOCKET_ERROR;
                        goto err;
                }
                hostname = ip_buf;
        }

        proxychains_write_log(TP " %s:%d ", hostname, htons(pto->port));
        // Utilizziamo SOCK_STREAM come default per compatibilità con il codice esistente
        retcode = tunnel_to(*ns, pto->ip, pto->port, pfrom->pt, pfrom->user, pfrom->pass, SOCK_STREAM);
        switch (retcode) {
                case SUCCESS:
                        pto->ps = BUSY_STATE;
                        break;
                case BLOCKED:
                        pto->ps = BLOCKED_STATE;
                        errmsg = "<--denied\n";
                        goto err;
                case SOCKET_ERROR:
                        pto->ps = DOWN_STATE;
                        errmsg = "<--socket error or timeout!\n";
                        goto err;
        }
        return retcode;
err:
        if(errmsg) proxychains_write_log(errmsg);
        if(*ns != -1) close(*ns);
        *ns = -1;
        return retcode;
}

int connect_proxy_chain(int sock, ip_type target_ip,
                        unsigned short target_port, proxy_data * pd,
                        unsigned int proxy_count, chain_type ct, unsigned int max_chain,
                        int socket_type) {
    // Se è un socket UDP o abbiamo forzato la modalità UDP, utilizziamo direttamente il primo proxy disponibile
    if (socket_type == SOCK_DGRAM || proxychains_force_udp_mode) {
        //proxychains_write_log(LOG_PREFIX "UDP socket connection through SOCKS5 proxy\n");
        proxy_data *p1;
        int ns = -1;
        unsigned int offset = 0;
        
        // Verifichiamo se esiste già un'associazione per questo socket
        udp_relay_data *relay_info = get_udp_relay_info(sock);
        if (relay_info != NULL) {
            PDEBUG("Found existing UDP relay info for socket %d\n", sock);
            // Già configurato, ritorna successo
            return SUCCESS;
        }
        
        // Troviamo il primo proxy disponibile
        if (!(p1 = select_proxy(FIFOLY, pd, proxy_count, &offset))) {
            proxychains_write_log("\n!!!need more proxies!!!\n");
            goto error_udp;
        }
        
        // Creiamo un socket TCP per negoziare con il proxy SOCKS5
        ns = socket(PF_INET, SOCK_STREAM, 0);
        if (ns == -1)
            goto error_udp;
            
        // Ci connettiamo al proxy SOCKS5
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = p1->port,
            .sin_addr.s_addr = (in_addr_t) p1->ip.addr.v4.as_int
        };
        
        if (timed_connect(ns, (struct sockaddr *)&addr, sizeof(addr))) {
            proxychains_write_log(" timeout\n");
            goto error_udp;
        }
        
        // Utilizziamo tunnel_to con il tipo di socket UDP
        // tunnel_to ora salverà automaticamente le informazioni del relay UDP
        if (tunnel_to(ns, target_ip, target_port, p1->pt, p1->user, p1->pass, SOCK_DGRAM) != SUCCESS) {
            proxychains_write_log(" UDP Association failed\n");
            goto error_udp;
        }
        
        // Aggiorna le informazioni del relay con il socket attuale (client)
        // Otteniamo le informazioni del relay appena create
        relay_info = get_udp_relay_info(ns);
        if (relay_info) {
            // Salva una nuova associazione per il socket client originale
            struct sockaddr *relay_addr = (struct sockaddr *)&relay_info->udp_relay;
            struct sockaddr *target_addr = (struct sockaddr *)&relay_info->target;
            
            int relay_idx = save_udp_relay_info(sock, 
                                             relay_addr, 
                                             relay_info->udp_relay_len,
                                             target_addr,
                                             relay_info->target_len,
                                             ns); // Mantenere il socket di controllo
            
            if (relay_idx >= 0) {
                PDEBUG("Created UDP association for client socket %d using control socket %d\n", sock, ns);
                return SUCCESS;
            }
        }
        
        // Se arriviamo qui, c'è stato un errore nella creazione dell'associazione
        goto error_udp;
        
    error_udp:
        // IMPORTANTE: NON chiudiamo il socket di controllo in caso di errore
        // Secondo il protocollo SOCKS5, la connessione TCP di controllo deve rimanere aperta
        // per tutta la durata della sessione UDP.
        // Chiudere questo socket qui causa l'interruzione dell'associazione UDP
        
        // Vecchio codice commentato:
        // if (ns != -1)
        //     close(ns);
        
        PDEBUG("UDP relay setup failed, but we keep the control socket open\n");
        errno = ETIMEDOUT;
        return -1;
    }
        proxy_data p4;
        proxy_data *p1, *p2, *p3;
        int ns = -1;
        int rc = -1;
        unsigned int offset = 0;
        unsigned int alive_count = 0;
        unsigned int curr_len = 0;
        unsigned int looped = 0; // went back to start of list in RR mode
        unsigned int rr_loop_max = 14;

        p3 = &p4;

        PFUNC();

        again:
        rc = -1;
        DUMP_PROXY_CHAIN(pd, proxy_count);

        switch (ct) {
                case DYNAMIC_TYPE:
                        alive_count = calc_alive(pd, proxy_count);
                        offset = 0;
                        do {
                                if(!(p1 = select_proxy(FIFOLY, pd, proxy_count, &offset)))
                                        goto error_more;
                        } while(SUCCESS != start_chain(&ns, p1, DT) && offset < proxy_count);
                        for(;;) {
                                p2 = select_proxy(FIFOLY, pd, proxy_count, &offset);
                                if(!p2)
                                        break;
                                if(SUCCESS != chain_step(&ns, p1, p2)) {
                                        PDEBUG("GOTO AGAIN 1\n");
                                        goto again;
                                }
                                p1 = p2;
                        }
                        //proxychains_write_log(TP);
                        p3->ip = target_ip;
                        p3->port = target_port;
                        if(SUCCESS != chain_step(&ns, p1, p3))
                                goto error;
                        break;

                case ROUND_ROBIN_TYPE:
                        alive_count = calc_alive(pd, proxy_count);
                        offset = proxychains_proxy_offset;
                        if(alive_count < max_chain)
                                goto error_more;
                        PDEBUG("1:rr_offset = %d\n", offset);
                        /* Check from current RR offset til end */
                        for (;rc != SUCCESS;) {
                                if (!(p1 = select_proxy(FIFOLY, pd, proxy_count, &offset))) {
                                        /* We've reached the end of the list, go to the start */
                                        offset = 0;
                                        looped++;
                                        if (looped > rr_loop_max) {
                                                proxychains_proxy_offset = 0;
                                                goto error_more;
                                        } else {
                                                PDEBUG("rr_type all proxies down, release all\n");
                                                release_all(pd, proxy_count);
                                                /* Each loop we wait 10ms more */
                                                usleep(10000 * looped);
                                                continue;
                                        }
                                }
                                PDEBUG("2:rr_offset = %d\n", offset);
                                rc=start_chain(&ns, p1, RRT);
                        }
                        /* Create rest of chain using RR */
                        for(curr_len = 1; curr_len < max_chain;) {
                                PDEBUG("3:rr_offset = %d, curr_len = %d, max_chain = %d\n", offset, curr_len, max_chain);
                                p2 = select_proxy(FIFOLY, pd, proxy_count, &offset);
                                if(!p2) {
                                        /* Try from the beginning to where we started */
                                        offset = 0;
                                        continue;
                                } else if(SUCCESS != chain_step(&ns, p1, p2)) {
                                        PDEBUG("GOTO AGAIN 1\n");
                                        goto again;
                                } else
                                        p1 = p2;
                                curr_len++;
                        }
                        //proxychains_write_log(TP);
                        p3->ip = target_ip;
                        p3->port = target_port;
                        proxychains_proxy_offset = offset+1;
                        PDEBUG("pd_offset = %d, curr_len = %d\n", proxychains_proxy_offset, curr_len);
                        if(SUCCESS != chain_step(&ns, p1, p3))
                                goto error;
                        break;

                case STRICT_TYPE:
                        alive_count = calc_alive(pd, proxy_count);
                        offset = 0;
                        if(!(p1 = select_proxy(FIFOLY, pd, proxy_count, &offset))) {
                                PDEBUG("select_proxy failed\n");
                                goto error_strict;
                        }
                        if(SUCCESS != start_chain(&ns, p1, ST)) {
                                PDEBUG("start_chain failed\n");
                                goto error_strict;
                        }
                        while(offset < proxy_count) {
                                if(!(p2 = select_proxy(FIFOLY, pd, proxy_count, &offset)))
                                        break;
                                if(SUCCESS != chain_step(&ns, p1, p2)) {
                                        PDEBUG("chain_step failed\n");
                                        goto error_strict;
                                }
                                p1 = p2;
                        }
                        //proxychains_write_log(TP);
                        p3->ip = target_ip;
                        p3->port = target_port;
                        if(SUCCESS != chain_step(&ns, p1, p3))
                                goto error;
                        break;

                case RANDOM_TYPE:
                        alive_count = calc_alive(pd, proxy_count);
                        if(alive_count < max_chain)
                                goto error_more;
                        curr_len = offset = 0;
                        do {
                                if(!(p1 = select_proxy(RANDOMLY, pd, proxy_count, &offset)))
                                        goto error_more;
                        } while(SUCCESS != start_chain(&ns, p1, RT) && offset < max_chain);
                        while(++curr_len < max_chain) {
                                if(!(p2 = select_proxy(RANDOMLY, pd, proxy_count, &offset)))
                                        goto error_more;
                                if(SUCCESS != chain_step(&ns, p1, p2)) {
                                        PDEBUG("GOTO AGAIN 2\n");
                                        goto again;
                                }
                                p1 = p2;
                        }
                        //proxychains_write_log(TP);
                        p3->ip = target_ip;
                        p3->port = target_port;
                        if(SUCCESS != chain_step(&ns, p1, p3))
                                goto error;

        }

        proxychains_write_log(TP " OK\n");
        dup2(ns, sock);
        close(ns);
        return 0;
        error:
        // Impostiamo il flag di fallimento della catena
        set_chain_failure();
        
        if(ns != -1)
                close(ns);
        errno = ECONNREFUSED;   // for nmap ;)
        return -1;

        error_more:
        proxychains_write_log("\n!!!need more proxies!!!\n");
        error_strict:
        PDEBUG("error\n");
        
        // Impostiamo il flag di fallimento della catena
        set_chain_failure();
        
        release_all(pd, proxy_count);
        if(ns != -1)
                close(ns);
        errno = ETIMEDOUT;
        return -1;
}

static pthread_mutex_t servbyname_lock;
void core_initialize(void) {
        MUTEX_INIT(&servbyname_lock);
        MUTEX_INIT(&udp_relay_mutex);
        
        // Inizializziamo l'array dei relay UDP
        int i;
        for (i = 0; i < MAX_UDP_SOCKETS; i++) {
                udp_relays[i].in_use = 0;
                udp_relays[i].control_sock = -1;
        }
}

void core_unload(void) {
        // Chiudiamo tutti i socket di controllo UDP attivi
        int i;
        pthread_mutex_lock(&udp_relay_mutex);
        for (i = 0; i < MAX_UDP_SOCKETS; i++) {
                if (udp_relays[i].in_use && udp_relays[i].control_sock >= 0) {
                        close(udp_relays[i].control_sock);
                        udp_relays[i].in_use = 0;
                        udp_relays[i].control_sock = -1;
                }
        }
        pthread_mutex_unlock(&udp_relay_mutex);
        
        MUTEX_DESTROY(&servbyname_lock);
        MUTEX_DESTROY(&udp_relay_mutex);
}

static void gethostbyname_data_setstring(struct gethostbyname_data* data, char* name) {
        snprintf(data->addr_name, sizeof(data->addr_name), "%s", name);
        data->hostent_space.h_name = data->addr_name;
}

extern ip_type4 hostsreader_get_numeric_ip_for_name(const char* name);
struct hostent* proxy_gethostbyname_old(const char *name)
{
        static struct hostent hostent_space;
        static in_addr_t resolved_addr;
        static char* resolved_addr_p;
        static char addr_name[256];

        int pipe_fd[2];
        char buff[256];
        in_addr_t addr;
        pid_t pid;
        int status, ret;
        size_t l;
        struct hostent* hp;

        hostent_space.h_addr_list = &resolved_addr_p;
        *hostent_space.h_addr_list = (char*)&resolved_addr;
        resolved_addr = 0;

        if(pc_isnumericipv4(name)) {
                strcpy(buff, name);
                goto got_buff;
        }

        gethostname(buff,sizeof(buff));
        if(!strcmp(buff,name))
                goto got_buff;

        memset(buff, 0, sizeof(buff));

        // TODO: this works only once, so cache it  ...
        //       later
        while ((hp=gethostent()))
                if (!strcmp(hp->h_name,name))
                        return hp;
#ifdef HAVE_PIPE2
        ret = pipe2(pipe_fd, O_CLOEXEC);
#else
        ret = pipe(pipe_fd);
        if(ret == 0) {
                fcntl(pipe_fd[0], F_SETFD, FD_CLOEXEC);
                fcntl(pipe_fd[1], F_SETFD, FD_CLOEXEC);
        }
#endif

        if(ret)
                goto err;
        pid = fork();
        switch(pid) {

                case 0: // child
                        proxychains_write_log("|DNS-request| %s \n", name);
                        close(pipe_fd[0]);
                        dup2(pipe_fd[1],1);
                        close(pipe_fd[1]);

                //      putenv("LD_PRELOAD=");
                        execlp("proxyresolv","proxyresolv",name,NULL);
                        perror("can't exec proxyresolv");
                        exit(2);

                case -1: //error
                        close(pipe_fd[0]);
                        close(pipe_fd[1]);
                        perror("can't fork");
                        goto err;

                default:
                        close(pipe_fd[1]);
                        waitpid(pid, &status, 0);
                        buff[0] = 0;
                        read(pipe_fd[0],&buff,sizeof(buff));
                        close(pipe_fd[0]);
got_buff:
                        l = strlen(buff);
                        if (!l) goto err_dns;
                        if (buff[l-1] == '\n') buff[l-1] = 0;
                        addr = inet_addr(buff);
                        if (addr == (in_addr_t) (-1))
                                goto err_dns;
                        memcpy(*(hostent_space.h_addr_list),
                                                &addr ,sizeof(struct in_addr));
                        hostent_space.h_name = addr_name;
                        snprintf(addr_name, sizeof addr_name, "%s", buff);
                        hostent_space.h_length = sizeof (in_addr_t);
                        hostent_space.h_addrtype = AF_INET;
        }
        proxychains_write_log("|DNS-response| %s is %s\n",
                        name, inet_ntoa(*(struct in_addr*)&addr));
        return &hostent_space;
err_dns:
        proxychains_write_log("|DNS-response|: %s lookup error\n", name);
err:
        return NULL;
}

struct hostent *proxy_gethostbyname(const char *name, struct gethostbyname_data* data) {
        PFUNC();
        char buff[256];

        data->resolved_addr_p[0] = (char *) &data->resolved_addr;
        data->resolved_addr_p[1] = NULL;

        data->hostent_space.h_addr_list = data->resolved_addr_p;
        // let aliases point to the NULL member, mimicking an empty list.
        data->hostent_space.h_aliases = &data->resolved_addr_p[1];

        data->resolved_addr = 0;
        data->hostent_space.h_addrtype = AF_INET;
        data->hostent_space.h_length = sizeof(in_addr_t);

        if(pc_isnumericipv4(name)) {
                data->resolved_addr = inet_addr(name);
                goto retname;
        }

        gethostname(buff, sizeof(buff));

        if(!strcmp(buff, name)) {
                data->resolved_addr = inet_addr(buff);
                if(data->resolved_addr == (in_addr_t) (-1))
                        data->resolved_addr = (in_addr_t) (IPT4_LOCALHOST.as_int);
                goto retname;
        }

        // this iterates over the "known hosts" db, usually /etc/hosts
        ip_type4 hdb_res = hostsreader_get_numeric_ip_for_name(name);
        if(hdb_res.as_int != IPT4_INVALID.as_int) {
                data->resolved_addr = hdb_res.as_int;
                goto retname;
        }
        
        data->resolved_addr = rdns_get_ip_for_host((char*) name, strlen(name)).as_int;
        if(data->resolved_addr == (in_addr_t) IPT4_INVALID.as_int) return NULL;

        retname:

        gethostbyname_data_setstring(data, (char*) name);
        
        PDEBUG("return hostent space\n");
        
        return &data->hostent_space;
}

struct addrinfo_data {
        struct addrinfo addrinfo_space;
        struct sockaddr_storage sockaddr_space;
        char addr_name[256];
};

void proxy_freeaddrinfo(struct addrinfo *res) {
        PFUNC();
        free(res);
}

static int mygetservbyname_r(const char* name, const char* proto, struct servent* result_buf,
                           char* buf, size_t buflen, struct servent** result) {
        PFUNC();
#ifdef HAVE_GNU_GETSERVBYNAME_R
        PDEBUG("using host getservbyname_r\n");
        return getservbyname_r(name, proto, result_buf, buf, buflen, result);
#endif
        struct servent *res;
        int ret;
        (void) buf; (void) buflen;
        MUTEX_LOCK(&servbyname_lock);
        res = getservbyname(name, proto);
        if(res) {
                *result_buf = *res;
                *result = result_buf;
                ret = 0;
        } else {
                *result = NULL;
                ret = ENOENT;
        }
        MUTEX_UNLOCK(&servbyname_lock);
        return ret;
}

static int looks_like_numeric_ipv6(const char *node)
{
        if(!strchr(node, ':')) return 0;
        const char* p= node;
        while(1) switch(*(p++)) {
                case 0: return 1;
                case ':': case '.':
                case '0': case '1': case '2': case '3': case '4':
                case '5': case '6': case '7': case '8': case '9':
                case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
                case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
                        break;
                default: return 0;
        }
}

static int my_inet_aton(const char *node, struct addrinfo_data* space)
{
        int ret;
        ((struct sockaddr_in *) &space->sockaddr_space)->sin_family = AF_INET;
        ret = inet_aton(node, &((struct sockaddr_in *) &space->sockaddr_space)->sin_addr);
        if(ret || !looks_like_numeric_ipv6(node)) return ret;
        ret = inet_pton(AF_INET6, node, &((struct sockaddr_in6 *) &space->sockaddr_space)->sin6_addr);
        if(ret) ((struct sockaddr_in6 *) &space->sockaddr_space)->sin6_family = AF_INET6;
        return ret;
}

int proxy_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
        struct gethostbyname_data ghdata;
        struct addrinfo_data *space;
        struct servent *se = NULL;
        struct hostent *hp = NULL;
        struct servent se_buf;
        struct addrinfo *p;
        char buf[1024];
        int port, af = AF_INET;

        PDEBUG("proxy_getaddrinfo node:%s service: %s, flags: %d\n",
                node?node:"",service?service:"",hints?(int)hints->ai_flags:0);

        space = calloc(1, sizeof(struct addrinfo_data));
        if(!space) return EAI_MEMORY;

        if(node && !my_inet_aton(node, space)) {
                /* some folks (nmap) use getaddrinfo() with AI_NUMERICHOST to check whether a string
                   containing a numeric ip was passed. we must return failure in that case. */
                if(hints && (hints->ai_flags & AI_NUMERICHOST)) {
err_nn:
                        free(space);
                        return EAI_NONAME;
                }
                if(proxychains_resolver == DNSLF_FORKEXEC)
                        hp = proxy_gethostbyname_old(node);
                else
                        hp = proxy_gethostbyname(node, &ghdata);

                if(hp)
                        memcpy(&((struct sockaddr_in *) &space->sockaddr_space)->sin_addr,
                               *(hp->h_addr_list), sizeof(in_addr_t));
                else
                        goto err_nn;
        } else if(node) {
                af = ((struct sockaddr_in *) &space->sockaddr_space)->sin_family;
        } else if(!node && !(hints->ai_flags & AI_PASSIVE)) {
                af = ((struct sockaddr_in *) &space->sockaddr_space)->sin_family = AF_INET;
                memcpy(&((struct sockaddr_in *) &space->sockaddr_space)->sin_addr,
                       "\177\0\0\1", 4);
        }
        if(service) mygetservbyname_r(service, NULL, &se_buf, buf, sizeof(buf), &se);

        port = se ? se->s_port : htons(atoi(service ? service : "0"));
        if(af == AF_INET)
                ((struct sockaddr_in *) &space->sockaddr_space)->sin_port = port;
        else
                ((struct sockaddr_in6 *) &space->sockaddr_space)->sin6_port = port;

        *res = p = &space->addrinfo_space;
        assert((size_t)p == (size_t) space);

        p->ai_addr = (void*) &space->sockaddr_space;
        if(node)
                snprintf(space->addr_name, sizeof(space->addr_name), "%s", node);
        p->ai_canonname = space->addr_name;
        p->ai_next = NULL;
        p->ai_family = space->sockaddr_space.ss_family = af;
        p->ai_addrlen = af == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

        if(hints) {
                p->ai_socktype = hints->ai_socktype;
                p->ai_flags = hints->ai_flags;
                p->ai_protocol = hints->ai_protocol;
                if(!p->ai_socktype && p->ai_protocol == IPPROTO_TCP)
                        p->ai_socktype = SOCK_STREAM;
        } else {
#ifndef AI_V4MAPPED
#define AI_V4MAPPED 0
#endif
                p->ai_flags = (AI_V4MAPPED | AI_ADDRCONFIG);
        }
        return 0;
}
