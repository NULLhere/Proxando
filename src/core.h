/***************************************************************************
                          core.h  -  description
                             -------------------
    begin                : Tue May 14 2002
    copyright          :  netcreature (C) 2002
    email                 : netcreature@users.sourceforge.net
 ***************************************************************************
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>

#ifndef __CORE_HEADER
#define __CORE_HEADER
#define     MAX_LOCALNET 64
#define     MAX_DNAT 64
#define     MAX_UDP_SOCKETS 64

// Struttura dati del thread locale per gestire lo stato della connessione
typedef struct {
    int had_chain_failure;  // Indica se la catena di proxy ha fallito
} thread_local_data;

#include "ip_type.h"

/*error codes*/
typedef enum {
        SUCCESS=0,
        MEMORY_FAIL,        // malloc failed
        SOCKET_ERROR,  // look errno for more
        CHAIN_DOWN,    // no proxy in chain responds to tcp
        CHAIN_EMPTY,   //  if proxy_count = 0
        BLOCKED,  //  target's port blocked on last proxy in the chain
        PROXY_UNREACHABLE  // none of the proxies are reachable
} ERR_CODE;

// Opzione per abilitare o disabilitare le connessioni dirette in caso di fallimento del proxy
// true = rigoroso (solo tramite proxy), false = consente connessioni dirette
extern int proxychains_strict_proxy;

typedef enum {
        HTTP_TYPE,
        SOCKS4_TYPE,
        SOCKS5_TYPE,
        RAW_TYPE
} proxy_type;

typedef enum {
        DYNAMIC_TYPE,
        STRICT_TYPE,
        RANDOM_TYPE,
        ROUND_ROBIN_TYPE
} chain_type;

typedef enum {
        PLAY_STATE,
        DOWN_STATE,
        BLOCKED_STATE,
        BUSY_STATE
} proxy_state;

typedef enum {
        RANDOMLY,
        FIFOLY
} select_type;

typedef struct {
        sa_family_t family;
        unsigned short port;
        union {
                struct {
                        struct in_addr in_addr;
                        struct in_addr in_mask;
                };
                struct {
                        struct in6_addr in6_addr;
                        unsigned char in6_prefix;
                };
        };
} localaddr_arg;

typedef struct {
        struct in_addr orig_dst, new_dst;
        unsigned short orig_port, new_port;
} dnat_arg;

typedef struct {
        ip_type ip;
        unsigned short port;
        proxy_type pt;
        proxy_state ps;
        char user[256];
        char pass[256];
        int proxy_id;  // ID del proxy per la selezione specifica
} proxy_data;

int connect_proxy_chain (int sock, ip_type target_ip, unsigned short target_port,
                         proxy_data * pd, unsigned int proxy_count, chain_type ct,
                         unsigned int max_chain, int socket_type);

void proxychains_write_log(char *str, ...);

typedef int (*close_t)(int);
typedef int (*close_range_t)(unsigned, unsigned, int);
typedef int (*connect_t)(int, const struct sockaddr *, socklen_t);
typedef struct hostent* (*gethostbyname_t)(const char *);
typedef void (*freeaddrinfo_t)(struct addrinfo *);
typedef struct hostent *(*gethostbyaddr_t) (const void *, socklen_t, int);

typedef int (*getaddrinfo_t)(const char *, const char *, const struct addrinfo *, 
                             struct addrinfo **);

typedef int (*getnameinfo_t) (const struct sockaddr *, socklen_t, char *, 
                              GN_NODELEN_T, char *, GN_SERVLEN_T, GN_FLAGS_T);

typedef ssize_t (*sendto_t) (int sockfd, const void *buf, size_t len, int flags,
                             const struct sockaddr *dest_addr, socklen_t addrlen);

typedef int (*socket_t) (int domain, int type, int protocol);

typedef ssize_t (*recvfrom_t) (int sockfd, void *buf, size_t len, int flags,
                             struct sockaddr *src_addr, socklen_t *addrlen);
typedef ssize_t (*write_t)(int fd, const void *buf, size_t count);
typedef ssize_t (*send_t)(int sockfd, const void *buf, size_t len, int flags);

// Struttura per memorizzare le informazioni di relaying UDP
typedef struct {
    int in_use;                     // Flag che indica se questa struttura è in uso
    int control_sock;               // Socket di controllo TCP per UDP ASSOCIATE
    int client_sock;                // Socket client UDP
    struct sockaddr_storage udp_relay;  // Indirizzo del relay UDP restituito dal proxy
    socklen_t udp_relay_len;        // Lunghezza dell'indirizzo del relay UDP
    struct sockaddr_storage target;  // Indirizzo di destinazione originale
    socklen_t target_len;            // Lunghezza dell'indirizzo di destinazione
    
    // AGGIUNTO SECONDO LA RICHIESTA DEL CLIENTE:
    // Memorizziamo la porta esatta come numero intero a 16 bit (senza conversioni di byte order)
    uint16_t exact_relay_port;      // Porta UDP esatta ricevuta dal server SOCKS5
} udp_relay_data;

// Massimo numero di socket UDP che possono essere gestiti contemporaneamente
#define MAX_UDP_SOCKETS 64

// Dichiarazione delle variabili globali per gestire le associazioni UDP
extern udp_relay_data udp_relays[MAX_UDP_SOCKETS];

// Funzione per salvare l'associazione UDP
int save_udp_relay_info(int sockfd, const struct sockaddr *relay_addr, socklen_t relay_len, 
                        const struct sockaddr *target_addr, socklen_t target_len, int control_sock);

// Funzione per ottenere l'associazione UDP
udp_relay_data *get_udp_relay_info(int sockfd);

// Funzione per cancellare l'associazione UDP
void remove_udp_relay_info(int sockfd);

// Funzione per trovare l'indice dell'associazione UDP per un socket
int find_udp_relay_info(int sockfd);

extern connect_t true_connect;
extern gethostbyname_t true_gethostbyname;
extern getaddrinfo_t true_getaddrinfo;
extern freeaddrinfo_t true_freeaddrinfo;
extern getnameinfo_t true_getnameinfo;
extern gethostbyaddr_t true_gethostbyaddr;
extern sendto_t true_sendto;
extern socket_t true_socket;
extern recvfrom_t true_recvfrom;

struct gethostbyname_data {
        struct hostent hostent_space;
        in_addr_t resolved_addr;
        char *resolved_addr_p[2];
        char addr_name[256];
};

struct hostent* proxy_gethostbyname(const char *name, struct gethostbyname_data *data);
struct hostent* proxy_gethostbyname_old(const char *name);

int proxy_getaddrinfo(const char *node, const char *service, 
                      const struct addrinfo *hints, struct addrinfo **res);
void proxy_freeaddrinfo(struct addrinfo *res);

// Funzione per ottenere i dati thread-local
thread_local_data* thread_get_data(void);

// Funzione per impostare il flag di fallimento della catena
void set_chain_failure(void);

void core_initialize(void);
void core_unload(void);

#include "debug.h"

#endif

//RcB: DEP "core.c"
//RcB: DEP "libproxychains.c"
//RcB: LINK "-Wl,--no-as-needed -ldl -lpthread"

