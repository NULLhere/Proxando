#ifndef DEBUG_H
#define DEBUG_H

# include <stdio.h>

#ifdef DEBUG
# define PSTDERR(fmt, args...) do { dprintf(2,fmt, ## args); } while(0)
# define PDEBUG(fmt, args...) PSTDERR("DEBUG:pid[%d]:" fmt, getpid(), ## args)
# define DEBUGDECL(args...) args
# define DUMP_PROXY_CHAIN(A, B) dump_proxy_chain(A, B)
#else
# define PSTDERR(fmt, args...) do { if(getenv("PROXYCHAINS_DEBUG_MODE")) dprintf(2,fmt, ## args); } while(0)
# define PDEBUG(fmt, args...) do { if(getenv("PROXYCHAINS_DEBUG_MODE")) dprintf(2,"DEBUG:pid[%d]:" fmt, getpid(), ## args); } while(0)
# define DEBUGDECL(args...)
# define DUMP_PROXY_CHAIN(A, B) do { if(getenv("PROXYCHAINS_DEBUG_MODE")) dump_proxy_chain(A, B); } while(0)
#endif

# define PFUNC() do { PDEBUG("%s()\n", __FUNCTION__); } while(0)

#include "core.h"
void dump_proxy_chain(proxy_data *pchain, unsigned int count);


#endif

