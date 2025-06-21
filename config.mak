
CC=cc
prefix=/usr/local
exec_prefix=/usr/local
bindir=/usr/local/bin
libdir=/usr/local/lib
includedir=/usr/local/include
sysconfdir=/usr/local/etc
CPPFLAGS+= -DSUPER_SECURE
CPPFLAGS+=  -Wno-unknown-pragmas -DGN_NODELEN_T=socklen_t -DGN_SERVLEN_T=socklen_t -DGN_FLAGS_T=int -DHAVE_GNU_GETSERVBYNAME_R -DHAVE_PIPE2 -DHAVE_SOCK_CLOEXEC -DHAVE_CLOCK_GETTIME
LD_SET_SONAME = -Wl,--soname,
LIBDL = -ldl
PTHREAD = -lpthread
