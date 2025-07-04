/*   (C) 2011, 2012 rofl0r
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef IS_MAC
#define _DARWIN_C_SOURCE
#endif
#include <dlfcn.h>

#include "common.h"

static int usage(char **argv) {
        printf("\nUsage:\t%s -q -f config_file --udp --debug -id proxy_id program_name [arguments]\n"
               "\t-q makes proxychains quiet - this overrides the config setting\n"
               "\t-f allows one to manually specify a configfile to use\n"
               "\t--udp forces UDP mode for SOCKS proxies\n"
               "\t--debug enables detailed debug logging\n"
               "\t-id allows selection of a specific proxy by ID (1, 2, 3, etc.)\n"
               "\tfor example : proxando -id 2 telnet somehost.com\n" "More help in README file\n\n", argv[0]);
        return EXIT_FAILURE;
}

static const char *dll_name = DLL_NAME;

static char own_dir[256];
static const char *dll_dirs[] = {
#ifndef SUPER_SECURE /* CVE-2015-3887 */
        ".",
#endif
        own_dir,
        LIB_DIR,
        "/lib",
        "/usr/lib",
        "/usr/local/lib",
        "/lib64",
        NULL
};

static void set_own_dir(const char *argv0) {
        size_t l = strlen(argv0);
        while(l && argv0[l - 1] != '/')
                l--;
        if(l == 0 || l >= sizeof(own_dir))
#ifdef SUPER_SECURE
                memcpy(own_dir, "/dev/null/", 11);
#else
                memcpy(own_dir, ".", 2);
#endif
        else {
                memcpy(own_dir, argv0, l - 1);
                own_dir[l] = 0;
        }
}

#define MAX_COMMANDLINE_FLAGS 3

int main(int argc, char *argv[]) {
        char *path = NULL;
        char buf[256];
        char pbuf[256];
        int start_argv = 1;
        int quiet = 0;
        int force_udp = 0;
        size_t i;
        const char *prefix = NULL;

        if(argc == 2 && !strcmp(argv[1], "--help"))
                return usage(argv);

        // Cerca le opzioni --udp e --debug in qualsiasi posizione
        for(i = 1; i < argc; i++) {
                if(!strcmp(argv[i], "--udp")) {
                        force_udp = 1;
                        // Sposta gli argomenti per rimuovere --udp dalla lista
                        memmove(&argv[i], &argv[i+1], (argc - i) * sizeof(char*));
                        argc--;
                        i--; // Ricontrolla la stessa posizione dopo lo spostamento
                } else if(!strcmp(argv[i], "--debug")) {
                        setenv(PROXYCHAINS_DEBUG_MODE_ENV_VAR, "1", 1);
                        // Sposta gli argomenti per rimuovere --debug dalla lista
                        memmove(&argv[i], &argv[i+1], (argc - i) * sizeof(char*));
                        argc--;
                        i--; // Ricontrolla la stessa posizione dopo lo spostamento
                }
        }
        
        for(i = 0; i < MAX_COMMANDLINE_FLAGS; i++) {
                if(start_argv < argc && argv[start_argv][0] == '-') {
                        if(argv[start_argv][1] == 'q') {
                                quiet = 1;
                                start_argv++;
                        } else if(argv[start_argv][1] == 'f') {

                                if(start_argv + 1 < argc)
                                        path = argv[start_argv + 1];
                                else
                                        return usage(argv);

                                start_argv += 2;
                        } else if(!strcmp(argv[start_argv], "-id")) {
                                if(start_argv + 1 < argc) {
                                        int proxy_id = atoi(argv[start_argv + 1]);
                                        if(proxy_id > 0) {
                                                setenv("PROXYCHAINS_PROXY_ID", argv[start_argv + 1], 1);
                                        } else {
                                                fprintf(stderr, LOG_PREFIX "Invalid proxy ID: %s\n", argv[start_argv + 1]);
                                                return usage(argv);
                                        }
                                } else {
                                        return usage(argv);
                                }
                                start_argv += 2;
                        }
                } else
                        break;
        }

        if(start_argv >= argc)
                return usage(argv);

        /* check if path of config file has not been passed via command line */
        path = get_config_path(path, pbuf, sizeof(pbuf));

        if(!quiet)
                fprintf(stderr, LOG_PREFIX "config file found: %s\n", path);

        /* Set PROXYCHAINS_CONF_FILE to get proxando lib to use new config file. */
        setenv(PROXYCHAINS_CONF_FILE_ENV_VAR, path, 1);

        if(quiet)
                setenv(PROXYCHAINS_QUIET_MODE_ENV_VAR, "1", 1);
        
        /* Se attivata l'opzione --udp, imposta la variabile d'ambiente per forzare il routing UDP */
        if(force_udp) {
                if(!quiet)
                        fprintf(stderr, LOG_PREFIX "UDP mode forced\n");
                setenv("PROXYCHAINS_FORCE_UDP", "1", 1);
        }


        // search DLL

        Dl_info dli;
        dladdr(own_dir, &dli);
        set_own_dir(dli.dli_fname);

        i = 0;

        while(dll_dirs[i]) {
                snprintf(buf, sizeof(buf), "%s/%s", dll_dirs[i], dll_name);
                if(access(buf, R_OK) != -1) {
                        prefix = dll_dirs[i];
                        break;
                }
                i++;
        }

        if(!prefix) {
                fprintf(stderr, "couldnt locate %s\n", dll_name);
                return EXIT_FAILURE;
        }
        if(!quiet)
                fprintf(stderr, LOG_PREFIX "preloading %s/%s\n", prefix, dll_name);

#if defined(IS_MAC) || defined(IS_OPENBSD)
#define LD_PRELOAD_SEP ":"
#else
/* Dynlinkers for Linux and most BSDs seem to support space
   as LD_PRELOAD separator, with colon added only recently.
   We use the old syntax for maximum compat */
#define LD_PRELOAD_SEP " "
#endif

#ifdef IS_MAC
        putenv("DYLD_FORCE_FLAT_NAMESPACE=1");
#define LD_PRELOAD_ENV "DYLD_INSERT_LIBRARIES"
#else
#define LD_PRELOAD_ENV "LD_PRELOAD"
#endif
        char *old_val = getenv(LD_PRELOAD_ENV);
        snprintf(buf, sizeof(buf), LD_PRELOAD_ENV "=%s/%s%s%s",
                 prefix, dll_name,
                 /* append previous LD_PRELOAD content, if existent */
                 old_val ? LD_PRELOAD_SEP : "",
                 old_val ? old_val : "");
        putenv(buf);
        execvp(argv[start_argv], &argv[start_argv]);
        fprintf(stderr, "proxando: can't load process '%s'.", argv[start_argv]);
        perror(" (hint: it's probably a typo)");

        return EXIT_FAILURE;
}
