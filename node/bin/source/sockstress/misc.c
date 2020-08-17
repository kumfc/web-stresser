#include "config.h"

char *sockaddrstr(const struct sockaddr *in) {
        union {
                struct f_s *fs;
                const struct sockaddr *s;
                const struct sockaddr_in *sin;
                const struct sockaddr_in6 *sin6;
        } s_u;
        static char nbuf[256], *ret=NULL;
        const void *p=NULL;

        if (in == NULL) {
                return NULL;
        }

        s_u.s=in;

        switch (s_u.fs->family) {
                case AF_INET:
                        p=&s_u.sin->sin_addr;
                        break;

                case AF_INET6:
                        p=&s_u.sin6->sin6_addr;
                        break;

                default:
                        ERR("unknown address family `%d'", s_u.fs->family);
                        return NULL;
        }

        ret=inet_ntop(s_u.fs->family, p, nbuf, sizeof(nbuf) - 1);
        if (ret == NULL) {
                ERR("inet_ntop fails: %s", strerror(errno));
        }

        return ret;
}

