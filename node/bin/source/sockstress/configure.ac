AC_PREREQ(2.59)
AC_INIT([sockstress], [0.0.5], [root@localhost])
AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_inject])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([netinet/in.h stdint.h stdlib.h string.h sys/socket.h unistd.h arpa/inet.h netdb.h stddef.h sys/time.h])
AC_HEADER_SYS_WAIT
AC_HEADER_TIME
AC_CHECK_MEMBER([struct sockaddr.sa_len], [AC_DEFINE(HAVE_STRUCT_SOCKADDR_LEN)], [], [#include <sys/types.h>
#include <sys/socket.h>])


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_PID_T

# Checks for library functions.
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([gethostbyname inet_ntoa memset socket alarm gettimeofday strchr strrchr strstr strerror strdup])
AC_FUNC_MEMCMP
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC

# Checks for files
AC_CHECK_FILE([/proc/net/route], , AC_MSG_ERROR([cant find /proc/net/route]))
AC_CHECK_FILE([/proc/net/arp], , AC_MSG_ERROR([cant find /proc/net/arp]))

# Other checks
AC_C_BIGENDIAN
if test "x$ac_cv_c_bigendian" = "xyes"; then
	CFLAGS="$CFLAGS -DBIGENDIAN=1"
fi

AC_CONFIG_FILES([Makefile
		 Makefile.inc])
AC_OUTPUT
