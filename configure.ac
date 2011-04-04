AC_PREREQ(2.50)

AC_INIT(rlm_memcache.c)

AM_INIT_AUTOMAKE(rlm_memcache, 0.1)
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
AC_PROG_LIBTOOL
AC_DISABLE_STATIC

AC_CONFIG_FILES([Makefile])

CFLAGS="$CFLAGS -DNDEBUG -Wall -g"

AC_ARG_WITH([freeradius], [AS_HELP_STRING([--with-freeradius=PATH], [Path to freeradius])],
            [
	     RADIUS_LDFLAGS="-L$withval/lib"
	     RADIUS_CFLAGS="-I$withval/include"],
            [
	     RADIUS_LDFLAGS="-L/usr/lib/freeradius"
	     ])

AC_ARG_WITH([libmemcached], [AS_HELP_STRING([--with-libmemcached=PATH], [Path to libmemcached])],
            [
	     MEMCACHE_LDFLAGS="-L$withval/lib"
	     MEMCACHE_CFLAGS="-I$withval/include"],
            [])

AC_CHECK_LIB(pthread, pthread_create,
                [ CFLAGS="$CFLAGS -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS"
                  LIBS="$LIBS -lpthread" ],
                AC_CHECK_LIB(c_r, pthread_create,
                            [ CFLAGS="$CFLAGS -pthread -D_THREAD_SAFE" ],
                            [ WITH_THREADS="no" ]
                            )
                )

CPPFLAGS="$CPPFLAGS $RADIUS_CFLAGS"
AC_CHECK_HEADERS([freeradius/radiusd.h], [], [AC_MSG_FAILURE([freeradius/libradius.h was not found])])

LDFLAGS="$LDFLAGS $RADIUS_LDFLAGS"
AC_CHECK_LIB([freeradius-radius], [main],
	[
	 AC_SUBST([RADIUSLIB], ["$RADIUS_LDFLAGS -lfreeradius-radius"])
	 AC_SUBST([RADIUS_CFLAGS], ["$RADIUS_CFLAGS"])
	],
	[AC_MSG_FAILURE([freeradius library was not found)])]
)

CPPFLAGS="$CPPFLAGS $MEMCACHE_CFLAGS"
AC_CHECK_HEADERS(libmemcached/memcached.h, [], [AC_MSG_FAILURE([libmemcached/memcached.h was not found])])

LDFLAGS="$LDFLAGS $MEMCACHE_LDFLAGS"
AC_CHECK_LIB([memcached], [main],
	[
	 AC_SUBST([MEMCACHELIB], ["$MEMCACHE_LDFLAGS -lmemcached"])
	 AC_SUBST([MEMCACHE_CFLAGS], ["$MEMCACHE_CFLAGS"])
	],
	[AC_MSG_FAILURE([memcached library was not found)])]
)

AC_OUTPUT
