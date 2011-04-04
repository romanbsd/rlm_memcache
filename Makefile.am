INCLUDES= -I@top_srcdir@ @RADIUS_CFLAGS@ @MEMCACHE_CFLAGS@
LIBS= @RADIUSLIB@ @MEMCACHELIB@

pkglib_LTLIBRARIES= rlm_memcache.la

rlm_memcache_la_LDFLAGS= -avoid-version -module -shared
rlm_memcache_la_SOURCES= rlm_memcache.c

test:
	memflush --servers localhost
	radclient -c 1 -f acct.txt -i 1 localhost acct testing123
	memcat --servers localhost 10.1.1.2 | grep -q 972522222222
