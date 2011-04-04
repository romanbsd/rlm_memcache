#include <freeradius/radiusd.h>
#include <freeradius/modules.h>
#include <freeradius/rad_assert.h>
#include <libmemcached/memcached.h>

/* maximum size of stored values */
#define BUFFERLEN 4096

/* maximum length of memcached key */
#define KEYLEN 32

typedef struct rlm_memcache_t {
	char *key;
	char *servers;
	memcached_st *memc;
} rlm_memcache_t;

static const CONF_PARSER module_config[] = {
	{ "key", PW_TYPE_STRING_PTR, offsetof(rlm_memcache_t, key), NULL, "Framed-IP-Address" },
	{ "servers", PW_TYPE_STRING_PTR, offsetof(rlm_memcache_t, servers), NULL, "localhost" },
	{ NULL, -1, 0, NULL, NULL }
};


static int memcache_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_memcache_t *inst;
	char *p, *last = NULL, *server;
	unsigned int port;
	memcached_return rc;
	memcached_server_st *server_list = NULL;

	inst = rad_malloc(sizeof(*inst));

	bzero(inst, sizeof(*inst));

	if ( cf_section_parse(conf, inst, module_config) < 0 ) {
		radlog(L_ERR, "rlm_memcache: Cannot parse config");
		free(inst);
		return -1;
	}

	if ( ! inst->servers ) {
		radlog(L_ERR, "rlm_memcache: 'servers' not specified");
		free(inst);
		return -1;
	}
	
	DEBUG("Key for memcached: %s", inst->key);

	inst->memc = memcached_create(NULL);

	for ( server = strtok_r(inst->servers, " ", &last); server; server = strtok_r(NULL, " ", &last) ) {
		if ( (p = strchr(server, ':' )) ) {
			*p = 0;
			p++;
			port = atoi(p);
		} else {
			port = MEMCACHED_DEFAULT_PORT;
		}
		DEBUG("Adding memcached server: %s:%u", server, port);
		server_list = memcached_server_list_append(server_list, server, port, &rc);
		if ( rc != MEMCACHED_SUCCESS) {
			radlog(L_ERR, "libmemcached: %s", memcached_strerror(inst->memc, rc));
			return -1;
		}
	}

	rc = memcached_server_push(inst->memc, server_list);
	memcached_server_list_free(server_list);

	if ( rc != MEMCACHED_SUCCESS) {
		radlog(L_ERR, "libmemcached: %s", memcached_strerror(inst->memc, rc));
		return -1;
	}

	*instance = inst;

	return 0;
}

static int memcache_detach(void *instance)
{
	rlm_memcache_t *p = instance;

	memcached_free(p->memc);
	free(p->servers);
	free(p->key);
	free(p);

	return 0;
}

static int memcache_account(void *instance, REQUEST *request)
{
	rlm_memcache_t *p = instance;
	char *vptr;
	const char *attr;
	int len, count = 0, left = 0, remove = 0;
	char val[BUFFERLEN], key[KEYLEN], out[255];
	memcached_return rc;

	rad_assert(request->packet != NULL);

	vptr = val;
	*vptr++ = '{';

	VALUE_PAIR *first = request->packet->vps;
	key[0] = 0;
	/* go over linked list of attribute value-pairs */
	while (first) {
		attr = first->name;
		if ( !key[0] && !strcmp(attr, p->key) ) {
			vp_prints_value(key, sizeof(key), first, 0);
			if (remove) {
				break;
			}
		}
		else if ( first->attribute == PW_ACCT_STATUS_TYPE ) {
			if ( first->lvalue == PW_STATUS_STOP ) {
				remove = 1;
				/* only if the key is alrady known */
				if (key[0]) {
					break;
				}
			}
		}
		/* if we need to remove key, no need to process attrs */
		else if ( remove ) {
			continue;
		}
		/* it's not a key, add to JSON hash */
		else {
			/* check that we have enough space */
			left = BUFFERLEN - (vptr-val);
			if ( left <= 0 ) {
				left = 0;
				break;
			}
			if ( count ) {
				*vptr++ = ',';
				left--;
			}
			len = vp_prints_value(out, sizeof(out), first, 0);

			snprintf(vptr, left, "\"%s\":\"%s\"", attr, out);
			vptr += len + strlen(attr) + 5; /* 4 * "  + 1 * : */
			count++;
		}
		first = first->next;
	}
	if ( remove ) {
		RDEBUG("removing '%s'", key);
		rc = memcached_delete(p->memc, key, strlen(key), (time_t)0);

	} else {
		left = BUFFERLEN - (vptr-val);
		if ( left > 1) {
			*vptr++ = '}';
			*vptr = 0;
		} else {
			val[BUFFERLEN-1] = 0;
		}

		RDEBUG("setting '%s' => '%s'", key, val);
		rc = memcached_set(p->memc, key, strlen(key), val, strlen(val), (time_t)0, (uint32_t)0);
	}

	if ( rc != MEMCACHED_SUCCESS) {
		radlog_request(L_ERR, 0, request, "libmemcached: %s", memcached_strerror(p->memc, rc));
		return RLM_MODULE_FAIL;
	}

	return RLM_MODULE_OK;
}

module_t rlm_memcache = {
	RLM_MODULE_INIT,
        "memcache",
        RLM_TYPE_THREAD_SAFE,           /* type */
        memcache_instantiate,           /* instantiation */
        memcache_detach,                /* detach */
        {
                NULL,                   /* authentication */
                NULL,                   /* authorization */
                memcache_account,	/* preaccounting */
                memcache_account,       /* accounting */
                NULL,                   /* checksimul */
                NULL,                   /* pre-proxy */
                NULL,                   /* post-proxy */
                NULL                    /* post-auth */
        },
};
