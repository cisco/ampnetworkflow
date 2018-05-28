/**
 @brief AMP Device Flow Control
        IP Address Cache
        Copyright 2016-2018 Cisco Systems
        GNU Public License
 @author Craig Davison <crdaviso@cisco.com>
 @date 2016 May 27
*/

#include <linux/slab.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/jiffies.h>
#include "compat.h"
#include "amp_addrcache.h"
#include "amp_log.h"

/** @todo do initialized thing as with sockcallwatch */


/* Globals: */

static struct kmem_cache *_g_entry_kmem_cache = NULL;
static DEFINE_MUTEX(_g_refcount_mutex);
static int _g_refcount = 0;
/** default maximum # of entries: */
static const uint32_t _g_default_cache_max_size = 1000;
/** absolute maximum # of entries: */
static const uint32_t _g_abs_cache_max_size = 1000000;
/** default clean TTL, in seconds: */
static const uint32_t _g_default_cache_ttl_clean = 86400;
/** default malicious TTL, in seconds: */
static const uint32_t _g_default_cache_ttl_malicious = 86400;

/* Types: */

/* entry in the cache tree */
typedef struct amp_addrcache_entry {
    struct rb_node tree_node;
    /** Remote address. Fields other than the family and address are ignored.
        sockaddr_in6 is used because it can hold either a sockaddr_in or
        sockaddr_in6, but is significantly smaller than sockaddr_storage: */
    struct sockaddr_in6 remote_addr;
    bool detect;
    amp_op_detection_t detection;
    uint32_t first_used;
    struct amp_addrcache_entry *prev;
    struct amp_addrcache_entry *next;
} amp_addrcache_entry_t;

/* Functions: */

static inline int _cmp_addr(const struct sockaddr *a, const struct sockaddr *b)
{
    int diff;
    if (a->sa_family < b->sa_family) {
        diff = -1;
    } else if (a->sa_family > b->sa_family) {
        diff = 1;
    } else if (a->sa_family == AF_INET) {
        diff = memcmp(&((struct sockaddr_in *)a)->sin_addr, &((struct sockaddr_in *)b)->sin_addr, sizeof(struct in_addr));
    } else {
        diff = memcmp(&((struct sockaddr_in6 *)a)->sin6_addr, &((struct sockaddr_in6 *)b)->sin6_addr, sizeof(struct in6_addr));
    }
    return diff;
}

static amp_addrcache_entry_t *_lookup_entry(struct rb_root *root,
                                            const struct sockaddr *addr)
{
    amp_addrcache_entry_t *ret = NULL;
    struct rb_node *cur_node;
    amp_addrcache_entry_t *cur_entry;
    int diff;

    cur_node = root->rb_node;
    while (cur_node)
    {
        cur_entry = rb_entry(cur_node, amp_addrcache_entry_t, tree_node);

        diff = _cmp_addr(addr, (struct sockaddr *)&cur_entry->remote_addr);
        if (diff < 0) {
            cur_node = cur_node->rb_left;
        } else if (diff > 0) {
            cur_node = cur_node->rb_right;
        } else {
            ret = cur_entry;
            break;
        }
    }

    return ret;
}

static int _insert_entry(struct rb_root *root, amp_addrcache_entry_t *entry)
{
    int ret = 0;
    struct rb_node **link;
    struct rb_node *parent = NULL;
    amp_addrcache_entry_t *cur_entry;
    int diff;

    /* Go to the bottom of the tree */
    link = &root->rb_node;
    while (*link)
    {
        parent = *link;
        cur_entry = rb_entry(parent, amp_addrcache_entry_t, tree_node);

        diff = _cmp_addr((struct sockaddr *)&entry->remote_addr, (struct sockaddr *)&cur_entry->remote_addr);
        if (diff < 0) {
            link = &(*link)->rb_left;
        } else if (diff > 0) {
            link = &(*link)->rb_right;
        } else {
            /* already exists in tree */
            ret = -EEXIST;
            goto done;
        }
    }

    /* Put the new node there */
    rb_link_node(&entry->tree_node, parent, link);
    rb_insert_color(&entry->tree_node, root);

done:
    return ret;
}

static int _del_entry(amp_addrcache_t *handle, amp_addrcache_entry_t *entry)
{
    int ret = 0;
    amp_log_debug("removing cache_entry %p", entry);
    do {
        rb_erase(&entry->tree_node, &handle->tree);
        /* remove from list */
        if (entry->prev) {
            entry->prev->next = entry->next;
        }
        if (entry->next) {
            entry->next->prev = entry->prev;
        }
        if (handle->list_head == entry) {
            handle->list_head = entry->next;
        }
        if (handle->list_tail == entry) {
            handle->list_tail = entry->prev;
        }
        handle->size--;
        kmem_cache_free(_g_entry_kmem_cache, entry);
        entry = NULL;
    } while (0);
    return ret;
}

static void _move_to_head(amp_addrcache_t *handle, amp_addrcache_entry_t *entry)
{
    if (entry->prev) {
        entry->prev->next = entry->next;
    }
    if (entry->next) {
        entry->next->prev = entry->prev;
    }
    if (handle->list_head == entry) {
        handle->list_head = entry->next;
    }
    if (handle->list_tail == entry) {
        handle->list_tail = entry->prev;
    }
    entry->prev = NULL;
    entry->next = handle->list_head;
    handle->list_head = entry;
    if (entry->next) {
        entry->next->prev = entry;
    } else {
        handle->list_tail = handle->list_head;
    }
}

int amp_addrcache_add(amp_addrcache_t *handle,
                      const struct sockaddr *remote_addr, bool detect,
                      amp_op_detection_t *detection)
{
    int ret = 0;
    amp_addrcache_entry_t *add_entry;
    amp_addrcache_entry_t *found_entry;
    uint32_t cur_uptime;
    char addr_str[INET6_ADDRSTRLEN];

    spin_lock(&handle->lock);
    do {
        if (handle->max_size < 1) {
            break;
        }
        cur_uptime = (uint32_t)CUR_UPTIME();
        if (remote_addr->sa_family != AF_INET &&
                remote_addr->sa_family != AF_INET6) {
            amp_log_err("Invalid sa_family %d", remote_addr->sa_family);
            ret = -1;
            break;
        }
        found_entry = _lookup_entry(&handle->tree, remote_addr);
        if (!found_entry) {
            /* if necessary, make space in the cache */
            while (handle->size >= handle->max_size) {
                if (_del_entry(handle, handle->list_tail)) {
                    amp_log_err("_del_entry failed");
                    ret = -1;
                    break;
                }
            }
            if (ret != 0) {
                break;
            }

            /* insert the new entry */
            /* using a spinlock, so need GFP_ATOMIC */
            add_entry = kmem_cache_zalloc(_g_entry_kmem_cache, GFP_ATOMIC);
            if (!add_entry) {
                amp_log_err("kmem_cache_zalloc failed");
                ret = -1;
                break;
            }
            ((struct sockaddr *)&add_entry->remote_addr)->sa_family = remote_addr->sa_family;
            if (remote_addr->sa_family == AF_INET) {
                memcpy(&((struct sockaddr_in *)&add_entry->remote_addr)->sin_addr, &((struct sockaddr_in *)remote_addr)->sin_addr, sizeof(struct in_addr));
            } else {
                memcpy(&((struct sockaddr_in6 *)&add_entry->remote_addr)->sin6_addr, &((struct sockaddr_in6 *)remote_addr)->sin6_addr, sizeof(struct in6_addr));
            }
            if (_insert_entry(&handle->tree, add_entry) != 0) {
                amp_log_err("_insert_entry failed");
                kmem_cache_free(_g_entry_kmem_cache, add_entry);
                add_entry = NULL;
                ret = -1;
                break;
            }

            handle->size++;
            add_entry->first_used = cur_uptime;
            found_entry = add_entry;
            if (detect) {
                amp_log_info("Added to cache: %s (detect=%d, remote_classification=%d, detection_name=%s)", amp_addr_to_str(remote_addr, addr_str, sizeof(addr_str)), detect, detection->remote_classification, detection->detection_name);
            } else {
                amp_log_debug("Added to cache: %s (detect=%d, remote_classification=%d, detection_name=%s)", amp_addr_to_str(remote_addr, addr_str, sizeof(addr_str)), detect, detection->remote_classification, detection->detection_name);
            }
        } else {
            if (found_entry->detect != detect) {
                amp_log_info("Updating cache: %s (detect=%d (was %d), remote_classification=%d (was %d), detection_name=%s (was %s))", amp_addr_to_str(remote_addr, addr_str, sizeof(addr_str)), detect, found_entry->detect, detection->remote_classification, found_entry->detection.remote_classification, detection->detection_name, found_entry->detection.detection_name);
            } else {
                amp_log_debug("Updating cache: %s (detect=%d (was %d), remote_classification=%d (was %d), detection_name=%s (was %s))", amp_addr_to_str(remote_addr, addr_str, sizeof(addr_str)), detect, found_entry->detect, detection->remote_classification, found_entry->detection.remote_classification, detection->detection_name, found_entry->detection.detection_name);
            }
        }

        found_entry->detect = detect;
        found_entry->detection = *detection;
        /* move this entry to the head of the list */
        _move_to_head(handle, found_entry);
    } while (0);
    spin_unlock(&handle->lock);

    return ret;
}

int amp_addrcache_lookup(amp_addrcache_t *handle,
                         const struct sockaddr *remote_addr, bool *found,
                         bool *detect, amp_op_detection_t *detection)
{
    int ret = 0;
    amp_addrcache_entry_t *found_entry;
    uint32_t cur_uptime;
    char addr_str[INET6_ADDRSTRLEN];

    spin_lock(&handle->lock);
    do {
        if (remote_addr->sa_family != AF_INET &&
                remote_addr->sa_family != AF_INET6) {
            amp_log_err("Invalid sa_family %d", remote_addr->sa_family);
            ret = -1;
            break;
        }
        found_entry = _lookup_entry(&handle->tree, remote_addr);
        if (found_entry) {
            cur_uptime = (uint32_t)CUR_UPTIME();
            if (found_entry->first_used + (found_entry->detect ? handle->ttl_malicious : handle->ttl_clean) < cur_uptime) {
                /* entry is too old */
                amp_log_debug("expiring cache_entry %p", found_entry);
                *found = false;
                if (_del_entry(handle, found_entry)) {
                    amp_log_err("_del_entry failed");
                    ret = -1;
                    break;
                }
            } else {
                /* move this entry to the head of the list */
                _move_to_head(handle, found_entry);
                *found = true;
                *detect = found_entry->detect;
                *detection = found_entry->detection;
            }
        } else {
            *found = false;
        }
    } while (0);
    spin_unlock(&handle->lock);

    if (ret == 0) {
        if (*found) {
            if (*detect) {
                amp_log_info("Found in cache: %s (detect=%d)", amp_addr_to_str(remote_addr, addr_str, sizeof(addr_str)), *detect);
            } else {
                amp_log_debug("Found in cache: %s (detect=%d)", amp_addr_to_str(remote_addr, addr_str, sizeof(addr_str)), *detect);
            }
        } else {
            amp_log_debug("Not found in cache: %s", amp_addr_to_str(remote_addr, addr_str, sizeof(addr_str)));
        }
    }

    return ret;
}

int amp_addrcache_set_opts(amp_addrcache_t *handle, uint32_t max_size,
                           uint32_t ttl_clean, uint32_t ttl_malicious)
{
    amp_addrcache_entry_t *entry, *next;
    uint32_t cur_uptime;
    int ret = 0;

    spin_lock(&handle->lock);
    cur_uptime = (uint32_t)CUR_UPTIME();
    do {
        if (ttl_clean == UINT32_MAX) {
            ttl_clean = _g_default_cache_ttl_clean;
        }
        if (ttl_malicious == UINT32_MAX) {
            ttl_malicious = _g_default_cache_ttl_malicious;
        }
        if (max_size == UINT32_MAX) {
            max_size = _g_default_cache_max_size;
        } else if (max_size > _g_abs_cache_max_size) {
            max_size = _g_abs_cache_max_size;
        }

        /* if necessary, make space in the cache */
        while (handle->size > max_size) {
            if (_del_entry(handle, handle->list_tail)) {
                amp_log_err("_del_entry failed");
                ret = -1;
                break;
            }
        }
        if (ret != 0) {
            break;
        }

        /* expire any entries outside the new cache TTL. this is inefficient,
         * but will happen infrequently */
        if (ttl_clean < handle->ttl_clean ||
                ttl_malicious < handle->ttl_malicious) {
            entry = handle->list_head;
            while (entry) {
                next = entry->next;
                if (entry->first_used + (entry->detect ? ttl_malicious : ttl_clean) < cur_uptime) {
                    /* entry is too old */
                    amp_log_debug("expiring cache_entry %p", entry);
                    if (_del_entry(handle, entry)) {
                        amp_log_err("_del_entry failed");
                        ret = -1;
                        break;
                    }
                }
                entry = next;
            }
            if (ret != 0) {
                break;
            }
        }

        handle->max_size = max_size;
        handle->ttl_clean = ttl_clean;
        handle->ttl_malicious = ttl_malicious;
    } while (0);
    spin_unlock(&handle->lock);

    return ret;
}

int amp_addrcache_empty(amp_addrcache_t *handle)
{
    int ret = 0;

    /* empty cache */
    while (handle->list_head) {
        if ((ret = _del_entry(handle, handle->list_head)) != 0) {
            amp_log_err("_del_entry failed");
            goto done;
        }
    }
    if (handle->list_tail != NULL) {
        amp_log_err("handle->list_tail != NULL");
        ret = -1;
        goto done;
    }
    if (rb_first(&handle->tree)) {
        amp_log_err("tree is not empty");
        ret = -1;
        goto done;
    }
    if (handle->size != 0) {
        amp_log_err("size != 0");
        ret = -1;
        goto done;
    }

done:
    return ret;
}

int amp_addrcache_init(amp_addrcache_t *handle, uint32_t max_size,
                       uint32_t ttl_clean, uint32_t ttl_malicious)
{
    int ret = 0;
    bool refcount_mutex_locked = false;

    if (!handle) {
        ret = -EINVAL;
        goto done;
    }

    memset(handle, 0, sizeof(amp_addrcache_t));
    if (ttl_clean == UINT32_MAX) {
        ttl_clean = _g_default_cache_ttl_clean;
    }
    if (ttl_malicious == UINT32_MAX) {
        ttl_malicious = _g_default_cache_ttl_malicious;
    }
    if (max_size == UINT32_MAX) {
        max_size = _g_default_cache_max_size;
    } else if (max_size > _g_abs_cache_max_size) {
        max_size = _g_abs_cache_max_size;
    }
    handle->max_size = max_size;
    handle->ttl_clean = ttl_clean;
    handle->ttl_malicious = ttl_malicious;
    spin_lock_init(&handle->lock);

    mutex_lock(&_g_refcount_mutex);
    refcount_mutex_locked = true;
    if (_g_refcount == 0) {
        _g_entry_kmem_cache = KMEM_CACHE_CREATE("csco_amp_addrcache",
            sizeof(amp_addrcache_entry_t), 0 /* align */, 0 /* flags */,
            NULL /* ctor */);
        if (!_g_entry_kmem_cache) {
            amp_log_err("KMEM_CACHE_CREATE(_g_entry_kmem_cache) failed");
            ret = -ENOMEM;
            goto done;
        }
        amp_log_info("created kmem_cache");
    }
    _g_refcount++;

done:
    if (ret != 0) {
        if (refcount_mutex_locked) {
            if (_g_refcount == 0) {
                if (_g_entry_kmem_cache) {
                    kmem_cache_destroy(_g_entry_kmem_cache);
                    _g_entry_kmem_cache = NULL;
                }
            }
        }
    }
    if (refcount_mutex_locked) {
        mutex_unlock(&_g_refcount_mutex);
        refcount_mutex_locked = false;
    }

    return ret;
}

int amp_addrcache_deinit(amp_addrcache_t *handle)
{
    int ret = 0;

    if ((ret = amp_addrcache_empty(handle)) != 0) {
        goto done;
    }

    mutex_lock(&_g_refcount_mutex);
    _g_refcount--;
    if (_g_refcount == 0) {
        kmem_cache_destroy(_g_entry_kmem_cache);
        _g_entry_kmem_cache = NULL;
        amp_log_info("destroyed kmem_cache");
    }
    mutex_unlock(&_g_refcount_mutex);

done:
    return ret;
}

