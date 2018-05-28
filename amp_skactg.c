/**
 @brief AMP Device Flow Control
        Socket Accounting
        Copyright 2015-2018 Cisco Systems
        GNU Public License
 @author Craig Davison <crdaviso@cisco.com>
 @date 2015 Feb 19
*/

#include <linux/slab.h>
#include <linux/in.h>
#include <linux/jiffies.h>
#include "compat.h"
#include "amp_skactg.h"
#include "amp_log.h"

/** @todo do initialized thing as with sockcallwatch */


/* Globals: */

static struct kmem_cache *_g_proc_kmem_cache = NULL;
static struct kmem_cache *_g_sk_kmem_cache = NULL;
static struct kmem_cache *_g_proc_sk_kmem_cache = NULL;
static struct kmem_cache *_g_sk_proc_kmem_cache = NULL;
static DEFINE_MUTEX(_g_refcount_mutex);
static int _g_refcount = 0;

/* Types: */

/** client or server */
typedef enum {
    AMP_CLISRV_UNKNOWN,
    AMP_CLISRV_CLIENT,
    AMP_CLISRV_SERVER
} amp_clisrv_t;

/** node in a list of sockets associated with a process */
typedef struct amp_proc_sk_node {
    /** socket */
    struct amp_sk *amp_sk;
    /** this process's position in the socket's list of processes */
    struct amp_sk_proc_node *sk_proc;
    /** prev in list */
    struct amp_proc_sk_node *prev_for_proc;
    /** next in list */
    struct amp_proc_sk_node *next_for_proc;
} amp_proc_sk_node_t;

/** node in a list of processes associated with a socket */
typedef struct amp_sk_proc_node {
    /** process */
    struct amp_proc *amp_proc;
    /** this socket's position in the process's list of sockets */
    struct amp_proc_sk_node *proc_sk;
    /** prev in list */
    struct amp_sk_proc_node *prev_for_sk;
    /** next in list */
    struct amp_sk_proc_node *next_for_sk;
} amp_sk_proc_node_t;

/** structure describing a process */
typedef struct amp_proc {
    /** socket count */
    uint32_t socket_count;
    /** time we started monitoring */
    uint32_t started_monitoring;
    /** socket count limit for monitoring */
    uint32_t socket_limit;
    /** time limit for monitoring */
    uint32_t time_limit;
    /** linked list of sockets */
    struct amp_proc_sk_node *proc_sk_head;
    /** process ID (thread group ID) */
    pid_t tgid;
    /** embedded rb_node */
    struct rb_node tree_node;
    /** next in linked list */
    struct amp_proc *older;
    /** prev in linked list */
    struct amp_proc *newer;
} amp_proc_t;

/** structure describing a socket */
typedef struct amp_sk {
    union {
        struct {
            /** client or server */
            amp_clisrv_t clisrv;
            /** number of bytes relayed over netlink */
            uint32_t sent_count;
            /** remote sockaddr used with this socket. use sockaddr_in6 because
                it can hold either a sockaddr_in or sockaddr_in6, but is
                significantly smaller than sockaddr_storage */
            struct sockaddr_in6 remote_addr;
            /** detection sent */
            bool detection_sent;
        } tcp;
        struct {
            /** last local sockaddr used with this socket. use sockaddr_in6
                because it can hold either a sockaddr_in or sockaddr_in6, but is
                significantly smaller than sockaddr_storage */
            struct sockaddr_in6 last_local_addr;
            /** last remote sockaddr used with this socket. use sockaddr_in6
                because it can hold either a sockaddr_in or sockaddr_in6, but is
                significantly smaller than sockaddr_storage */
            struct sockaddr_in6 last_remote_addr;
            /** detection sent for current set of addrs */
            bool cur_detection_sent;
        } udp;
    } proto;
    /** linked list of processes */
    struct amp_sk_proc_node *sk_proc_head;
    /** time when added - for debug purposes */
    uint32_t time_added;
    /** tgid when added - for debug purposes */
    pid_t first_tgid;
    /** sock */
    struct sock *sk;
    /** unique ID */
    uint64_t id;
    /** embedded rb_node */
    struct rb_node tree_node;
    /** next in linked list */
    struct amp_sk *older;
    /** prev in linked list */
    struct amp_sk *newer;
} amp_sk_t;

typedef enum {
    AMP_SK_OP_CONNECT,
    AMP_SK_OP_ACCEPT,
    AMP_SK_OP_SEND,
    AMP_SK_OP_RECV,
} amp_sk_op_t;

/* Functions: */

/* printk a sockaddr */
static void _printsockaddr(amp_log_level_t log_level,
                           struct sockaddr *sock_name)
{
    if (sock_name->sa_family == AF_INET) {
#ifndef NIPQUAD
        amp_log(log_level, "%pI4:%d",
                &((struct sockaddr_in *)sock_name)->sin_addr,
                ntohs(((struct sockaddr_in *)sock_name)->sin_port));
#else
        amp_log(log_level, NIPQUAD_FMT ":%d",
                NIPQUAD(((struct sockaddr_in *)sock_name)->sin_addr),
                ntohs(((struct sockaddr_in *)sock_name)->sin_port));
#endif
    } else if (sock_name->sa_family == AF_INET6) {
#ifndef NIP6_FMT
        amp_log(log_level, "%pI6:%d",
                &((struct sockaddr_in6 *)sock_name)->sin6_addr,
                ntohs(((struct sockaddr_in6 *)sock_name)->sin6_port));
#else
        amp_log(log_level, NIP6_FMT ":%d",
                NIP6(((struct sockaddr_in6 *)sock_name)->sin6_addr),
                ntohs(((struct sockaddr_in6 *)sock_name)->sin6_port));
#endif
    }
}

/* operation - dump proc info to syslog */
static void _dump_proc(amp_log_level_t log_level, amp_proc_t *amp_proc)
{
    amp_proc_sk_node_t *proc_sk;
    uint32_t cur_uptime;

    cur_uptime = (uint32_t)CUR_UPTIME();
    amp_log(log_level, "proc %d: count %d, age %u, socket_limit %u, time_limit %u, socks [", amp_proc->tgid, amp_proc->socket_count, cur_uptime - amp_proc->started_monitoring, amp_proc->socket_limit, amp_proc->time_limit);
    proc_sk = amp_proc->proc_sk_head;
    while (proc_sk) {
        /*amp_sk_proc_node_t *sk_proc;*/
        amp_log(log_level, "%p ", proc_sk->amp_sk->sk);
        /*amp_log(log_level, "[");
        sk_proc = proc_sk->amp_sk->sk_proc_head;
        while (sk_proc) {
            amp_log(log_level, "%d ", sk_proc->amp_proc->tgid);
            sk_proc = sk_proc->next_for_sk;
        }
        amp_log(log_level, "] ");*/
        proc_sk = proc_sk->next_for_proc;
    }
    amp_log(log_level, "]");
}

/* operation - dump sock info to syslog */
static void _dump_sk(amp_log_level_t log_level, amp_sk_t *amp_sk)
{
    amp_sk_proc_node_t *sk_proc;
    const char *server_label;
    uint32_t cur_uptime;

    cur_uptime = (uint32_t)CUR_UPTIME();
    amp_log(log_level, "sock %p: first tgid %d, age %u, proto %d", amp_sk->sk, amp_sk->first_tgid, cur_uptime - amp_sk->time_added, amp_sk->sk->sk_protocol);
    switch (amp_sk->sk->sk_protocol) {
        case IPPROTO_TCP:
            switch(amp_sk->proto.tcp.clisrv) {
                case AMP_CLISRV_CLIENT:
                    server_label = "client";
                    break;
                case AMP_CLISRV_SERVER:
                    server_label = "server";
                    break;
                default:
                    server_label = "unknown";
                    break;
            }
            amp_log(log_level, ", %s, %u bytes sent, detection%s sent, remote_addr ", server_label, amp_sk->proto.tcp.sent_count, amp_sk->proto.tcp.detection_sent ? "" : " not");
            _printsockaddr(log_level, (struct sockaddr *)&amp_sk->proto.tcp.remote_addr);
            break;
        case IPPROTO_UDP:
            amp_log(log_level, ", detection%s sent, last_local ", amp_sk->proto.udp.cur_detection_sent ? "" : " not");
            _printsockaddr(log_level, (struct sockaddr *)&amp_sk->proto.udp.last_local_addr);
            amp_log(log_level, ", last_remote ");
            _printsockaddr(log_level, (struct sockaddr *)&amp_sk->proto.udp.last_remote_addr);
            break;
        default:
            break;
    }
    amp_log(log_level, ", tgids [");
    sk_proc = amp_sk->sk_proc_head;
    while (sk_proc) {
        /*amp_proc_sk_node_t *proc_sk;*/
        amp_log(log_level, "%d ", sk_proc->amp_proc->tgid);
        /*amp_log(log_level, "[");
        proc_sk = sk_proc->amp_proc->proc_sk_head;
        while (proc_sk) {
            amp_log(log_level, "%p ", proc_sk->amp_sk->sk);
            proc_sk = proc_sk->next_for_proc;
        }
        amp_log(log_level, "] ");*/
        sk_proc = sk_proc->next_for_sk;
    }
    amp_log(log_level, "]");
}

/* operation - lookup proc in proc tree */
static amp_proc_t *_lookup_proc(struct rb_root *root, pid_t tgid)
{
    amp_proc_t *ret = NULL;
    struct rb_node *cur_node;
    amp_proc_t *cur_entry;

    cur_node = root->rb_node;
    while (cur_node)
    {
        cur_entry = rb_entry(cur_node, amp_proc_t, tree_node);

        if (cur_entry->tgid > tgid) {
            cur_node = cur_node->rb_left;
        } else if (cur_entry->tgid < tgid) {
            cur_node = cur_node->rb_right;
        } else {
            ret = cur_entry;
            break;
        }
    }

    return ret;
}

/* operation - insert proc in proc tree */
static int _insert_proc(struct rb_root *root, amp_proc_t *amp_proc)
{
    int ret = 0;
    struct rb_node **link;
    struct rb_node *parent = NULL;
    amp_proc_t *cur_entry;

    /* Go to the bottom of the tree */
    link = &root->rb_node;
    while (*link)
    {
        parent = *link;
        cur_entry = rb_entry(parent, amp_proc_t, tree_node);

        if (cur_entry->tgid > amp_proc->tgid) {
            link = &(*link)->rb_left;
        } else if (cur_entry->tgid < amp_proc->tgid) {
            link = &(*link)->rb_right;
        } else {
            /* already exists in tree */
            ret = -EEXIST;
            goto done;
        }
    }

    /* Put the new node there */
    rb_link_node(&amp_proc->tree_node, parent, link);
    rb_insert_color(&amp_proc->tree_node, root);

done:
    return ret;
}

/* operation - lookup sock in sock tree */
static amp_sk_t *_lookup_sk(struct rb_root *root, struct sock *sk)
{
    amp_sk_t *ret = NULL;
    struct rb_node *cur_node;
    amp_sk_t *cur_entry;

    cur_node = root->rb_node;
    while (cur_node)
    {
        cur_entry = rb_entry(cur_node, amp_sk_t, tree_node);

        if (cur_entry->sk > sk) {
            cur_node = cur_node->rb_left;
        } else if (cur_entry->sk < sk) {
            cur_node = cur_node->rb_right;
        } else {
            ret = cur_entry;
            break;
        }
    }

    return ret;
}

/* operation - insert sock in sock tree */
static int _insert_sk(struct rb_root *root, amp_sk_t *amp_sk)
{
    int ret = 0;
    struct rb_node **link;
    struct rb_node *parent = NULL;
    amp_sk_t *cur_entry;

    /* Go to the bottom of the tree */
    link = &root->rb_node;
    while (*link)
    {
        parent = *link;
        cur_entry = rb_entry(parent, amp_sk_t, tree_node);

        if (cur_entry->sk > amp_sk->sk) {
            link = &(*link)->rb_left;
        } else if (cur_entry->sk < amp_sk->sk) {
            link = &(*link)->rb_right;
        } else {
            /* already exists in tree */
            ret = -EEXIST;
            goto done;
        }
    }

    /* Put the new node there */
    rb_link_node(&amp_sk->tree_node, parent, link);
    rb_insert_color(&amp_sk->tree_node, root);

done:
    return ret;
}

/* operation - release sock: (D)
lookup sock in sock tree (B). if it doesn't exist, return success. (B2)
for each pid in the list:
    remove the reference to this sock
remove each element in the pid list
free amp_sk
return success.
*/
static void _release_sk(amp_skactg_t *handle, amp_sk_t *amp_sk)
{
    amp_sk_proc_node_t *cur_sk_proc, *nxt_sk_proc;
    amp_proc_t *amp_proc;
    amp_proc_sk_node_t *proc_sk;

    /* iterate through list of procs and remove all of them */
    cur_sk_proc = amp_sk->sk_proc_head;
    while (cur_sk_proc) {
        nxt_sk_proc = cur_sk_proc->next_for_sk;

        /* remove from list of socks for that proc */
        amp_proc = cur_sk_proc->amp_proc;
        proc_sk = cur_sk_proc->proc_sk;
        if (proc_sk->prev_for_proc) {
            proc_sk->prev_for_proc->next_for_proc = proc_sk->next_for_proc;
        } else {
            amp_proc->proc_sk_head = proc_sk->next_for_proc;
        }
        if (proc_sk->next_for_proc) {
            proc_sk->next_for_proc->prev_for_proc = proc_sk->prev_for_proc;
        }
        kmem_cache_free(_g_proc_sk_kmem_cache, proc_sk);
        proc_sk = NULL;

        /* remove node */
        kmem_cache_free(_g_sk_proc_kmem_cache, cur_sk_proc);

        cur_sk_proc = nxt_sk_proc;
    }

    rb_erase(&amp_sk->tree_node, &handle->sk_tree);

    /* remove from linked list */
    if (amp_sk->older) {
        amp_sk->older->newer = amp_sk->newer;
    } else {
        handle->oldest_amp_sk = amp_sk->newer;
    }
    if (amp_sk->newer) {
        amp_sk->newer->older = amp_sk->older;
    } else {
        handle->newest_amp_sk = amp_sk->older;
    }
    handle->sk_count--;

    kmem_cache_free(_g_sk_kmem_cache, amp_sk);
    amp_sk = NULL;
}

/* operation - forget about process: (C)
lookup proc in proc tree (A). if it doesn't exist, return success. (A2)
for each sock in the list:
    remove the reference to this proc
remove each element in the sock list
free amp_proc
return success.
NOTE: don't remove sock if there are no more procs associated with it. wait for release. there may be a child process that still holds the sock but hasn't used it yet.
*/
static void _forget_proc(amp_skactg_t *handle, amp_proc_t *amp_proc)
{
    amp_proc_sk_node_t *cur_proc_sk, *nxt_proc_sk;
    amp_sk_t *amp_sk;
    amp_sk_proc_node_t *sk_proc;

    /* iterate through list of sockets and remove all of them */
    cur_proc_sk = amp_proc->proc_sk_head;
    while (cur_proc_sk) {
        nxt_proc_sk = cur_proc_sk->next_for_proc;

        /* remove from list of procs for that sock */
        amp_sk = cur_proc_sk->amp_sk;
        sk_proc = cur_proc_sk->sk_proc;
        if (sk_proc->prev_for_sk) {
            sk_proc->prev_for_sk->next_for_sk = sk_proc->next_for_sk;
        } else {
            amp_sk->sk_proc_head = sk_proc->next_for_sk;
        }
        if (sk_proc->next_for_sk) {
            sk_proc->next_for_sk->prev_for_sk = sk_proc->prev_for_sk;
        }
        kmem_cache_free(_g_sk_proc_kmem_cache, sk_proc);
        sk_proc = NULL;

        /* remove node */
        kmem_cache_free(_g_proc_sk_kmem_cache, cur_proc_sk);

        cur_proc_sk = nxt_proc_sk;
    }

    rb_erase(&amp_proc->tree_node, &handle->proc_tree);

    /* remove from linked list */
    if (amp_proc->older) {
        amp_proc->older->newer = amp_proc->newer;
    } else {
        handle->oldest_amp_proc = amp_proc->newer;
    }
    if (amp_proc->newer) {
        amp_proc->newer->older = amp_proc->older;
    } else {
        handle->newest_amp_proc = amp_proc->older;
    }
    handle->proc_count--;

    kmem_cache_free(_g_proc_kmem_cache, amp_proc);
    amp_proc = NULL;
}

/* operation - should monitor */
static int _should_monitor(amp_skactg_t *handle, amp_sk_op_t op, pid_t tgid,
                           struct sock *sk,
                           const struct sockaddr_storage *local_addr,
                           struct sockaddr_storage *remote_addr,
                           uint64_t *sk_id, uint32_t *num_bytes,
                           uint32_t *seqnum, bool *detect,
                           amp_op_detection_t *detection)
{
    int ret = 0;
    amp_sk_t *amp_sk;
    amp_proc_t *amp_proc;
    amp_sk_proc_node_t *cur_sk_proc;
    amp_proc_sk_node_t *proc_sk;
    uint32_t cur_uptime;
    bool sk_added = false;
    bool increase_sk_count = false;
    bool new_sockaddr = false;
    size_t socklen = 0;
    int err;
    bool addr_found;
    bool cache_detect;
    amp_op_detection_t cache_detection;
    bool dont_monitor = false;
    static struct in6_addr _zero_addr_in6 = {{{ 0 }}};
    static struct in6_addr _loopback_addr_in6 = {{{ 0, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 1 }}};
    static uint8_t _ipv4_net_in6[] = { 0, 0, 0, 0,
                                       0, 0, 0, 0,
                                       0, 0, 0xff, 0xff };
#define IS_IN_LOOPBACK(addr) \
    IN_LOOPBACK(ntohl(((struct sockaddr_in *)addr)->sin_addr.s_addr))
#define IS_IN_ZERO(addr) \
    (ntohl(((struct sockaddr_in *)addr)->sin_addr.s_addr) == INADDR_ANY)
#define IS_IN6_LOOPBACK(addr) \
    (!memcmp(&((struct sockaddr_in6 *)addr)->sin6_addr, &_loopback_addr_in6, sizeof(struct in6_addr)) || \
     (!memcmp(&((struct sockaddr_in6 *)addr)->sin6_addr, _ipv4_net_in6, sizeof(_ipv4_net_in6)) && \
      IN_LOOPBACK(ntohl(((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr32[3]))))
#define IS_IN6_ZERO(addr) \
    (!memcmp(&((struct sockaddr_in6 *)addr)->sin6_addr, &_zero_addr_in6, sizeof(struct in6_addr)) || \
     (!memcmp(&((struct sockaddr_in6 *)addr)->sin6_addr, _ipv4_net_in6, sizeof(_ipv4_net_in6)) && \
      ntohl(((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr32[3]) == INADDR_ANY))

    *detect = false;

    /* only TCP or UDP */
    if (sk->sk_protocol != IPPROTO_TCP && sk->sk_protocol != IPPROTO_UDP) {
        amp_log_err("(op %d) unknown protocol %d", op, sk->sk_protocol);
        goto done;
    }

    /* only send and recv for UDP */
    if (sk->sk_protocol == IPPROTO_UDP &&
            op != AMP_SK_OP_RECV && op != AMP_SK_OP_SEND) {
        goto done;
    }

    cur_uptime = (uint32_t)CUR_UPTIME();
    amp_sk = _lookup_sk(&handle->sk_tree, sk);
    if (!amp_sk) {
        /* if the socket doesn't exist in the tree, and it's TCP, and this is
           not a connect or accept, ignore this */
        if (sk->sk_protocol == IPPROTO_TCP &&
                op != AMP_SK_OP_ACCEPT &&
                op != AMP_SK_OP_CONNECT) {
            goto done;
        }
    } else {
        if (remote_addr->ss_family == 0 && sk->sk_protocol == IPPROTO_TCP &&
                op == AMP_SK_OP_SEND) {
            /* use the saved remote_addr */
            memcpy(remote_addr, &amp_sk->proto.tcp.remote_addr, sizeof(amp_sk->proto.tcp.remote_addr));
        }
    }

    /* ensure that the socket family and protocol are supported */
    if (local_addr->ss_family != remote_addr->ss_family) {
        /* Due to a bug in ruby, this behaviour was observed for panoptimon:
           Jul  5 22:08:32 fireamp kernel: sendmsg: pid 1778, data [21........], len 364, sock ffff881f4376c640, sk ffff882010785100: proto UDP, local 0.0.0.0:42276, remote 0000:0000:0000:0000:0000:0000:0000:0001:5555 */
        amp_log_debug("(op %d) local_addr->ss_family %d != remote_addr->ss_family %d", op, local_addr->ss_family, remote_addr->ss_family);
        /* Ignore this, as the socket call would have never succeeded */
        goto done;
    }
    if (local_addr->ss_family == AF_INET) {
        /* if ignore_loopback is set, and both addresses are either loopback or
           zero, ignore this */
        if (handle->ignore_loopback &&
                (IS_IN_LOOPBACK(local_addr) || IS_IN_ZERO(local_addr)) &&
                (IS_IN_LOOPBACK(remote_addr) || IS_IN_ZERO(remote_addr))) {
            /*amp_log(AMP_LOG_DEBUG, KERN_DEBUG KBUILD_MODNAME ": <debug> ignoring loopback addresses - local ");
            _printsockaddr(AMP_LOG_DEBUG, (struct sockaddr *)local_addr);
            amp_log(AMP_LOG_DEBUG, ", remote ");
            _printsockaddr(AMP_LOG_DEBUG, (struct sockaddr *)remote_addr);
            amp_log(AMP_LOG_DEBUG, "\n");*/
            goto done;
        }
        socklen = sizeof(struct sockaddr_in);
    } else if (local_addr->ss_family == AF_INET6) {
        if (handle->ignore_ipv6) {
            /*amp_log(AMP_LOG_DEBUG, KERN_DEBUG KBUILD_MODNAME ": <debug> ignoring ipv6 addresses - local ");
            _printsockaddr(AMP_LOG_DEBUG, (struct sockaddr *)local_addr);
            amp_log(AMP_LOG_DEBUG, ", remote ");
            _printsockaddr(AMP_LOG_DEBUG, (struct sockaddr *)remote_addr);
            amp_log(AMP_LOG_DEBUG, "\n");*/
            goto done;
        }
        /* if ignore_loopback is set, and both addresses are either loopback or
           zero, ignore this */
        if (handle->ignore_loopback &&
                (IS_IN6_LOOPBACK(local_addr) || IS_IN6_ZERO(local_addr)) &&
                (IS_IN6_LOOPBACK(remote_addr) || IS_IN6_ZERO(remote_addr))) {
            /*amp_log(AMP_LOG_DEBUG, KERN_DEBUG KBUILD_MODNAME ": <debug> ignoring loopback addresses - local ");
            _printsockaddr(AMP_LOG_DEBUG, (struct sockaddr *)local_addr);
            amp_log(AMP_LOG_DEBUG, ", remote ");
            _printsockaddr(AMP_LOG_DEBUG, (struct sockaddr *)remote_addr);
            amp_log(AMP_LOG_DEBUG, "\n");*/
            goto done;
        }
        socklen = sizeof(struct sockaddr_in6);
    } else {
        amp_log_err("(op %d) unknown family %d", op, local_addr->ss_family);
        goto done;
    }

    /* lookup address in cache */
    err = amp_addrcache_lookup(handle->addrcache, (struct sockaddr *)remote_addr, &addr_found, &cache_detect, &cache_detection);
    if (err || !addr_found) {
        cache_detect = false;
    }

    /* lookup process */
    amp_proc = _lookup_proc(&handle->proc_tree, tgid);

    if (!amp_sk) {
        /* Only create a new amp_sk if we're within monitoring limits, or
           cache_detect is true */
        if (amp_proc &&
                (amp_proc->socket_count >= amp_proc->socket_limit ||
                 cur_uptime - amp_proc->started_monitoring >= amp_proc->time_limit)) {
            /* do not monitor */
            dont_monitor = true;
            if (!cache_detect) {
                ret = 0;
                goto done;
            }
        }
        /* delete oldest sock if necessary */
        while (handle->sk_count >= handle->max_sk_count) {
            amp_log(AMP_LOG_INFO, KERN_INFO KBUILD_MODNAME ": <info> dropping oldest ");
            _dump_sk(AMP_LOG_INFO, handle->oldest_amp_sk);
            amp_log(AMP_LOG_INFO, "\n");
            _release_sk(handle, handle->oldest_amp_sk);
        }
        /* create new sock */
        /* using a spinlock, so need GFP_ATOMIC */
        amp_sk = kmem_cache_zalloc(_g_sk_kmem_cache, GFP_ATOMIC);
        if (!amp_sk) {
            amp_log_err("kmem_cache_zalloc failed");
            ret = -ENOMEM;
            goto done;
        }
        if (sk->sk_protocol == IPPROTO_TCP) {
            if (op == AMP_SK_OP_ACCEPT) {
                amp_sk->proto.tcp.clisrv = AMP_CLISRV_SERVER;
            } else if (op == AMP_SK_OP_CONNECT) {
                amp_sk->proto.tcp.clisrv = AMP_CLISRV_CLIENT;
            } else {
                amp_sk->proto.tcp.clisrv = AMP_CLISRV_UNKNOWN;
            }
        }
        amp_sk->sk = sk;
        amp_sk->id = handle->cur_sk_id++;
        amp_sk->time_added = cur_uptime;
        amp_sk->first_tgid = tgid;
        err = _insert_sk(&handle->sk_tree, amp_sk);
        if (err != 0) {
            amp_log_err("_insert_sk failed");
            kmem_cache_free(_g_sk_kmem_cache, amp_sk);
            amp_sk = NULL;
            ret = err;
            goto done;
        }
        /* add to linked list */
        if (handle->newest_amp_sk) {
            handle->newest_amp_sk->newer = amp_sk;
        } else {
            handle->oldest_amp_sk = amp_sk;
        }
        amp_sk->older = handle->newest_amp_sk;
        handle->newest_amp_sk = amp_sk;
        handle->sk_count++;
    }
    *sk_id = amp_sk->id;

    if (!dont_monitor && amp_proc) {
        /* check if this process is already associated with this sock. */
        /* use a linear search. this is acceptable because a sock will
           generally be associated with one or few processes */
        cur_sk_proc = amp_sk->sk_proc_head;
        while (cur_sk_proc &&
               cur_sk_proc->amp_proc != amp_proc) {
            cur_sk_proc = cur_sk_proc->next_for_sk;
        }
        if (!cur_sk_proc) {
            /* Only associate this amp_sk with the process if we're within
               monitoring limits */
            if (amp_proc->socket_count >= amp_proc->socket_limit ||
                cur_uptime - amp_proc->started_monitoring >= amp_proc->time_limit) {
                /* do not monitor */
                dont_monitor = true;
                if (!cache_detect) {
                    ret = 0;
                    goto done;
                }
            }
        }
        if (!cur_sk_proc && !dont_monitor) {
            /* add to lists */
            /* using a spinlock, so need GFP_ATOMIC */
            proc_sk = kmem_cache_zalloc(_g_proc_sk_kmem_cache, GFP_ATOMIC);
            if (!proc_sk) {
                amp_log_err("kmem_cache_zalloc failed");
                ret = -ENOMEM;
                goto done;
            }
            cur_sk_proc = kmem_cache_zalloc(_g_sk_proc_kmem_cache, GFP_ATOMIC);
            if (!cur_sk_proc) {
                amp_log_err("kmem_cache_zalloc failed");
                kmem_cache_free(_g_proc_sk_kmem_cache, proc_sk);
                proc_sk = NULL;
                ret = -ENOMEM;
                goto done;
            }

            proc_sk->amp_sk = amp_sk;
            proc_sk->next_for_proc = amp_proc->proc_sk_head;
            if (proc_sk->next_for_proc) {
                proc_sk->next_for_proc->prev_for_proc = proc_sk;
            }
            amp_proc->proc_sk_head = proc_sk;
            cur_sk_proc->amp_proc = amp_proc;
            cur_sk_proc->next_for_sk = amp_sk->sk_proc_head;
            if (cur_sk_proc->next_for_sk) {
                cur_sk_proc->next_for_sk->prev_for_sk = cur_sk_proc;
            }
            amp_sk->sk_proc_head = cur_sk_proc;
            /* references */
            proc_sk->sk_proc = cur_sk_proc;
            cur_sk_proc->proc_sk = proc_sk;

            sk_added = true;
            increase_sk_count = true;
        }
    }

    if (sk->sk_protocol == IPPROTO_TCP) {
        /* TCP */
        /* update *num_bytes */
        if (!dont_monitor &&
                op == AMP_SK_OP_SEND &&
                amp_sk->proto.tcp.clisrv == AMP_CLISRV_CLIENT) {
            if (amp_sk->proto.tcp.sent_count + *num_bytes > handle->send_limit) {
                if (handle->send_limit > amp_sk->proto.tcp.sent_count) {
                    *num_bytes = handle->send_limit - amp_sk->proto.tcp.sent_count;
                } else {
                    *num_bytes = 0;
                }
            }
            *seqnum = amp_sk->proto.tcp.sent_count;
            amp_sk->proto.tcp.sent_count += *num_bytes;
        } else {
            *num_bytes = 0;
            *seqnum = 0;
        }

        /* update the saved remote addr */
        memcpy(&amp_sk->proto.tcp.remote_addr, remote_addr, socklen);

        if (cache_detect && !amp_sk->proto.tcp.detection_sent) {
            /* send detection */
            amp_sk->proto.tcp.detection_sent = true;
            *detect = cache_detect;
            *detection = cache_detection;
        }

        /* relay to userland if accept, connect or sending data to a server */
        if (!dont_monitor &&
                (op == AMP_SK_OP_ACCEPT || op == AMP_SK_OP_CONNECT ||
                *num_bytes > 0)) {
            ret = 1;
        }
    } else {
        /* UDP */
        /* don't send a payload */
        *num_bytes = 0;
        *seqnum = 0;
        /* update last_*_addr */
        if (memcmp(local_addr, &amp_sk->proto.udp.last_local_addr, socklen)) {
            memcpy(&amp_sk->proto.udp.last_local_addr, local_addr, socklen);
            amp_sk->proto.tcp.detection_sent = true;
            new_sockaddr = true;
            if (!dont_monitor) {
                /* not necessarily a new socket, but a new "connection" that
                   should increase the count */
                increase_sk_count = true;
            }
        }
        if (memcmp(remote_addr, &amp_sk->proto.udp.last_remote_addr, socklen)) {
            memcpy(&amp_sk->proto.udp.last_remote_addr, remote_addr, socklen);
            amp_sk->proto.udp.cur_detection_sent = false;
            new_sockaddr = true;
            if (!dont_monitor) {
                /* not necessarily a new socket, but a new "connection" that
                   should increase the count */
                increase_sk_count = true;
            }
        }
        if (cache_detect && !amp_sk->proto.udp.cur_detection_sent) {
            /* send detection */
            amp_sk->proto.udp.cur_detection_sent = true;
            *detect = cache_detect;
            *detection = cache_detection;
        }
        /* relay to userland if accept, connect or last_*_addr differs */
        if (!dont_monitor &&
                (op == AMP_SK_OP_ACCEPT || op == AMP_SK_OP_CONNECT ||
                new_sockaddr)) {
            ret = 1;
        }
    }

    /* Only increase the socket count for this process if we're within
       monitoring limits */
    if (amp_proc && !sk_added &&
            (amp_proc->socket_count > amp_proc->socket_limit ||
             (increase_sk_count &&
              amp_proc->socket_count >= amp_proc->socket_limit) ||
             cur_uptime - amp_proc->started_monitoring >= amp_proc->time_limit)) {
        /* do not monitor */
        dont_monitor = true;
        if (!cache_detect) {
            ret = 0;
            goto done;
        }
    }

    if (!dont_monitor && amp_proc && increase_sk_count) {
        amp_proc->socket_count++;
    }

done:
    return ret;
}

static void _reset_monitoring(amp_skactg_t *handle)
{
    struct rb_node *cur_node;
    amp_proc_t *amp_proc;

    /* remove nodes in proc tree */
    cur_node = rb_first(&handle->proc_tree);
    while (cur_node) {
        amp_proc = rb_entry(cur_node, amp_proc_t, tree_node);
        _forget_proc(handle, amp_proc);
        cur_node = rb_first(&handle->proc_tree);
    }
}

/* return whether we should monitor this sendmsg and relay it to userland */
int amp_skactg_sendmsg(amp_skactg_t *handle, pid_t tgid, struct sock *sk,
                       const struct sockaddr_storage *local_addr,
                       struct sockaddr_storage *remote_addr,
                       uint64_t *sk_id, uint32_t *num_bytes, uint32_t *seqnum,
                       bool *detect, amp_op_detection_t *detection)
{
    int ret;
    spin_lock(&handle->lock);
    ret = _should_monitor(handle, AMP_SK_OP_SEND, tgid, sk, local_addr, remote_addr, sk_id, num_bytes, seqnum, detect, detection);
    spin_unlock(&handle->lock);
    if (ret < 0) {
        amp_log_err("_should_monitor failed");
    }
    return ret;
}

/* return whether we should monitor this recvmsg and relay it to userland */
int amp_skactg_recvmsg(amp_skactg_t *handle, pid_t tgid, struct sock *sk,
                       const struct sockaddr_storage *local_addr,
                       struct sockaddr_storage *remote_addr,
                       uint64_t *sk_id, uint32_t *num_bytes, uint32_t *seqnum,
                       bool *detect, amp_op_detection_t *detection)
{
    int ret;
    spin_lock(&handle->lock);
    ret = _should_monitor(handle, AMP_SK_OP_RECV, tgid, sk, local_addr, remote_addr, sk_id, num_bytes, seqnum, detect, detection);
    spin_unlock(&handle->lock);
    if (ret < 0) {
        amp_log_err("_should_monitor failed");
    }
    return ret;
}

/* return whether we should monitor this connect and relay it to userland */
int amp_skactg_connect(amp_skactg_t *handle, pid_t tgid, struct sock *sk,
                       const struct sockaddr_storage *local_addr,
                       struct sockaddr_storage *remote_addr, uint64_t *sk_id,
                       bool *detect, amp_op_detection_t *detection)
{
    uint32_t num_bytes = 0;
    uint32_t seqnum;
    int ret;
    spin_lock(&handle->lock);
    ret = _should_monitor(handle, AMP_SK_OP_CONNECT, tgid, sk, local_addr, remote_addr, sk_id, &num_bytes, &seqnum, detect, detection);
    spin_unlock(&handle->lock);
    if (ret < 0) {
        amp_log_err("_should_monitor failed");
    }
    return ret;
}

/* return whether we should monitor this accept and relay it to userland */
int amp_skactg_accept(amp_skactg_t *handle, pid_t tgid, struct sock *sk,
                      const struct sockaddr_storage *local_addr,
                      struct sockaddr_storage *remote_addr, uint64_t *sk_id,
                      bool *detect, amp_op_detection_t *detection)
{
    uint32_t num_bytes = 0;
    uint32_t seqnum;
    int ret;
    spin_lock(&handle->lock);
    ret = _should_monitor(handle, AMP_SK_OP_ACCEPT, tgid, sk, local_addr, remote_addr, sk_id, &num_bytes, &seqnum, detect, detection);
    spin_unlock(&handle->lock);
    if (ret < 0) {
        amp_log_err("_should_monitor failed");
    }
    return ret;
}

/* operation - update limits for process:
lookup pid in pid tree (A). if it doesn't exist, add it. (A1)
change monitoring limits.
return success.
*/
int amp_skactg_update_proc_limits(amp_skactg_t *handle, pid_t tgid,
                                  uint32_t sock_limit, uint32_t time_limit)
{
    amp_proc_t *amp_proc;
    int ret = 0;
    uint32_t cur_uptime;
    int err;

    spin_lock(&handle->lock);
    cur_uptime = (uint32_t)CUR_UPTIME();
    amp_proc = _lookup_proc(&handle->proc_tree, tgid);
    if (!amp_proc) {
        /* delete oldest proc if necessary */
        while (handle->proc_count >= handle->max_proc_count) {
            amp_log(AMP_LOG_INFO, KERN_INFO KBUILD_MODNAME ": <info> dropping oldest ");
            _dump_proc(AMP_LOG_INFO, handle->oldest_amp_proc);
            amp_log(AMP_LOG_INFO, "\n");
            _forget_proc(handle, handle->oldest_amp_proc);
        }
        /* add new proc */
        /* using a spinlock, so need GFP_ATOMIC */
        amp_proc = kmem_cache_zalloc(_g_proc_kmem_cache, GFP_ATOMIC);
        if (!amp_proc) {
            /* spin_unlock here rather than after done: to reduce time spent
               locked */
            spin_unlock(&handle->lock);
            amp_log_err("kmem_cache_zalloc failed");
            ret = -ENOMEM;
            goto done;
        }
        amp_proc->tgid = tgid;
        amp_proc->started_monitoring = cur_uptime;
        err = _insert_proc(&handle->proc_tree, amp_proc);
        if (err != 0) {
            /* spin_unlock here rather than after done: to reduce time spent
               locked */
            spin_unlock(&handle->lock);
            amp_log_err("_insert_proc failed");
            kmem_cache_free(_g_proc_kmem_cache, amp_proc);
            amp_proc = NULL;
            ret = err;
            goto done;
        }
        /* add to linked list */
        if (handle->newest_amp_proc) {
            handle->newest_amp_proc->newer = amp_proc;
        } else {
            handle->oldest_amp_proc = amp_proc;
        }
        amp_proc->older = handle->newest_amp_proc;
        handle->newest_amp_proc = amp_proc;
        handle->proc_count++;
    }
    amp_proc->socket_limit = sock_limit;
    amp_proc->time_limit = time_limit;
    spin_unlock(&handle->lock);

done:
    return ret;
}

/* operation - set options: */
void amp_skactg_set_opts(amp_skactg_t *handle, uint32_t send_limit,
                         bool ignore_ipv6, bool ignore_loopback)
{
    spin_lock(&handle->lock);
    handle->send_limit = send_limit;
    handle->ignore_ipv6 = ignore_ipv6;
    handle->ignore_loopback = ignore_loopback;
    spin_unlock(&handle->lock);
}

/* operation - release sock:
   return whether we should relay the release to userland */
int amp_skactg_release_sk(amp_skactg_t *handle, struct sock *sk,
                          uint64_t *sk_id)
{
    int ret = 0;
    amp_sk_t *amp_sk;

    spin_lock(&handle->lock);
    amp_sk = _lookup_sk(&handle->sk_tree, sk);
    if (amp_sk) {
        *sk_id = amp_sk->id;
        _release_sk(handle, amp_sk);
        ret = 1; /* found */
    }
    spin_unlock(&handle->lock);

    return ret;
}

/* operation - forget about process: */
void amp_skactg_forget_proc(amp_skactg_t *handle, pid_t tgid)
{
    amp_proc_t *amp_proc;

    spin_lock(&handle->lock);
    amp_proc = _lookup_proc(&handle->proc_tree, tgid);
    if (amp_proc) {
        _forget_proc(handle, amp_proc);
    }
    spin_unlock(&handle->lock);
}

/* operation - reset monitoring for all processes */
void amp_skactg_reset_monitoring(amp_skactg_t *handle)
{
    spin_lock(&handle->lock);
    _reset_monitoring(handle);
    spin_unlock(&handle->lock);
}

/* operation - dump info to syslog */
void amp_skactg_dump(amp_skactg_t *handle)
{
    struct rb_node *cur_node;
    amp_proc_t *amp_proc;
    amp_sk_t *amp_sk;

    spin_lock(&handle->lock);

    /* proc tree */
    cur_node = rb_first(&handle->proc_tree);
    while (cur_node) {
        amp_proc = rb_entry(cur_node, amp_proc_t, tree_node);
        amp_log(AMP_LOG_INFO, KERN_INFO KBUILD_MODNAME ": <info> ");
        _dump_proc(AMP_LOG_INFO, amp_proc);
        amp_log(AMP_LOG_INFO, "\n");
        cur_node = rb_next(cur_node);
    }

    /* sock tree */
    cur_node = rb_first(&handle->sk_tree);
    while (cur_node) {
        amp_sk = rb_entry(cur_node, amp_sk_t, tree_node);
        amp_log(AMP_LOG_INFO, KERN_INFO KBUILD_MODNAME ": <info> ");
        _dump_sk(AMP_LOG_INFO, amp_sk);
        amp_log(AMP_LOG_INFO, "\n");
        cur_node = rb_next(cur_node);
    }

    spin_unlock(&handle->lock);
}

/* init */
int amp_skactg_init(amp_skactg_t *handle, amp_addrcache_t *addrcache,
                    uint32_t max_proc_count, uint32_t max_sk_count)
{
    int ret = 0;
    bool refcount_mutex_locked = false;

    if (!handle) {
        ret = -EINVAL;
        goto done;
    }

    memset(handle, 0, sizeof(amp_skactg_t));
    handle->addrcache = addrcache;
    handle->cur_sk_id = CUR_UPTIME() << 24;
    handle->max_proc_count = max_proc_count;
    handle->max_sk_count = max_sk_count;
    spin_lock_init(&handle->lock);

    mutex_lock(&_g_refcount_mutex);
    refcount_mutex_locked = true;
    if (_g_refcount == 0) {
        _g_sk_kmem_cache = KMEM_CACHE_CREATE("csco_amp_skactg_sk",
            sizeof(amp_sk_t), 0 /* align */, 0 /* flags */,
            NULL /* ctor */);
        if (!_g_sk_kmem_cache) {
            amp_log_err("KMEM_CACHE_CREATE(_g_sk_kmem_cache) failed");
            ret = -ENOMEM;
            goto done;
        }
        _g_proc_kmem_cache = KMEM_CACHE_CREATE("csco_amp_skactg_proc",
            sizeof(amp_proc_t), 0 /* align */, 0 /* flags */,
            NULL /* ctor */);
        if (!_g_proc_kmem_cache) {
            amp_log_err("KMEM_CACHE_CREATE(_g_proc_kmem_cache) failed");
            ret = -ENOMEM;
            goto done;
        }
        _g_sk_proc_kmem_cache = KMEM_CACHE_CREATE("csco_amp_skactg_sk_proc",
            sizeof(amp_sk_proc_node_t), 0 /* align */, 0 /* flags */,
            NULL /* ctor */);
        if (!_g_sk_proc_kmem_cache) {
            amp_log_err("KMEM_CACHE_CREATE(_g_sk_proc_kmem_cache) failed");
            ret = -ENOMEM;
            goto done;
        }
        _g_proc_sk_kmem_cache = KMEM_CACHE_CREATE("csco_amp_skactg_proc_sk",
            sizeof(amp_proc_sk_node_t), 0 /* align */, 0 /* flags */,
            NULL /* ctor */);
        if (!_g_proc_sk_kmem_cache) {
            amp_log_err("KMEM_CACHE_CREATE(_g_proc_sk_kmem_cache) failed");
            ret = -ENOMEM;
            goto done;
        }
        amp_log_info("created kmem_caches");
    }
    _g_refcount++;

done:
    if (ret != 0) {
        if (refcount_mutex_locked) {
            if (_g_refcount == 0) {
                if (_g_proc_sk_kmem_cache) {
                    kmem_cache_destroy(_g_proc_sk_kmem_cache);
                    _g_proc_sk_kmem_cache = NULL;
                }
                if (_g_sk_proc_kmem_cache) {
                    kmem_cache_destroy(_g_sk_proc_kmem_cache);
                    _g_sk_proc_kmem_cache = NULL;
                }
                if (_g_proc_kmem_cache) {
                    kmem_cache_destroy(_g_proc_kmem_cache);
                    _g_proc_kmem_cache = NULL;
                }
                if (_g_sk_kmem_cache) {
                    kmem_cache_destroy(_g_sk_kmem_cache);
                    _g_sk_kmem_cache = NULL;
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

/* deinit */
void amp_skactg_deinit(amp_skactg_t *handle)
{
    struct rb_node *cur_node;
    amp_sk_t *amp_sk;

    /* remove nodes in sock tree */
    cur_node = rb_first(&handle->sk_tree);
    while (cur_node) {
        amp_sk = rb_entry(cur_node, amp_sk_t, tree_node);
        _release_sk(handle, amp_sk);
        cur_node = rb_first(&handle->sk_tree);
    }

    _reset_monitoring(handle);

    mutex_lock(&_g_refcount_mutex);
    _g_refcount--;
    if (_g_refcount == 0) {
        kmem_cache_destroy(_g_proc_sk_kmem_cache);
        _g_proc_sk_kmem_cache = NULL;
        kmem_cache_destroy(_g_sk_proc_kmem_cache);
        _g_sk_proc_kmem_cache = NULL;
        kmem_cache_destroy(_g_proc_kmem_cache);
        _g_proc_kmem_cache = NULL;
        kmem_cache_destroy(_g_sk_kmem_cache);
        _g_sk_kmem_cache = NULL;
        amp_log_info("destroyed kmem_caches");
    }
    mutex_unlock(&_g_refcount_mutex);
}

