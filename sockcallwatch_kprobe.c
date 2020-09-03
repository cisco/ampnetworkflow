/**
 @brief AMP Device Flow Control
        Socket Call Watcher
        Copyright 2014-2018 Cisco Systems
        GNU Public License
 @author Craig Davison <crdaviso@cisco.com>
 @date 2014 Jun 16
*/

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include "compat.h"
#include "sockcallwatch.h"


/* types and globals: */

#define AMP_SCW_KRETPROBE_MAXACTIVE 20

struct _jprobe_elem {
    struct jprobe probe;
    int registered;
    struct _jprobe_elem *next;
};

struct _kretprobe_elem {
    struct kretprobe probe;
    int registered;
    struct _kretprobe_elem *next;
};

static struct {
    int initialized;
    amp_scw_cb_t cb;
    /* using a linked list because this will be small: */
    struct _jprobe_elem *jprobes_head;
    rwlock_t jprobes_list_lock;
    int jprobes_enabled;
    /* using a linked list because this will be small: */
    struct _kretprobe_elem *kretprobes_head;
    rwlock_t kretprobes_list_lock;
    int kretprobes_enabled;
    int register_enabled;
    struct mutex register_mutex;
    struct kmem_cache *jprobe_kmem_cache;
    struct kmem_cache *kretprobe_kmem_cache;
} _state;


/* functions: */

int amp_scw_init(amp_scw_cb_t *cb)
{
    int ret = 0;
    if (_state.initialized) {
        ret = -EINVAL;
        goto done;
    }
    if (!cb ||
            !cb->connect_cb ||
            !cb->release_cb ||
            !cb->accept_cb ||
            !cb->recvmsg_cb ||
            !cb->sendmsg_cb ||
            !cb->post_accept_cb) {
        ret = -EINVAL;
        goto cleanup;
    }
    _state.cb = *cb;
    _state.jprobes_head = NULL;
    _state.jprobes_enabled = 1;
    rwlock_init(&_state.jprobes_list_lock);
    _state.kretprobes_head = NULL;
    _state.kretprobes_enabled = 1;
    rwlock_init(&_state.kretprobes_list_lock);
    mutex_init(&_state.register_mutex);
    _state.register_enabled = 1;
    _state.jprobe_kmem_cache = KMEM_CACHE_CREATE("csco_amp_scw_j",
        sizeof(struct _jprobe_elem), 0 /* align */, 0 /* flags */,
        NULL /* ctor */);
    if (!_state.jprobe_kmem_cache) {
        ret = -ENOMEM;
        goto cleanup;
    }
    _state.kretprobe_kmem_cache = KMEM_CACHE_CREATE("csco_amp_scw_kret",
        sizeof(struct _kretprobe_elem), 0 /* align */, 0 /* flags */,
        NULL /* ctor */);
    if (!_state.kretprobe_kmem_cache) {
        ret = -ENOMEM;
        goto cleanup;
    }
    _state.initialized = 1;
    /* success */
    goto done;

cleanup:
    if (_state.kretprobe_kmem_cache) {
        kmem_cache_destroy(_state.kretprobe_kmem_cache);
        _state.kretprobe_kmem_cache = NULL;
    }
    if (_state.jprobe_kmem_cache) {
        kmem_cache_destroy(_state.jprobe_kmem_cache);
        _state.jprobe_kmem_cache = NULL;
    }
done:
    return ret;
}

int amp_scw_deinit(void)
{
    int ret = 0;
    struct _jprobe_elem *j_next;
    struct _kretprobe_elem *kret_next;

    /* disable registration */
    mutex_lock(&_state.register_mutex);
    _state.register_enabled = 0;
    mutex_unlock(&_state.register_mutex);

    /* unregister kretprobes */
    /* MUST unregister kretprobes before jprobes. If the system is in a
     * kretprobe handler while a jprobe is being unregistered, the kernel will
     * crash on a breakpoint (int3).
     * Fixes https://access.redhat.com/solutions/4710551 */
    write_lock(&_state.kretprobes_list_lock);
    _state.kretprobes_enabled = 0;
    write_unlock(&_state.kretprobes_list_lock);
    while (_state.kretprobes_head) {
        kret_next = _state.kretprobes_head->next;
        if (_state.kretprobes_head->registered) {
            unregister_kretprobe(&_state.kretprobes_head->probe);
        }
        kmem_cache_free(_state.kretprobe_kmem_cache, _state.kretprobes_head);
        _state.kretprobes_head = kret_next;
    }

    /* unregister jprobes */
    write_lock(&_state.jprobes_list_lock);
    _state.jprobes_enabled = 0;
    write_unlock(&_state.jprobes_list_lock);
    while (_state.jprobes_head) {
        j_next = _state.jprobes_head->next;
        if (_state.jprobes_head->registered) {
            unregister_jprobe(&_state.jprobes_head->probe);
        }
        kmem_cache_free(_state.jprobe_kmem_cache, _state.jprobes_head);
        _state.jprobes_head = j_next;
    }

    /* probe handlers are now no longer running:
     * - probes are run with preemption disabled
     * - unregistering a probe runs synchronize_sched()
     * - "synchronize_sched() blocks until all currently-executing preempt-
     *   disabled regions of code complete"
     */
    mutex_destroy(&_state.register_mutex);

    kmem_cache_destroy(_state.kretprobe_kmem_cache);
    _state.kretprobe_kmem_cache = NULL;
    kmem_cache_destroy(_state.jprobe_kmem_cache);
    _state.jprobe_kmem_cache = NULL;

    memset(&_state.cb, 0, sizeof(amp_scw_cb_t));
    _state.initialized = 0;

    return ret;
}

#ifdef STRUCT_MSGHDR_HAS_IOCB
static void _recvmsg_handler(struct socket *sock, struct msghdr *msg,
                             size_t size, int flags)
#else
static void _recvmsg_handler(struct kiocb *iocb, struct socket *sock,
                             struct msghdr *msg, size_t size, int flags)
#endif
{
    amp_scw_recvmsg_cb_t recvmsg_cb;
    if (_state.initialized) {
        recvmsg_cb =_state.cb.recvmsg_cb;
        if (recvmsg_cb) {
#ifdef STRUCT_MSGHDR_HAS_IOCB
            recvmsg_cb(msg->msg_iocb, sock, msg, size, flags);
#else
            recvmsg_cb(iocb, sock, msg, size, flags);
#endif
        }
    }
    jprobe_return();
}

#ifdef STRUCT_MSGHDR_HAS_IOCB
static void _sendmsg_handler(struct socket *sock, struct msghdr *msg,
                             size_t size)
#else
static void _sendmsg_handler(struct kiocb *iocb, struct socket *sock,
                             struct msghdr *msg, size_t size)
#endif
{
    amp_scw_sendmsg_cb_t sendmsg_cb;
    if (_state.initialized) {
        sendmsg_cb = _state.cb.sendmsg_cb;
        if (sendmsg_cb) {
#ifdef STRUCT_MSGHDR_HAS_IOCB
            sendmsg_cb(msg->msg_iocb, sock, msg, size);
#else
            sendmsg_cb(iocb, sock, msg, size);
#endif
        }
    }
    jprobe_return();
}

static void _connect_handler(struct socket *sock,
                             struct sockaddr * uaddr,
                             int addr_len, int flags)
{
    amp_scw_connect_cb_t connect_cb;
    if (_state.initialized) {
        connect_cb = _state.cb.connect_cb;
        if (connect_cb) {
            connect_cb(sock, uaddr, addr_len, flags);
        }
    }
    jprobe_return();
}

static void _release_handler(struct socket *sock)
{
    amp_scw_release_cb_t release_cb;
    if (_state.initialized) {
        release_cb = _state.cb.release_cb;
        if (release_cb) {
            release_cb(sock);
        }
    }
    jprobe_return();
}

#ifdef PROTO_ACCEPT_HAS_KERN
static void _accept_handler(struct socket *sock,
                            struct socket *newsock, int flags, bool kern)
#else
static void _accept_handler(struct socket *sock, 
                            struct socket *newsock, int flags)
#endif
{
    amp_scw_accept_cb_t accept_cb;
    if (_state.initialized) {
        accept_cb = _state.cb.accept_cb;
        if (accept_cb) {
            accept_cb(sock, newsock, flags);
        }
    }
    jprobe_return();
}

static int _post_accept_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct sock *sk;
    amp_scw_post_accept_cb_t post_accept_cb;

    sk = (struct sock *)regs_return_value(regs);

    if (_state.initialized) {
        post_accept_cb = _state.cb.post_accept_cb;
        if (post_accept_cb) {
            (void)post_accept_cb(sk);
        }
    }
    /** @todo XXX find out what this return value means: */
    return 0;
}

static void _dummy_handler(void)
{
    /* does nothing */
    jprobe_return();
}

static int _jprobe_is_registered(kprobe_opcode_t *func)
{
    int exists = 0;
    struct _jprobe_elem *elem;
    if (_state.jprobes_enabled) {
        elem = _state.jprobes_head;
        while (elem) {
            if (elem->probe.kp.addr == func) {
                /* already in list */
                exists = 1;
                break;
            }
            elem = elem->next;
        }
    }
    return exists;
}

static int _kretprobe_is_registered(kprobe_opcode_t *func)
{
    int exists = 0;
    struct _kretprobe_elem *elem;
    if (_state.kretprobes_enabled) {
        elem = _state.kretprobes_head;
        while (elem) {
            if (elem->probe.kp.addr == func) {
                /* already in list */
                exists = 1;
                break;
            }
            elem = elem->next;
        }
    }
    return exists;
}

static int _register_jprobe(kprobe_opcode_t *func, kprobe_opcode_t *handler)
{
    int err;
    int ret = 0;
    struct _jprobe_elem *elem = NULL;
    int need_add;
    int mutex_locked = 0;

    if (!func || !handler) {
        /* null arguments */
        ret = -EINVAL;
        goto done;
    }

    write_lock(&_state.jprobes_list_lock);

    /* first check if we have already hooked this func */
    need_add = !_jprobe_is_registered(func);

    /* if not already registered, register jprobe and add to the linked list */
    if (need_add && _state.jprobes_enabled) {
        /* using a spinlock, so need GFP_ATOMIC */
        elem = kmem_cache_zalloc(_state.jprobe_kmem_cache, GFP_ATOMIC);
        if (!elem) {
            /* write_unlock here rather than after done: to reduce time spent
               locked */
            write_unlock(&_state.jprobes_list_lock);
            ret = -ENOMEM;
            goto done;
        }
        elem->probe.kp.addr = func;
        elem->probe.entry = handler;
        elem->next = _state.jprobes_head;
        _state.jprobes_head = elem;
    }

    write_unlock(&_state.jprobes_list_lock);

    /* elem may be an invalid pointer at this point. However, since the deinit
       function sets _state.register_enabled to 0 before freeing the jprobes
       list, we will only attempt to dereference it if it is valid. */
    if (elem) {
        mutex_lock(&_state.register_mutex);
        mutex_locked = 1;
        if (_state.register_enabled) {
            err = register_jprobe(&elem->probe);
            if (err != 0) {
                ret = err;
                goto done;
            }
            elem->registered = 1;
        }
    }

done:
    if (mutex_locked) {
        mutex_unlock(&_state.register_mutex);
        mutex_locked = 0;
    }

    return ret;
}

static int _register_kretprobe(kprobe_opcode_t *func,
                               kretprobe_handler_t handler)
{
    int err;
    int ret = 0;
    struct _kretprobe_elem *elem = NULL;
    int need_add;
    int mutex_locked = 0;

    if (!func || !handler) {
        /* null arguments */
        ret = -EINVAL;
        goto done;
    }

    write_lock(&_state.kretprobes_list_lock);

    /* first check if we have already hooked this func */
    need_add = !_kretprobe_is_registered(func);

    /* if not already registered, register jprobe and add to the linked list */
    if (need_add && _state.kretprobes_enabled) {
        /* using a spinlock, so need GFP_ATOMIC */
        elem = kmem_cache_zalloc(_state.kretprobe_kmem_cache, GFP_ATOMIC);
        if (!elem) {
            /* write_unlock here rather than after done: to reduce time spent
               locked */
            write_unlock(&_state.kretprobes_list_lock);
            ret = -ENOMEM;
            goto done;
        }
        elem->probe.kp.addr = func;
        elem->probe.handler = handler;
        elem->probe.maxactive = AMP_SCW_KRETPROBE_MAXACTIVE;
        elem->next = _state.kretprobes_head;
        _state.kretprobes_head = elem;
    }

    write_unlock(&_state.kretprobes_list_lock);

    /* elem may be an invalid pointer at this point. However, since the deinit
       function sets _state.register_enabled to 0 before freeing the kretprobes
       list, we will only attempt to dereference it if it is valid. */
    if (elem) {
        mutex_lock(&_state.register_mutex);
        mutex_locked = 1;
        if (_state.register_enabled) {
            err = register_kretprobe(&elem->probe);
            if (err != 0) {
                ret = err;
                goto done;
            }
            elem->registered = 1;
        }
    }

done:
    if (mutex_locked) {
        mutex_unlock(&_state.register_mutex);
        mutex_locked = 0;
    }

    return ret;
}

int amp_scw_register_recvmsg(amp_scw_recvmsg_fn_t func)
{
    return _register_jprobe((kprobe_opcode_t *)func, (kprobe_opcode_t *)_recvmsg_handler);
}

int amp_scw_register_sendmsg(amp_scw_sendmsg_fn_t func)
{
    return _register_jprobe((kprobe_opcode_t *)func, (kprobe_opcode_t *)_sendmsg_handler);
}

int amp_scw_register_connect(amp_scw_connect_fn_t func)
{
    return _register_jprobe((kprobe_opcode_t *)func, (kprobe_opcode_t *)_connect_handler);
}

int amp_scw_register_release(amp_scw_release_fn_t func)
{
    return _register_jprobe((kprobe_opcode_t *)func, (kprobe_opcode_t *)_release_handler);
}

int amp_scw_register_accept(amp_scw_accept_fn_t func)
{
    return _register_jprobe((kprobe_opcode_t *)func, (kprobe_opcode_t *)_accept_handler);
}

int amp_scw_register_dummy(amp_scw_dummy_fn_t func)
{
    return _register_jprobe((kprobe_opcode_t *)func, (kprobe_opcode_t *)_dummy_handler);
}

int amp_scw_register_post_accept(amp_scw_post_accept_fn_t func)
{
    return _register_kretprobe((kprobe_opcode_t *)func, _post_accept_handler);
}

int amp_scw_is_registered(void *func)
{
    int exists;
    read_lock(&_state.jprobes_list_lock);
    exists = _jprobe_is_registered((kprobe_opcode_t *)func);
    read_unlock(&_state.jprobes_list_lock);
    if (!exists) {
        read_lock(&_state.kretprobes_list_lock);
        exists = _kretprobe_is_registered((kprobe_opcode_t *)func);
        read_unlock(&_state.kretprobes_list_lock);
    }
    return exists;
}

