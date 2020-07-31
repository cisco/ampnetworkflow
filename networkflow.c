/**
 @brief AMP Device Flow Control
        Copyright 2014-2018 Cisco Systems
        GNU Public License
 @author Craig Davison <crdaviso@cisco.com>
 @date 2014 Jun 9
*/

#include <linux/module.h>
#include <linux/net.h>
#include <net/sock.h>       /* must include this before inet_common.h */
#include <net/inet_common.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <net/genetlink.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/fs.h>

#include "sockcallwatch.h"
#include "amp_skactg.h"
#include "amp_log.h"
#include "amp_addrcache.h"
#include "include/ampnetworkflow.h"
#include "compat.h"

#ifdef HAVE_SCHED_MM_H
#include <linux/sched/mm.h>
#endif
#ifdef HAVE_SCHED_TASK_H
#include <linux/sched/task.h>
#endif

MODULE_LICENSE("GPL");      /* because we require several GPL-only symbols */
MODULE_AUTHOR("Craig Davison <crdaviso@cisco.com>");
MODULE_DESCRIPTION("Cisco AMP Device Flow Control");

/*
$ grep skactg /proc/slabinfo
csco_amp_skactg_proc_sk      0      0     32  112    1 : tunables  120   60    8 : slabdata      0      0      0
csco_amp_skactg_sk_proc      0      0     32  112    1 : tunables  120   60    8 : slabdata      0      0      0
csco_amp_skactg_proc      0      0     72   53    1 : tunables  120   60    8 : slabdata      0      0      0
csco_amp_skactg_sk      4     60    128   30    1 : tunables  120   60    8 : slabdata      2      2      0

100000 sockets + 2000 processes + (worst case) every process is associated with
1000 sockets = 12800000 + 144000 + 128000000
*/
#define SKACTG_MAX_PROC_COUNT 2000
#define SKACTG_MAX_SK_COUNT 100000


/* TODO:
   - conn_count/sock_count confusion
   - don't send the whole sockaddr_storage over netlink?
   - reference count for ipv6 module? might not be needed
   - recvmsg_cb when not connected
*/


/* function prototypes: */

static int _set_monitoring(struct sk_buff *skb, struct genl_info *info);
static int _forget_monitoring(struct sk_buff *skb, struct genl_info *info);
static int _set_opts(struct sk_buff *skb, struct genl_info *info);
static int _action(struct sk_buff *skb, struct genl_info *info);
static int _reset_monitoring(struct sk_buff *skb, struct genl_info *info);
static int _dump_accounting(struct sk_buff *skb, struct genl_info *info);
static int _hello(struct sk_buff *skb, struct genl_info *info);


/* globals: */

static const struct proto_ops *_g_tcpv4_ops = NULL;
static const struct proto_ops *_g_udpv4_ops = NULL;
static const struct proto_ops *_g_tcpv6_ops = NULL;
static const struct proto_ops *_g_udpv6_ops = NULL;

static struct {
    atomic_t genlmsg_seq;

    /** nl_portid - only send messages to this peer, and do not send at all if
      *             it is 0.
      * set nl_portid whenever a message is received from userland, and reset it
      * to 0 if send fails. since only root can send a message, this ensures
      * that the peer is a process owned by root. */
    uint32_t nl_portid;
    struct mutex portid_mutex;
    uint32_t last_drop_msg;
    uint32_t num_dropped_msgs;

    atomic_t num_rec_queued;
    struct workqueue_struct *proc_name_wq;
    struct workqueue_struct *msg_send_wq;
    struct kmem_cache *proc_name_kmem_cache;
    struct kmem_cache *register_release_kmem_cache;
} _g_state = {
    .genlmsg_seq = ATOMIC_INIT(0),
    .num_rec_queued = ATOMIC_INIT(0),
};

static amp_skactg_t _g_skactg;
static amp_addrcache_t _g_addrcache;

/* generic netlink family setup
   links:
   http://lwn.net/Articles/208755/
   http://www.linuxfoundation.org/collaborate/workgroups/networking/generic_netlink_howto
   linux-2.6.29/net/wimax/
   linux-2.6.29/include/linux/wimax.h
   http://1984.lsi.us.es/~pablo/docs/spae.pdf
   Chapter 2 of "Linux Kernel Networking: Implementation and Theory", by Rami Rosen
 */
static struct genl_family _g_genl_family = {
#ifdef GENL_ID_GENERATE
    .id          = GENL_ID_GENERATE,
#endif
    .hdrsize     = 0,
    .name        = AMP_NKE_GENL_FAM_NAME,
    .version     = AMP_NKE_GENL_VERSION,
    .maxattr     = AMP_NKE_ATTR_COUNT-1,
};
/* using __read_mostly instead of const because genl_register_ops does not take in const pointers */
static struct nla_policy _g_cmd_set_monitoring_pol[AMP_NKE_ATTR_COUNT] __read_mostly = {
    [AMP_NKE_ATTR_PID] = { .type = NLA_U32 },
    [AMP_NKE_ATTR_CONN_LIMIT] = { .type = NLA_U32 },
    [AMP_NKE_ATTR_TIME_LIMIT] = { .type = NLA_U32 },
};
static struct nla_policy _g_cmd_forget_monitoring_pol[AMP_NKE_ATTR_COUNT] __read_mostly = {
    [AMP_NKE_ATTR_PID] = { .type = NLA_U32 },
};
static struct nla_policy _g_cmd_set_opts_pol[AMP_NKE_ATTR_COUNT] __read_mostly = {
    [AMP_NKE_ATTR_SET_SEND_LIMIT] = { .type = NLA_U32 },
    [AMP_NKE_ATTR_IGNORE_IPV6] = { .type = NLA_FLAG },
    [AMP_NKE_ATTR_IGNORE_LOOPBACK] = { .type = NLA_FLAG },
    [AMP_NKE_ATTR_LOG_LEVEL] = { .type = NLA_U8 },
    [AMP_NKE_ATTR_CACHE_TTL_MALICIOUS] = { .type = NLA_U32 },
    [AMP_NKE_ATTR_CACHE_TTL_CLEAN] = { .type = NLA_U32 },
    [AMP_NKE_ATTR_CACHE_MAX_SIZE] = { .type = NLA_U32 },
};
static struct nla_policy _g_cmd_action_pol[AMP_NKE_ATTR_COUNT] __read_mostly = {
    [AMP_NKE_ATTR_FLOW_REMOTE_SOCKADDR] = { .len = sizeof(struct sockaddr_storage) },
    [AMP_NKE_ATTR_REMOTE_CLASSIFICATION] = { .type = NLA_U8 },
    [AMP_NKE_ATTR_CACHE_REMOTE] = { .type = NLA_FLAG },
    /* do not list AMP_NKE_ATTR_DETECTION_NAME as it is optional and not of a
     * fixed size */
};
static struct nla_policy _g_no_attrs_pol[AMP_NKE_ATTR_COUNT] __read_mostly = {
};
static struct genl_ops _g_genl_ops[] = {
    {
        .cmd     = AMP_NKE_CMD_SET_MONITORING_FOR_PID,
        .flags   = GENL_ADMIN_PERM,
        .policy  = _g_cmd_set_monitoring_pol,
        .doit    = _set_monitoring,
    },
    {
        .cmd     = AMP_NKE_CMD_FORGET_MONITORING_FOR_PID,
        .flags   = GENL_ADMIN_PERM,
        .policy  = _g_cmd_forget_monitoring_pol,
        .doit    = _forget_monitoring,
    },
    {
        .cmd     = AMP_NKE_CMD_SET_OPTS,
        .flags   = GENL_ADMIN_PERM,
        .policy  = _g_cmd_set_opts_pol,
        .doit    = _set_opts,
    },
    {
        .cmd     = AMP_NKE_CMD_ACTION_ALLOW,
        .flags   = GENL_ADMIN_PERM,
        .policy  = _g_cmd_action_pol,
        .doit    = _action,
    },
    {
        .cmd     = AMP_NKE_CMD_ACTION_DETECT,
        .flags   = GENL_ADMIN_PERM,
        .policy  = _g_cmd_action_pol,
        .doit    = _action,
    },
    {
        .cmd     = AMP_NKE_CMD_ACTION_UNCHANGED,
        .flags   = GENL_ADMIN_PERM,
        .policy  = _g_cmd_action_pol,
        .doit    = _action,
    },
    {
        .cmd     = AMP_NKE_CMD_RESET_MONITORING,
        .flags   = GENL_ADMIN_PERM,
        .policy  = _g_no_attrs_pol,
        .doit    = _reset_monitoring,
    },
    {
        .cmd     = AMP_NKE_CMD_DUMP_ACCOUNTING,
        .flags   = GENL_ADMIN_PERM,
        .policy  = _g_no_attrs_pol,
        .doit    = _dump_accounting,
    },
    {
        .cmd     = AMP_NKE_CMD_HELLO,
        .flags   = GENL_ADMIN_PERM,
        .policy  = _g_no_attrs_pol,
        .doit    = _hello,
    }
};


/* functions: */

static int _getsockinfo(struct socket *sock,
                        struct sockaddr_storage *sock_name,
                        struct sockaddr_storage *peer_name,
                        unsigned char *protocol,
                        int *connected,
                        const char *caller)
{
    int ret = 0;
    int len;
    int err;

    if (!sock) {
        /* sock is NULL */
        amp_log_info("caller %s: sock is NULL", caller);
        ret = -EINVAL;
        goto done;
    }
    if (!sock->sk) {
        /* sock->sk is NULL */
        /* this is possible on release when the socket was never connected */
        amp_log_debug("caller %s: sock->sk is NULL", caller);
        ret = -EINVAL;
        goto done;
    }
    if (sock->sk->sk_family != PF_INET && sock->sk->sk_family != PF_INET6) {
        /* non-inet socket */
        ret = -EINVAL;
        goto done;
    }
    if (sock->sk->sk_protocol != IPPROTO_TCP && sock->sk->sk_protocol != IPPROTO_UDP) {
        /* socket is not TCPv4, UDPv4, TCPv6 or UDPv6 */
        ret = -EINVAL;
        goto done;
    }
    *protocol = sock->sk->sk_protocol;

    if (!sock->ops) {
        /* sock->ops is NULL */
        amp_log_info("caller %s: sock->ops is NULL", caller);
        ret = -EINVAL;
        goto done;
    }
    if (!sock->ops->getname) {
        /* sock->ops->getname is NULL */
        amp_log_info("caller %s: sock->ops->getname is NULL", caller);
        ret = -EINVAL;
        goto done;
    }
    len = sizeof(struct sockaddr_storage);
    err = sock->ops->getname(sock, (struct sockaddr *)sock_name, &len, 0);
    if (err != 0) {
        amp_log_info("caller %s: sock->ops->getname(peer=%d) returned %d", caller, 0, err);
        ret = err;
        goto done;
    }
    len = sizeof(struct sockaddr_storage);
    err = sock->ops->getname(sock, (struct sockaddr *)peer_name, &len, 1);
    if (err == -ENOTCONN) {
        *connected = 0;
    } else if (err != 0) {
        amp_log_info("caller %s: sock->ops->getname(peer=%d) returned %d", caller, 1, err);
        ret = err;
        goto done;
    } else {
        *connected = 1;
    }

done:
    return ret;
}

static void _printsockinfo(char *str,
                          int str_size,
                          struct sockaddr *sock_name,
                          struct sockaddr *peer_name,
                          unsigned char proto)
{
    str[0] = '\0';
    if (sock_name->sa_family == AF_INET) {
#ifndef NIPQUAD
        snprintf(str, str_size,
                 "proto %s, local %pI4:%d",
                 proto == IPPROTO_TCP ? "TCP" : "UDP",
                 &((struct sockaddr_in *)sock_name)->sin_addr,
                 ntohs(((struct sockaddr_in *)sock_name)->sin_port));
#else
        snprintf(str, str_size,
                 "proto %s, local " NIPQUAD_FMT ":%d",
                 proto == IPPROTO_TCP ? "TCP" : "UDP",
                 NIPQUAD(((struct sockaddr_in *)sock_name)->sin_addr),
                 ntohs(((struct sockaddr_in *)sock_name)->sin_port));
#endif
    } else if (sock_name->sa_family == AF_INET6) {
#ifndef NIP6_FMT
        snprintf(str, str_size,
                 "proto %s, local %pI6:%d",
                 proto == IPPROTO_TCP ? "TCP" : "UDP",
                 &((struct sockaddr_in6 *)sock_name)->sin6_addr,
                 ntohs(((struct sockaddr_in6 *)sock_name)->sin6_port));
#else
        snprintf(str, str_size,
                 "proto %s, local " NIP6_FMT ":%d",
                 proto == IPPROTO_TCP ? "TCP" : "UDP",
                 NIP6(((struct sockaddr_in6 *)sock_name)->sin6_addr),
                 ntohs(((struct sockaddr_in6 *)sock_name)->sin6_port));
#endif
    }
    if (peer_name && peer_name->sa_family == AF_INET) {
#ifndef NIPQUAD
        snprintf(&str[strlen(str)], str_size - strlen(str),
                 ", remote %pI4:%d",
                 &((struct sockaddr_in *)peer_name)->sin_addr,
                 ntohs(((struct sockaddr_in *)peer_name)->sin_port));
#else
        snprintf(&str[strlen(str)], str_size - strlen(str),
                 ", remote " NIPQUAD_FMT ":%d",
                 NIPQUAD(((struct sockaddr_in *)peer_name)->sin_addr),
                 ntohs(((struct sockaddr_in *)peer_name)->sin_port));
#endif
    } else if (peer_name && peer_name->sa_family == AF_INET6) {
#ifndef NIP6_FMT
        snprintf(&str[strlen(str)], str_size - strlen(str),
                 ", remote %pI6:%d",
                 &((struct sockaddr_in6 *)peer_name)->sin6_addr,
                 ntohs(((struct sockaddr_in6 *)peer_name)->sin6_port));
#else
        snprintf(&str[strlen(str)], str_size - strlen(str),
                 ", remote " NIP6_FMT ":%d",
                 NIP6(((struct sockaddr_in6 *)peer_name)->sin6_addr),
                 ntohs(((struct sockaddr_in6 *)peer_name)->sin6_port));
#endif
    }
}

static void _iovec_to_str(struct msghdr *msg, size_t size, char *str, size_t str_size)
{
    size_t copy_len;
    size_t i;

    if (str_size <= 0) {
        goto done;
    }
    str[0] = '\0';
    copy_len = size < str_size-1 ? size : str_size-1;

    if (msg && copy_len > 0) {
#ifdef STRUCT_MSGHDR_HAS_IOV_ITER
        struct iov_iter iter;
        size_t n;
        iter = msg->msg_iter;
        n = copy_from_iter(str, copy_len, &iter);
        if (n != copy_len) {
            amp_log_info("copy_from_iter(copy_len=%lu, size=%lu) returned %lu", copy_len, size, n);
            str[0] = '\0';
            goto done;
        }
#else
        int err;
        if (!msg->msg_iov) {
            goto done;
        }
        err = memcpy_fromiovecend(str, msg->msg_iov, 0, copy_len);
        if (err != 0) {
            amp_log_info("memcpy_fromiovecend(copy_len=%lu, size=%lu) returned %d", copy_len, size, err);
            str[0] = '\0';
            goto done;
        }
#endif
    }

    for (i = 0; i < copy_len; i++) {
        if (str[i] < 0x20 || str[i] > 0x7e) {
            /* mask unprintable characters */
            str[i] = '.';
        }
    }
    str[copy_len] = '\0';

done:
    return;
}

/* d_path adds this suffix to deleted files: */
#define DELETED_SUFFIX " (deleted)"

/* adapted from proc_exe_link in fs/proc/task_mmu.c (<= 2.6.25)
                                 and fs/proc/base.c (>= 2.6.26) */
/* see also http://www.spinics.net/lists/newbies/msg19536.html */
/* if d_path does not return the full path, we may need to look at something
   like http://www.gossamer-threads.com/lists/linux/kernel/343214 */
static char *_get_proc_path(struct task_struct *task, char *buf, int buflen)
{
    struct file *exe_file = NULL;
#ifndef MM_STRUCT_EXE_FILE
    struct vm_area_struct *vma;
#endif
    char *result = ERR_PTR(-ENOENT);
    struct mm_struct *mm = NULL;
#ifndef STRUCT_FILE_F_PATH
    struct dentry *dentry = NULL;
    struct vfsmount *mnt = NULL;
#endif
    size_t len;

    if (!task) {
        amp_log_err("task is NULL");
        result = ERR_PTR(-EINVAL);
        goto out;
    }
    mm = get_task_mm(task);
    if (!mm) {
        /* most likely, task was killed */
        amp_log_debug("get_task_mm returned NULL (pid %d has already exited)", task_tgid_nr(task));
        goto out;
    }
    down_read(&mm->mmap_sem);

#ifdef MM_STRUCT_EXE_FILE
    exe_file = mm->exe_file;
    if (!exe_file) {
        amp_log_info("mm->exe_file is NULL");
    }
#else
    vma = mm->mmap;
    while (vma) {
        if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
            exe_file = vma->vm_file;
            break;
        }
        vma = vma->vm_next;
    }
    if (!exe_file) {
        amp_log_info("VM_EXECUTABLE not found");
    }
#endif

    if (exe_file) {
        get_file(exe_file);
#ifdef STRUCT_FILE_F_PATH
        path_get(&exe_file->f_path);
#else
        mnt = mntget(exe_file->f_vfsmnt);
        dentry = dget(exe_file->f_dentry);
#endif
    }

    up_read(&mm->mmap_sem);
    mmput(mm);

    if (exe_file) {
#ifdef STRUCT_FILE_F_PATH
        result = d_path(&exe_file->f_path, buf, buflen);
        path_put(&exe_file->f_path);
#else
        if (mnt && dentry) {
            result = d_path(dentry, mnt, buf, buflen);
            if (!result) {
                amp_log_err("d_path failed");
            } else if (IS_ERR(result)) {
                amp_log_err("d_path failed: %ld", PTR_ERR(result));
            }
        }
        if (dentry) {
            dput(dentry);
        }
        if (mnt) {
            mntput(mnt);
        }
#endif
        fput(exe_file);
    }

    /** @note The (deleted) suffix is a design flaw in d_path that we must work
              around. We want a path with no suffix, but it's not possible to
              distinguish a deleted file from one with (deleted) at the end of
              its name.
              There is a D_PATH_NO_DELETED in compat.h, but it's too risky to
              use - the locking in d_path changes frequently between kernel
              versions */
    if (result && !IS_ERR(result)) {
        len = strlen(result);
        if (len >= sizeof(DELETED_SUFFIX) - 1) {
            if (strcmp(&result[len - (sizeof(DELETED_SUFFIX) - 1)],
                    DELETED_SUFFIX) == 0) {
                result[len - (sizeof(DELETED_SUFFIX) - 1)] = '\0';
            }
        }
    }
    /** @todo On newer kernels, we can use dentry_path_raw to get the filename
              (but not full path) without the (deleted) suffix.
              TODO: if d_path returns a path with a (deleted) suffix, consider
              replacing everything after the rightmost / with everything after
              the rightmost / from the dentry_path_raw output. This will
              remove the ambiguity of the (deleted) suffix, but will require
              a second buffer, and there may be a race condition because we
              would be building two paths. */

out:
    return result;
}

typedef struct {
    struct work_struct work;
    struct task_struct *task;
    uint8_t cmd;
    amp_nke_sk_op_t sk_op;
    pid_t pid;
    uid_t uid;
    struct sockaddr_storage local_addr;
    struct sockaddr_storage remote_addr;
    uint8_t proto;
    uint64_t sk_id;
    char *filename_buf;
    char *filename_ptr;
    size_t payload_size;
    amp_op_detection_t detection;
    uint32_t payload_seqnum;
    uint8_t payload[0];
} _send_rec_cb_t;

#define ATTR_BUFFER_ROOM 1024

static inline size_t _msg_send_offset(_send_rec_cb_t *cb_data,
                                      size_t payload_offset)
{
    int err;
    int mutex_locked = 0;
    struct sk_buff *skb = NULL;
    void *genl_msg;
    struct nlattr *payload_attr;
    void *payload_data;
    size_t payload_size = 0;

    /* atomic operations are nonintuitive here. atomic_inc increases the
       sequence number, but also ensures that a subsequent call to
       atomic_read() in this thread will return that value, not the current
       sequence number as would be expected.
       see https://www.kernel.org/doc/Documentation/atomic_ops.txt */
    atomic_inc(&_g_state.genlmsg_seq);

    /* use at least 8 kB so we can fit the payload and filename */
    skb = alloc_skb(SKB_MAX_ALLOC, GFP_KERNEL);
    if (!skb) {
        amp_log_err("alloc_skb failed");
        goto done;
    }

    genl_msg = GENLMSG_PUT(skb, 0 /* portid */, atomic_read(&_g_state.genlmsg_seq), &_g_genl_family, 0 /* flags */, cb_data->cmd);
    if (genl_msg == NULL) {
        amp_log_err("genlmsg_put failed");
        goto done;
    }

    err = nla_put_u8(skb, AMP_NKE_ATTR_REC_SK_OP, cb_data->sk_op);
    if (err != 0) {
        amp_log_err("nla_put_u8(sk_op) failed");
        goto done;
    }
    err = nla_put_u32(skb, AMP_NKE_ATTR_REC_UID, cb_data->uid);
    if (err != 0) {
        amp_log_err("nla_put_u32(uid) failed");
        goto done;
    }
    err = nla_put_u32(skb, AMP_NKE_ATTR_REC_PID, cb_data->pid);
    if (err != 0) {
        amp_log_err("nla_put_u32(tgid) failed");
        goto done;
    }
    if (cb_data->local_addr.ss_family != 0) {
        err = nla_put(skb, AMP_NKE_ATTR_REC_FLOW_LOCAL_SOCKADDR, sizeof(struct sockaddr_storage), &cb_data->local_addr);
        if (err != 0) {
            amp_log_err("nla_put(local_addr) failed");
            goto done;
        }
    }
    if (cb_data->remote_addr.ss_family != 0) {
        err = nla_put(skb, AMP_NKE_ATTR_REC_FLOW_REMOTE_SOCKADDR, sizeof(struct sockaddr_storage), &cb_data->remote_addr);
        if (err != 0) {
            amp_log_err("nla_put(remote_addr) failed");
            goto done;
        }
    }
    err = nla_put_u8(skb, AMP_NKE_ATTR_REC_FLOW_PROTOCOL, cb_data->proto);
    if (err != 0) {
        amp_log_err("nla_put_u8(sock_proto) failed");
        goto done;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0)
    err = nla_put_u64_64bit(skb, AMP_NKE_ATTR_REC_SOCK_ID, cb_data->sk_id, AMP_NKE_ATTR_PAD);
    if (err != 0) {
        amp_log_err("nla_put_u64_64bit(sk_id) failed");
        goto done;
    }
#else
    err = nla_put_u64(skb, AMP_NKE_ATTR_REC_SOCK_ID, cb_data->sk_id);
    if (err != 0) {
        amp_log_err("nla_put_u64(sk_id) failed");
        goto done;
    }
#endif
    if (cb_data->filename_ptr) {
        err = nla_put_string(skb, AMP_NKE_ATTR_REC_FILENAME, cb_data->filename_ptr);
        if (err != 0) {
            amp_log_err("nla_put_string(filename_ptr) failed");
            goto done;
        }
    }
    if (cb_data->payload_size > payload_offset &&
            skb_tailroom(skb) > ATTR_BUFFER_ROOM) {
        ssize_t max_size = skb_tailroom(skb) - ATTR_BUFFER_ROOM;
        payload_size = cb_data->payload_size - payload_offset;
        /* whittle payload_size down until it fits */
        while (max_size < nla_total_size(payload_size) &&
                payload_size > (nla_total_size(payload_size) - max_size)) {
            payload_size -= (nla_total_size(payload_size) - max_size);
        }
        if (max_size < nla_total_size(payload_size)) {
            payload_size = 0;
        }
    }
    if (payload_size > 0) {
        if (payload_size < cb_data->payload_size) {
            amp_log_debug("Sending partial payload (%lu @ %lu)", payload_size, payload_offset);
        }
        payload_attr = nla_reserve(skb, AMP_NKE_ATTR_REC_PAYLOAD, payload_size);
        if (!payload_attr) {
            amp_log_err("nla_reserve(%lu of %lu) failed", payload_size, SKB_MAX_ALLOC);
            goto done;
        }
        payload_data = nla_data(payload_attr);
        if (!payload_data) {
            amp_log_err("nla_data(payload_attr) failed");
            goto done;
        }
        memcpy(payload_data, &cb_data->payload[payload_offset], payload_size);
        err = nla_put_u32(skb, AMP_NKE_ATTR_REC_PAYLOAD_SEQNUM, cb_data->payload_seqnum + payload_offset);
        if (err != 0) {
            amp_log_err("nla_put_u32(payload_seqnum) failed");
            goto done;
        }
    } else {
        /* no payload - do not set AMP_NKE_ATTR_REC_PAYLOAD or
           AMP_NKE_ATTR_REC_PAYLOAD_SEQNUM */
    }
    if (cb_data->cmd == AMP_NKE_CMD_REC_DETECT) {
        err = nla_put_u8(skb, AMP_NKE_ATTR_REC_REMOTE_CLASSIFICATION, cb_data->detection.remote_classification);
        if (err != 0) {
            amp_log_err("nla_put_u8(remote_classification) failed");
            goto done;
        }
        err = nla_put_string(skb, AMP_NKE_ATTR_REC_DETECTION_NAME, cb_data->detection.detection_name);
        if (err != 0) {
            amp_log_err("nla_put_string(detection_name) failed");
            goto done;
        }
    }
    (void)genlmsg_end(skb, genl_msg);

    mutex_lock(&_g_state.portid_mutex);
    mutex_locked = 1;
    if (_g_state.nl_portid != 0) {
        err = GENLMSG_UNICAST(&init_net, skb, _g_state.nl_portid);
        /* don't free skb after handing it off to genlmsg_unicast, even if
           the function returns an error */
        skb = NULL;
        /* genlmsg_unicast returns -ECONNREFUSED if there are no listeners, and
           -EAGAIN if the listener's buffer is full */
        /** @todo TODO implement flow control with the client? The client sees
                  ENOBUFS when the kernel sees EAGAIN */
        if (err != 0) {
            if (err == -ECONNREFUSED) {
                /* peer disconnected */
                amp_log_info("peer disconnected");
                _g_state.nl_portid = 0;
            } else if (err == -EAGAIN) {
                /* this could get noisy if a large number of messages are
                   dropped. limit the frequency of output. */
                uint32_t cur_uptime = (uint32_t)CUR_UPTIME();
                if (_g_state.last_drop_msg == cur_uptime) {
                    _g_state.num_dropped_msgs++;
                } else {
                    if (_g_state.num_dropped_msgs > 0) {
                        amp_log_info("dropped %u msgs", _g_state.num_dropped_msgs);
                        _g_state.num_dropped_msgs = 0;
                    }
                    _g_state.last_drop_msg = cur_uptime;
                    amp_log_info("dropped msg");
                }
            } else {
                amp_log_err("genlmsg_unicast failed: %d", err);
                goto done;
            }
        }
    }
    mutex_unlock(&_g_state.portid_mutex);
    mutex_locked = 0;

done:
    if (skb) {
        nlmsg_free(skb);
        skb = NULL;
    }
    if (mutex_locked) {
        mutex_unlock(&_g_state.portid_mutex);
        mutex_locked = 0;
    }

    return payload_size;
}

static inline void __msg_send_task(_send_rec_cb_t *cb_data)
{
    size_t payload_offset = 0;

    do {
        size_t payload_sent = _msg_send_offset(cb_data, payload_offset);
        if (payload_sent == 0) {
            break;
        }
        payload_offset += payload_sent;
    } while (cb_data->payload_size > payload_offset);

    if (cb_data->filename_buf) {
        kmem_cache_free(_g_state.proc_name_kmem_cache, cb_data->filename_buf);
        cb_data->filename_buf = NULL;
        cb_data->filename_ptr = NULL;
    }
    kfree(cb_data);
    cb_data = NULL;

    atomic_dec(&_g_state.num_rec_queued);
}

#ifdef INIT_WORK_USES_CONTAINER
static void _msg_send_task(struct work_struct *work)
{
    _send_rec_cb_t *cb_data = container_of(work, _send_rec_cb_t, work);
    __msg_send_task(cb_data);
}
#else
static void _msg_send_task(void *param)
{
    _send_rec_cb_t *cb_data = param;
    __msg_send_task(cb_data);
}
#endif

static inline void __proc_name_task(_send_rec_cb_t *cb_data)
{
    cb_data->filename_buf = kmem_cache_alloc(_g_state.proc_name_kmem_cache, GFP_KERNEL);
    if (!cb_data->filename_buf) {
        amp_log_err("kmem_cache_alloc failed");
    } else {
        cb_data->filename_ptr = _get_proc_path(cb_data->task, cb_data->filename_buf, PATH_MAX);
        if (cb_data->filename_ptr && IS_ERR(cb_data->filename_ptr)) {
            /* errors are logged by _get_proc_path */
            cb_data->filename_ptr = NULL;
            kmem_cache_free(_g_state.proc_name_kmem_cache, cb_data->filename_buf);
            cb_data->filename_buf = NULL;
        }
    }
    put_task_struct(cb_data->task);
    cb_data->task = NULL;

    /* submit to other queue */
#ifdef INIT_WORK_USES_CONTAINER
    INIT_WORK(&cb_data->work, _msg_send_task);
#else
    INIT_WORK(&cb_data->work, _msg_send_task, cb_data);
#endif
    (void)queue_work(_g_state.msg_send_wq, &cb_data->work);
}

#ifdef INIT_WORK_USES_CONTAINER
static void _proc_name_task(struct work_struct *work)
{
    _send_rec_cb_t *cb_data = container_of(work, _send_rec_cb_t, work);
    __proc_name_task(cb_data);
}
#else
static void _proc_name_task(void *param)
{
    _send_rec_cb_t *cb_data = param;
    __proc_name_task(cb_data);
}
#endif

static int _send_rec(uint8_t cmd,
                     amp_nke_sk_op_t sk_op,
                     struct task_struct *task,
                     const struct sockaddr_storage *local_addr,
                     const struct sockaddr_storage *remote_addr,
                     uint16_t proto,
                     uint64_t sk_id,
                     const struct msghdr *payload_msg,
                     size_t payload_size,
                     uint32_t payload_seqnum,
                     amp_op_detection_t *detection)
{
    int ret = 0;
    _send_rec_cb_t *cb_data = NULL;

    /* Use work queues to call _get_proc_path and genlmsg_unicast because
       these functions may sleep. */
    /** @todo FIXME Note that deferring _get_proc_path introduces a race
              condition - the process name may change by the time
              _msg_send_task is called. */

    atomic_inc(&_g_state.num_rec_queued);

    /* can't yield while in a jprobe handler; use GFP_ATOMIC */
    cb_data = kzalloc(sizeof(_send_rec_cb_t) + payload_size, GFP_ATOMIC);
    if (!cb_data) {
        amp_log_err("kzalloc(%lu + %lu = %lu) failed", sizeof(_send_rec_cb_t), payload_size, sizeof(_send_rec_cb_t) + payload_size);
        ret = -ENOMEM;
        goto done;
    }
    get_task_struct(task);
    cb_data->task = task;
    cb_data->pid = task_tgid_nr(task);
    cb_data->uid = TASK_UID(task);
    cb_data->cmd = cmd;
    cb_data->sk_op = sk_op;
    if (local_addr) {
        memcpy(&cb_data->local_addr, local_addr, sizeof(struct sockaddr_storage));
    }
    if (remote_addr) {
        memcpy(&cb_data->remote_addr, remote_addr, sizeof(struct sockaddr_storage));
    }
    cb_data->proto = proto;
    cb_data->sk_id = sk_id;
    cb_data->payload_size = payload_size;
    cb_data->payload_seqnum = payload_seqnum;
    if (payload_size > 0) {
#ifdef STRUCT_MSGHDR_HAS_IOV_ITER
        struct iov_iter iter;
        size_t n;
        iter = payload_msg->msg_iter;
        n = copy_from_iter(cb_data->payload, payload_size, &iter);
        if (n != payload_size) {
            /* May fail due to an invalid pointer passed from userland */
            amp_log_info("copy_from_iter(size=%lu) returned %lu", payload_size, n);
            ret = -EFAULT;
            goto done;
        }
#else
        int err;
        err = memcpy_fromiovecend(cb_data->payload, payload_msg->msg_iov, 0, payload_size);
        if (err != 0) {
            if (err == -EFAULT) {
                /* Invalid pointer passed from userland */
                amp_log_info("memcpy_fromiovecend(size=%lu) returned %d", payload_size, err);
            } else {
                amp_log_err("memcpy_fromiovecend(size=%lu) returned %d", payload_size, err);
            }
            ret = err;
            goto done;
        }
#endif
    }
    if (detection) {
        cb_data->detection = *detection;
    }

#ifdef INIT_WORK_USES_CONTAINER
    INIT_WORK(&cb_data->work, _proc_name_task);
#else
    INIT_WORK(&cb_data->work, _proc_name_task, cb_data);
#endif
    (void)queue_work(_g_state.proc_name_wq, &cb_data->work);
    cb_data = NULL;

done:
    if (cb_data) {
        put_task_struct(cb_data->task);
        cb_data->task = NULL;
        kfree(cb_data);
        cb_data = NULL;
    }
    if (ret != 0) {
        atomic_dec(&_g_state.num_rec_queued);
    }

    return ret;
}

typedef struct {
    amp_scw_release_fn_t func;
    struct work_struct work;
} _register_release_cb_t;

static inline void __register_release_task(_register_release_cb_t *cb_data)
{
    int err;
    amp_log_debug("register");
    err = amp_scw_register_release(cb_data->func);
    if (err) {
        amp_log_err("amp_scw_register_release failed: %d", err);
    }
    kmem_cache_free(_g_state.register_release_kmem_cache, cb_data);
    cb_data = NULL;
    amp_log_debug("done");
}

#ifdef INIT_WORK_USES_CONTAINER
static void _register_release_task(struct work_struct *work)
{
    _register_release_cb_t *cb_data = container_of(work, _register_release_cb_t, work);
    __register_release_task(cb_data);
}
#else
static void _register_release_task(void *param)
{
    _register_release_cb_t *cb_data = param;
    __register_release_task(cb_data);
}
#endif

static int _register_release(struct socket *sock)
{
    int ret = 0;
    _register_release_cb_t *cb_data;

    if (!sock->ops->release) {
        amp_log_info("sock->ops->release is NULL");
        ret = -EINVAL;
        goto done;
    }

    /* there is no race condition here - sock->ops->release being registered by
       another thread after this check is fine: */
    if (!amp_scw_is_registered(sock->ops->release)) {
        /* Run in a separate a thread because register_jprobe may sleep */
        /* XXX Since we can't wait while in a jprobe handler, we cannot ensure
           that the socket release probe is in place before exiting this probe
           handler. Therefore, some socket release calls may be missed.
           We mitigate this by pre-registering inet_stream_ops.release and
           inet_dgram_ops.release */
        amp_log_debug("register");

        /* can't yield while in a jprobe handler; use GFP_ATOMIC */
        cb_data = kmem_cache_alloc(_g_state.register_release_kmem_cache, GFP_ATOMIC);
        if (!cb_data) {
            amp_log_err("kmem_cache_alloc failed");
            ret = -ENOMEM;
            goto done;
        }

        cb_data->func = sock->ops->release;
#ifdef INIT_WORK_USES_CONTAINER
        INIT_WORK(&cb_data->work, _register_release_task);
#else
        INIT_WORK(&cb_data->work, _register_release_task, cb_data);
#endif
        (void)schedule_work(&cb_data->work);
        amp_log_debug("done");
    }

done:
    return ret;
}

#define PRINT_DATA_LEN 10
#define SOCK_STR_LEN 200

static void _recvmsg_cb(struct kiocb *iocb, struct socket *sock,
                        struct msghdr *msg, size_t size, int flags)
{
    unsigned char sock_proto;
    int sock_connected;
    /* these structures are copied to userland in _send_rec, so
       ensure any bytes we don't write to are set to 0: */
    struct sockaddr_storage sock_name = { 0 }, sock_peer_name = { 0 };
    int err;
    char sock_str[SOCK_STR_LEN];
    uint32_t send_rec_size;
    uint32_t send_rec_seqnum;
    int do_send_rec;
    uint64_t sk_id;
    bool detect;
    amp_op_detection_t detection;

    err = _getsockinfo(sock, &sock_name, &sock_peer_name, &sock_proto, &sock_connected, __func__);
    if (err != 0) {
        goto done;
    }
    if (!sock_connected) {
        /* msg->msg_name is not set yet at this point, so we have no way of
           knowing where the datagram came from */
        /** @todo FIXME */
        /* set sock_peer_name to an all-zero address */
        memset(&sock_peer_name, 0, sizeof(struct sockaddr_storage));
        sock_peer_name.ss_family = sock_name.ss_family;
    }

    /* register watch for release */
    err = _register_release(sock);
    if (err != 0) {
        amp_log_err("_register_release failed");
        goto done;
    }

    send_rec_size = (uint32_t)size;
    do_send_rec = amp_skactg_recvmsg(&_g_skactg, task_tgid_nr(current), sock->sk, &sock_name, &sock_peer_name, &sk_id, &send_rec_size, &send_rec_seqnum, &detect, &detection);
    if (do_send_rec < 0) {
        amp_log_err("amp_skactg_recvmsg returned %d", do_send_rec);
        goto done;
    }

    if (do_send_rec) {
        _printsockinfo(sock_str, sizeof(sock_str), (struct sockaddr *)&sock_name, (struct sockaddr *)&sock_peer_name, sock_proto);
        amp_log_debug("recvmsg: pid %d, len %lu, sock %p, sk %p: %s", task_tgid_nr(current), size, sock, sock->sk, sock_str);

        err = _send_rec(AMP_NKE_CMD_REC_SK_OP, AMP_NKE_SK_OP_RECV, current, &sock_name, &sock_peer_name, sock_proto, sk_id, (send_rec_size > 0) ? msg : NULL, send_rec_size, send_rec_seqnum, NULL);
        if (err != 0) {
            /* errors are logged by _send_rec */
            goto done;
        }
    }

    if (detect) {
        err = _send_rec(AMP_NKE_CMD_REC_DETECT, AMP_NKE_SK_OP_RECV, current, &sock_name, &sock_peer_name, sock_proto, sk_id, NULL, 0, 0, &detection);
        if (err != 0) {
            /* errors are logged by _send_rec */
        }
    }

done:
    return;
}

static void _sendmsg_cb(struct kiocb *iocb,
                        struct socket *sock,
                        struct msghdr *msg,
                        size_t size)
{
    int sock_connected;
    unsigned char sock_proto;
    /* these structures are copied to userland in _send_rec, so
       ensure any bytes we don't write to are set to 0: */
    struct sockaddr_storage sock_name = { 0 }, sock_peer_name = { 0 };
    int err;
    char sock_str[SOCK_STR_LEN];
    char data_str[PRINT_DATA_LEN+1];
    uint32_t send_rec_size;
    uint32_t send_rec_seqnum;
    int do_send_rec;
    uint64_t sk_id;
    bool detect;
    amp_op_detection_t detection;

    err = _getsockinfo(sock, &sock_name, &sock_peer_name, &sock_proto, &sock_connected, __func__);
    if (err != 0) {
        goto done;
    }
    if ((sock_proto == IPPROTO_UDP) ||
            (sock_proto == IPPROTO_TCP && !sock_connected)) {
        if (!msg->msg_name) {
            /* msg->msg_name == NULL is expected for TCP, and
               sock_connected == 0 is expected when the destination port is 0
               (getpeername does not work; see
               http://daniel.haxx.se/blog/2014/10/25/pretending-port-zero-is-a-normal-one/).
               in this case, use a zeroed-out sock_peer_name */
            if (sock->sk->sk_protocol == IPPROTO_TCP) {
                amp_log_debug("!sock_connected && !msg->msg_name");
                sock_peer_name.ss_family = 0;
            } else if (!sock_connected) {
                amp_log_info("msg->msg_name is NULL");
                goto done;
            }
        } else {
            if (msg->msg_namelen < sizeof(struct sockaddr) ||
                    msg->msg_namelen > sizeof(struct sockaddr_storage)) {
                amp_log_info("msg->msg_namelen == %d", msg->msg_namelen);
                goto done;
            }
            memcpy(&sock_peer_name, msg->msg_name, msg->msg_namelen);
        }
    }

    /* register watch for release */
    err = _register_release(sock);
    if (err != 0) {
        amp_log_err("_register_release failed");
        goto done;
    }

    send_rec_size = (uint32_t)size;
    do_send_rec = amp_skactg_sendmsg(&_g_skactg, task_tgid_nr(current), sock->sk, &sock_name, &sock_peer_name, &sk_id, &send_rec_size, &send_rec_seqnum, &detect, &detection);
    if (do_send_rec < 0) {
        amp_log_err("amp_skactg_sendmsg returned %d", do_send_rec);
        goto done;
    }

    if (do_send_rec) {
        _printsockinfo(sock_str, sizeof(sock_str), (struct sockaddr *)&sock_name, (struct sockaddr *)&sock_peer_name, sock_proto);
        _iovec_to_str(msg, send_rec_size, data_str, sizeof(data_str));
        amp_log_debug("sendmsg: pid %d, data [%s], len %lu, sock %p, sk %p: %s", task_tgid_nr(current), data_str, size, sock, sock->sk, sock_str);

        err = _send_rec(AMP_NKE_CMD_REC_SK_OP, AMP_NKE_SK_OP_SEND, current, &sock_name, &sock_peer_name, sock_proto, sk_id, (send_rec_size > 0) ? msg : NULL, send_rec_size, send_rec_seqnum, NULL);
        if (err != 0) {
            /* errors are logged by _send_rec */
            goto done;
        }
    }

    if (detect) {
        err = _send_rec(AMP_NKE_CMD_REC_DETECT, AMP_NKE_SK_OP_SEND, current, &sock_name, &sock_peer_name, sock_proto, sk_id, NULL, 0, 0, &detection);
        if (err != 0) {
            /* errors are logged by _send_rec */
        }
    }

done:
    return;
}

static void _connect_cb(struct socket *sock,
                        struct sockaddr * uaddr,
                        int addr_len, int flags)
{
    int sock_connected;
    unsigned char sock_proto;
    /* these structures are copied to userland in _send_rec, so
       ensure any bytes we don't write to are set to 0: */
    struct sockaddr_storage sock_name = { 0 }, sock_peer_name = { 0 };
    int err;
    char sock_str[SOCK_STR_LEN];
    int do_send_rec;
    uint64_t sk_id;
    bool detect;
    amp_op_detection_t detection;

    err = _getsockinfo(sock, &sock_name, &sock_peer_name, &sock_proto, &sock_connected, __func__);
    if (err != 0) {
        goto done;
    }

    if (!uaddr) {
        amp_log_info("uaddr is NULL");
        goto done;
    }
    if (addr_len < sizeof(struct sockaddr) ||
            addr_len > sizeof(struct sockaddr_storage)) {
        amp_log_info("addr_len == %d", addr_len);
        goto done;
    }
    memcpy(&sock_peer_name, uaddr, addr_len);

    /* register watch for release */
    err = _register_release(sock);
    if (err != 0) {
        amp_log_err("_register_release failed");
        goto done;
    }

    do_send_rec = amp_skactg_connect(&_g_skactg, task_tgid_nr(current), sock->sk, &sock_name, &sock_peer_name, &sk_id, &detect, &detection);
    if (do_send_rec < 0) {
        amp_log_err("amp_skactg_connect returned %d", do_send_rec);
        goto done;
    }

    if (do_send_rec) {
        _printsockinfo(sock_str, sizeof(sock_str), (struct sockaddr *)&sock_name, (struct sockaddr *)&sock_peer_name, sock_proto);
        amp_log_debug("connect: pid %d, sock %p, sk %p: %s", task_tgid_nr(current), sock, sock->sk, sock_str);

        err = _send_rec(AMP_NKE_CMD_REC_SK_OP, AMP_NKE_SK_OP_CONNECT, current, &sock_name, &sock_peer_name, sock_proto, sk_id, NULL, 0, 0, NULL);
        if (err != 0) {
            /* errors are logged by _send_rec */
            goto done;
        }
    }

    if (detect) {
        err = _send_rec(AMP_NKE_CMD_REC_DETECT, AMP_NKE_SK_OP_CONNECT, current, &sock_name, &sock_peer_name, sock_proto, sk_id, NULL, 0, 0, &detection);
        if (err != 0) {
            /* errors are logged by _send_rec */
        }
    }

done:
    return;
}

static void _accept_cb(struct socket *sock,
                       struct socket *newsock, int flags)
{
    int err;

    if (!sock) {
        amp_log_info("sock is NULL");
        goto done;
    }
    if (!sock->sk) {
        amp_log_info("sock->sk is NULL");
        goto done;
    }

    /* save a pointer to the ops table for this sock. this will be used by the post_accept cb. */
    /* ops tables are protocol-specific but not socket-specific. */
    if (sock->sk->sk_family == PF_INET && sock->sk->sk_protocol == IPPROTO_TCP) {
        _g_tcpv4_ops = sock->ops;
    } else if (sock->sk->sk_family == PF_INET && sock->sk->sk_protocol == IPPROTO_UDP) {
        _g_udpv4_ops = sock->ops;
    } else if (sock->sk->sk_family == PF_INET6 && sock->sk->sk_protocol == IPPROTO_TCP) {
        _g_tcpv6_ops = sock->ops;
    } else if (sock->sk->sk_family == PF_INET6 && sock->sk->sk_protocol == IPPROTO_UDP) {
        _g_udpv6_ops = sock->ops;
    } else {
        /* socket is not TCPv4, UDPv4, TCPv6 or UDPv6 */
        goto done;
    }

    /* register watch for release */
    err = _register_release(sock);
    if (err != 0) {
        amp_log_err("_register_release failed");
        goto done;
    }

    amp_log_debug("accept: pid %d, sock %p, sock->sk %p, newsock %p, newsock->sk %p", task_tgid_nr(current), sock, sock->sk, newsock, newsock ? newsock->sk : NULL);

done:
    return;
}

static void _release_cb(struct socket *sock)
{
    int sock_connected;
    unsigned char sock_proto;
    struct sockaddr_storage sock_name, sock_peer_name;
    int err;
    char sock_str[SOCK_STR_LEN];
    int do_send_rec;
    uint64_t sk_id;

    err = _getsockinfo(sock, &sock_name, &sock_peer_name, &sock_proto, &sock_connected, __func__);
    if (err != 0) {
        goto done;
    }
    if (sock_proto == IPPROTO_UDP) {
        /* pretend the socket is not connected - it may have never contacted
         * the remote address it is connected to, and could make for misleading
         * records. */
        sock_connected = 0;
    }

    do_send_rec = amp_skactg_release_sk(&_g_skactg, sock->sk, &sk_id);
    if (do_send_rec < 0) {
        amp_log_err("amp_skactg_release_sk returned %d", do_send_rec);
        goto done;
    }

    if (do_send_rec) {
        _printsockinfo(sock_str, sizeof(sock_str), (struct sockaddr *)&sock_name, sock_connected ? (struct sockaddr *)&sock_peer_name : NULL, sock_proto);
        amp_log_debug("release: pid %d, sock %p, sk %p: %s", task_tgid_nr(current), sock, sock->sk, sock_str);

        err = _send_rec(AMP_NKE_CMD_REC_SK_OP, AMP_NKE_SK_OP_RELEASE, current, &sock_name, sock_connected ? &sock_peer_name : NULL, sock_proto, sk_id, NULL, 0, 0, NULL);
        if (err != 0) {
            /* errors are logged by _send_rec */
            goto done;
        }
    }

done:
    return;
}

static void _post_accept_cb(struct sock *sk)
{
    int sock_connected;
    unsigned char sock_proto;
    /* these structures are copied to userland in _send_rec, so
       ensure any bytes we don't write to are set to 0: */
    struct sockaddr_storage sock_name = { 0 }, sock_peer_name = { 0 };
    int err;
    char sock_str[SOCK_STR_LEN];
    struct socket fake_sock = { 0 };
    const struct proto_ops *ops;
    int do_send_rec;
    uint64_t sk_id;
    bool detect;
    amp_op_detection_t detection;

    if (!sk) {
        /* no connection was made */
        amp_log_debug("sk is NULL");
        goto done;
    }
    if (sk->sk_family == PF_INET && sk->sk_protocol == IPPROTO_TCP) {
        ops = _g_tcpv4_ops;
    } else if (sk->sk_family == PF_INET && sk->sk_protocol == IPPROTO_UDP) {
        ops = _g_udpv4_ops;
    } else if (sk->sk_family == PF_INET6 && sk->sk_protocol == IPPROTO_TCP) {
        ops = _g_tcpv6_ops;
    } else if (sk->sk_family == PF_INET6 && sk->sk_protocol == IPPROTO_UDP) {
        ops = _g_udpv6_ops;
    } else {
        /* socket is not TCPv4, UDPv4, TCPv6 or UDPv6 */
        goto done;
    }

    /* make a fake struct sock */
    /* NOTE: it is probably not safe to call all library functions on this sock, but ops->getname does work. */
    fake_sock.sk = sk;
    fake_sock.ops = ops;
    err = _getsockinfo(&fake_sock, &sock_name, &sock_peer_name, &sock_proto, &sock_connected, __func__);
    if (err != 0) {
        goto done;
    }
    if (!sock_connected) {
        amp_log_info("not connected - peer name not set");
        /* peer name will not be set */
        goto done;
    }

    do_send_rec = amp_skactg_accept(&_g_skactg, task_tgid_nr(current), sk, &sock_name, &sock_peer_name, &sk_id, &detect, &detection);
    if (do_send_rec < 0) {
        amp_log_err("amp_skactg_accept returned %d", do_send_rec);
        goto done;
    }

    if (do_send_rec) {
        _printsockinfo(sock_str, sizeof(sock_str), (struct sockaddr *)&sock_name, (struct sockaddr *)&sock_peer_name, sock_proto);
        amp_log_debug("post_accept: pid %d, sk %p: %s", task_tgid_nr(current), sk, sock_str);

        err = _send_rec(AMP_NKE_CMD_REC_SK_OP, AMP_NKE_SK_OP_ACCEPT, current, &sock_name, &sock_peer_name, sock_proto, sk_id, NULL, 0, 0, NULL);
        if (err != 0) {
            /* errors are logged by _send_rec */
            goto done;
        }
    }

    if (detect) {
        err = _send_rec(AMP_NKE_CMD_REC_DETECT, AMP_NKE_SK_OP_ACCEPT, current, &sock_name, &sock_peer_name, sock_proto, sk_id, NULL, 0, 0, &detection);
        if (err != 0) {
            /* errors are logged by _send_rec */
        }
    }

done:
    return;
}

/* the current peer is the one that sent the last message */
static int _update_portid(struct genl_info *info)
{
    int ret = 0;

    if (info->genlhdr->version != AMP_NKE_GENL_VERSION) {
        amp_log_err("info->genlhdr->version %d != %d", info->genlhdr->version, AMP_NKE_GENL_VERSION);
        ret = -EINVAL;
        goto done;
    }

    mutex_lock(&_g_state.portid_mutex);
#ifdef NETLINK_USES_PORTID
    _g_state.nl_portid = info->snd_portid;
#else
    /* old nomenclature: pid */
    _g_state.nl_portid = info->snd_pid;
#endif
    mutex_unlock(&_g_state.portid_mutex);

done:
    return ret;
}

static void _msg_send_hello_rec(void)
{
    int err;
    int mutex_locked = 0;
    struct sk_buff *skb = NULL;
    void *genl_msg;

    /* use at least 8 kB so we can fit the payload and filename */
    skb = alloc_skb(SKB_MAX_ALLOC, GFP_KERNEL);
    if (!skb) {
        amp_log_err("alloc_skb failed");
        goto done;
    }

    genl_msg = GENLMSG_PUT(skb, 0 /* portid */, 0, &_g_genl_family, 0 /* flags */, AMP_NKE_CMD_REC_HELLO);
    if (genl_msg == NULL) {
        amp_log_err("genlmsg_put failed");
        goto done;
    }

    (void)genlmsg_end(skb, genl_msg);

    mutex_lock(&_g_state.portid_mutex);
    mutex_locked = 1;
    if (_g_state.nl_portid != 0) {
        err = GENLMSG_UNICAST(&init_net, skb, _g_state.nl_portid);
        /* don't free skb after handing it off to genlmsg_unicast, even if
           the function returns an error */
        skb = NULL;
        /* genlmsg_unicast returns -ECONNREFUSED if there are no listeners, and
           -EAGAIN if the listener's buffer is full */
        /** @todo TODO implement flow control with the client? The client sees
                  ENOBUFS when the kernel sees EAGAIN */
        if (err != 0) {
            if (err == -ECONNREFUSED) {
                /* peer disconnected */
                amp_log_info("peer disconnected");
                _g_state.nl_portid = 0;
            } else if (err == -EAGAIN) {
                amp_log_info("dropped msg");
            } else {
                amp_log_err("genlmsg_unicast failed: %d", err);
                goto done;
            }
        }
    }
    mutex_unlock(&_g_state.portid_mutex);
    mutex_locked = 0;

done:
    if (skb) {
        nlmsg_free(skb);
        skb = NULL;
    }
    if (mutex_locked) {
        mutex_unlock(&_g_state.portid_mutex);
        mutex_locked = 0;
    }

    atomic_dec(&_g_state.num_rec_queued);

    return;
}

static int _hello(struct sk_buff *skb, struct genl_info *info)
{
    (void)_update_portid(info);
    _msg_send_hello_rec();
    return 0;
}

static int _set_monitoring(struct sk_buff *skb, struct genl_info *info)
{
    uint32_t conn_limit, time_limit, pid;

    if (_update_portid(info) != 0) {
        goto done;
    }
    if (!info->attrs[AMP_NKE_ATTR_PID]) {
        amp_log_err("missing AMP_NKE_ATTR_PID");
        goto done;
    }
    pid = nla_get_u32(info->attrs[AMP_NKE_ATTR_PID]);
    if (!info->attrs[AMP_NKE_ATTR_CONN_LIMIT]) {
        amp_log_err("missing AMP_NKE_ATTR_CONN_LIMIT");
        goto done;
    }
    conn_limit = nla_get_u32(info->attrs[AMP_NKE_ATTR_CONN_LIMIT]);
    if (!info->attrs[AMP_NKE_ATTR_TIME_LIMIT]) {
        amp_log_err("missing AMP_NKE_ATTR_TIME_LIMIT");
        goto done;
    }
    time_limit = nla_get_u32(info->attrs[AMP_NKE_ATTR_TIME_LIMIT]);
    amp_log_debug("(pid %u, conn_limit %u, time_limit %u)", pid, conn_limit, time_limit);
    amp_skactg_update_proc_limits(&_g_skactg, pid, conn_limit, time_limit);

done:
    return 0;
}

static int _forget_monitoring(struct sk_buff *skb, struct genl_info *info)
{
    uint32_t pid;

    if (_update_portid(info) != 0) {
        goto done;
    }
    if (!info->attrs[AMP_NKE_ATTR_PID]) {
        amp_log_err("missing AMP_NKE_ATTR_PID");
        goto done;
    }
    pid = nla_get_u32(info->attrs[AMP_NKE_ATTR_PID]);
    amp_log_debug("(pid %u)", pid);
    amp_skactg_forget_proc(&_g_skactg, pid);

done:
    return 0;
}

static int _set_opts(struct sk_buff *skb, struct genl_info *info)
{
    uint32_t send_limit;
    bool ignore_ipv6, ignore_loopback;
    uint8_t log_level;
    uint32_t cache_max_size, cache_ttl_clean, cache_ttl_malicious;

    if (_update_portid(info) != 0) {
        goto done;
    }
    if (!info->attrs[AMP_NKE_ATTR_SET_SEND_LIMIT]) {
        amp_log_err("missing AMP_NKE_ATTR_SET_SEND_LIMIT");
        goto done;
    }
    send_limit = nla_get_u32(info->attrs[AMP_NKE_ATTR_SET_SEND_LIMIT]);
    ignore_ipv6 = nla_get_flag(info->attrs[AMP_NKE_ATTR_IGNORE_IPV6]);
    ignore_loopback = nla_get_flag(info->attrs[AMP_NKE_ATTR_IGNORE_LOOPBACK]);
    if (!info->attrs[AMP_NKE_ATTR_LOG_LEVEL]) {
        amp_log_err("missing AMP_NKE_ATTR_LOG_LEVEL");
        goto done;
    }
    log_level = nla_get_u8(info->attrs[AMP_NKE_ATTR_LOG_LEVEL]);
    amp_log_set_max_level(log_level);
    if (!info->attrs[AMP_NKE_ATTR_CACHE_MAX_SIZE]) {
        amp_log_err("missing AMP_NKE_ATTR_CACHE_MAX_SIZE");
        goto done;
    }
    cache_max_size = nla_get_u32(info->attrs[AMP_NKE_ATTR_CACHE_MAX_SIZE]);
    if (!info->attrs[AMP_NKE_ATTR_CACHE_TTL_CLEAN]) {
        amp_log_err("missing AMP_NKE_ATTR_CACHE_TTL_CLEAN");
        goto done;
    }
    cache_ttl_clean = nla_get_u32(info->attrs[AMP_NKE_ATTR_CACHE_TTL_CLEAN]);
    if (!info->attrs[AMP_NKE_ATTR_CACHE_TTL_MALICIOUS]) {
        amp_log_err("missing AMP_NKE_ATTR_CACHE_TTL_MALICIOUS");
        goto done;
    }
    cache_ttl_malicious = nla_get_u32(info->attrs[AMP_NKE_ATTR_CACHE_TTL_MALICIOUS]);
    amp_log_info("AMP_NKE_ATTR_SET_SEND_LIMIT = %u, "
                 "AMP_NKE_ATTR_IGNORE_IPV6 = %d, "
                 "AMP_NKE_ATTR_IGNORE_LOOPBACK = %d, "
                 "AMP_NKE_ATTR_LOG_LEVEL = %u, "
                 "AMP_NKE_ATTR_CACHE_MAX_SIZE = %u, "
                 "AMP_NKE_ATTR_CACHE_TTL_CLEAN = %u, "
                 "AMP_NKE_ATTR_CACHE_TTL_MALICIOUS = %u",
            send_limit, ignore_ipv6, ignore_loopback, log_level,
            cache_max_size, cache_ttl_clean, cache_ttl_malicious);
    amp_skactg_set_opts(&_g_skactg, send_limit, ignore_ipv6, ignore_loopback);
    (void)amp_addrcache_set_opts(&_g_addrcache, cache_max_size, cache_ttl_clean, cache_ttl_malicious);

done:
    return 0;
}

static int _action(struct sk_buff *skb, struct genl_info *info)
{
    amp_op_detection_t detection = { 0 };
    struct sockaddr_storage *remote_addr;
    bool cache_remote;
    bool detect;
    char addr_str[INET6_ADDRSTRLEN];
    int err;

    if (_update_portid(info) != 0) {
        goto done;
    }

    if (!info->attrs[AMP_NKE_ATTR_FLOW_REMOTE_SOCKADDR]) {
        amp_log_err("missing AMP_NKE_ATTR_FLOW_REMOTE_SOCKADDR");
        goto done;
    }
    if (nla_len(info->attrs[AMP_NKE_ATTR_FLOW_REMOTE_SOCKADDR]) != sizeof(struct sockaddr_storage)) {
        /** @todo TODO find out if the policy does this check for us */
        amp_log_err("ignoring AMP_NKE_ATTR_FLOW_REMOTE_SOCKADDR len = %d", nla_len(info->attrs[AMP_NKE_ATTR_FLOW_REMOTE_SOCKADDR]));
        goto done;
    }
    remote_addr = nla_data(info->attrs[AMP_NKE_ATTR_FLOW_REMOTE_SOCKADDR]);
    if (info->attrs[AMP_NKE_ATTR_REMOTE_CLASSIFICATION]) {
        detection.remote_classification = nla_get_u8(info->attrs[AMP_NKE_ATTR_REMOTE_CLASSIFICATION]);
    }
    cache_remote = nla_get_flag(info->attrs[AMP_NKE_ATTR_CACHE_REMOTE]);
    if (info->attrs[AMP_NKE_ATTR_DETECTION_NAME]) {
        (void)nla_strlcpy(detection.detection_name, info->attrs[AMP_NKE_ATTR_DETECTION_NAME], sizeof(detection.detection_name));
    }

    amp_log_debug("AMP_NKE_ATTR_FLOW_REMOTE_SOCKADDR = %s, "
                  "AMP_NKE_ATTR_REMOTE_CLASSIFICATION = %d, "
                  "AMP_NKE_ATTR_CACHE_REMOTE = %d, "
                  "AMP_NKE_ATTR_DETECTION_NAME = %s",
            amp_addr_to_str((struct sockaddr *)remote_addr, addr_str,
            sizeof(addr_str)), detection.remote_classification, cache_remote,
            detection.detection_name);

    if (cache_remote && (info->genlhdr->cmd == AMP_NKE_CMD_ACTION_ALLOW ||
            info->genlhdr->cmd == AMP_NKE_CMD_ACTION_DETECT)) {
        detect = (info->genlhdr->cmd == AMP_NKE_CMD_ACTION_DETECT);
        err = amp_addrcache_add(&_g_addrcache, (struct sockaddr *)remote_addr, detect, &detection);
        if (err) {
            amp_log_err("amp_addrcache_add failed");
        }
    }

done:
    return 0;
}

static int _reset_monitoring(struct sk_buff *skb, struct genl_info *info)
{
    if (_update_portid(info) != 0) {
        goto done;
    }
    amp_log_info("");
    amp_skactg_reset_monitoring(&_g_skactg);
    amp_addrcache_empty(&_g_addrcache);

done:
    return 0;
}

static int _dump_accounting(struct sk_buff *skb, struct genl_info *info)
{
    if (_update_portid(info) != 0) {
        goto done;
    }
    amp_log_info("");
    amp_skactg_dump(&_g_skactg);

done:
    return 0;
}

int init_module(void)
{
    int err;
    int ret = 0;

    amp_scw_cb_t cb = {
        .connect_cb = _connect_cb,
        .accept_cb = _accept_cb,
        .recvmsg_cb = _recvmsg_cb,
        .sendmsg_cb = _sendmsg_cb,
        .release_cb = _release_cb,
        .post_accept_cb = _post_accept_cb
    };

    amp_log_info("starting ampnetworkflow");

    mutex_init(&_g_state.portid_mutex);

    _g_state.proc_name_kmem_cache = KMEM_CACHE_CREATE("csco_amp_proc_name",
        PATH_MAX, 0 /* align */, 0 /* flags */, NULL /* ctor */);
    if (!_g_state.proc_name_kmem_cache) {
        amp_log_err("kmem_cache_create(proc_name_kmem_cache) failed");
        ret = -ENOMEM;
        goto wq_destroy;
    }
    _g_state.register_release_kmem_cache = KMEM_CACHE_CREATE("csco_amp_reg_rel",
        sizeof(_register_release_cb_t), 0 /* align */, 0 /* flags */,
        NULL /* ctor */);
    if (!_g_state.register_release_kmem_cache) {
        amp_log_err("kmem_cache_create(register_release_kmem_cache) failed");
        ret = -ENOMEM;
        goto wq_destroy;
    }

    /* initialize work queues */
    _g_state.msg_send_wq = create_singlethread_workqueue("csco_amp_msg_wq");
    if (!_g_state.msg_send_wq) {
        amp_log_err("create_singlethread_workqueue(msg_send_wq) failed");
        ret = -ENOMEM;
        goto wq_destroy;
    }
    _g_state.proc_name_wq = create_singlethread_workqueue("csco_amp_prc_wq");
    if (!_g_state.proc_name_wq) {
        amp_log_err("create_singlethread_workqueue(proc_name_wq) failed");
        ret = -ENOMEM;
        goto wq_destroy;
    }

    err = amp_addrcache_init(&_g_addrcache, UINT32_MAX, UINT32_MAX, UINT32_MAX);
    if (err != 0) {
        ret = err;
        amp_log_err("amp_addrcache_init failed");
        goto wq_destroy;
    }

    err = amp_skactg_init(&_g_skactg, &_g_addrcache, SKACTG_MAX_PROC_COUNT, SKACTG_MAX_SK_COUNT);
    if (err != 0) {
        ret = err;
        amp_log_err("amp_skactg_init failed");
        goto deinit_addrcache;
    }

    /* register generic netlink family */
    err = GENL_REGISTER_FAMILY_WITH_OPS(&_g_genl_family,
                                        _g_genl_ops);
    if (err != 0) {
        amp_log_err("GENL_REGISTER_FAMILY_WITH_OPS failed");
        ret = err;
        goto deinit_skactg;
    }
    amp_log_info("_g_genl_family.id %u", _g_genl_family.id);

    /* sockcallwatch registrations - do these last */
    err = amp_scw_init(&cb);
    if (err != 0) {
        ret = err;
        amp_log_err("amp_scw_init failed");
        goto unreg;
    }

    /* register handler functions from inet_stream_ops and inet_dgram_ops.
       this should(!) cover both IPv4 and IPv6 because inet6_stream_ops
       and inet6_dgram_ops use the same handler functions for these
       operations */
    err = amp_scw_register_sendmsg(inet_stream_ops.sendmsg);
    if (err != 0) {
        amp_log_err("amp_scw_register_sendmsg(inet_stream_ops.sendmsg (%s NULL)) failed: %d", inet_stream_ops.sendmsg ? "!=" : "==", err);
        ret = err;
        /* do not goto deinit_scw and return right away - continue and try to
           register more probes so the logs contain more information */
    }
    err = amp_scw_register_recvmsg(inet_stream_ops.recvmsg);
    if (err != 0) {
        amp_log_err("amp_scw_register_recvmsg(inet_stream_ops.recvmsg (%s NULL)) failed: %d", inet_stream_ops.recvmsg ? "!=" : "==", err);
        ret = err;
        /* do not goto deinit_scw and return right away - continue and try to
           register more probes so the logs contain more information */
    }
    err = amp_scw_register_connect(inet_stream_ops.connect);
    if (err != 0) {
        amp_log_err("amp_scw_register_connect(inet_stream_ops.connect (%s NULL)) failed: %d", inet_stream_ops.connect ? "!=" : "==", err);
        ret = err;
        /* do not goto deinit_scw and return right away - continue and try to
           register more probes so the logs contain more information */
    }
    err = amp_scw_register_accept(inet_stream_ops.accept);
    if (err != 0) {
        amp_log_err("amp_scw_register_accept(inet_stream_ops.accept (%s NULL)) failed: %d", inet_stream_ops.accept ? "!=" : "==", err);
        ret = err;
        /* do not goto deinit_scw and return right away - continue and try to
           register more probes so the logs contain more information */
    }
    err = amp_scw_register_sendmsg(inet_dgram_ops.sendmsg);
    if (err != 0) {
        amp_log_err("amp_scw_register_sendmsg(inet_dgram_ops.sendmsg (%s NULL)) failed: %d", inet_dgram_ops.sendmsg ? "!=" : "==", err);
        ret = err;
        /* do not goto deinit_scw and return right away - continue and try to
           register more probes so the logs contain more information */
    }
    err = amp_scw_register_recvmsg(inet_dgram_ops.recvmsg);
    if (err != 0) {
        amp_log_err("amp_scw_register_recvmsg(inet_dgram_ops.recvmsg (%s NULL)) failed: %d", inet_dgram_ops.recvmsg ? "!=" : "==", err);
        ret = err;
        /* do not goto deinit_scw and return right away - continue and try to
           register more probes so the logs contain more information */
    }

    /* register accept handler from tcp_prot.
        this should(!) cover both IPv4 and IPv6 because tcpv6_prot
        uses the same handler function */
    err = amp_scw_register_post_accept(tcp_prot.accept);
    if (err != 0) {
        amp_log_err("amp_scw_register_post_accept(tcp_prot.accept (%s NULL)) failed: %d", tcp_prot.accept ? "!=" : "==", err);
        ret = err;
        /* do not goto deinit_scw and return right away - continue and try to
           register more probes so the logs contain more information */
    }

    /* register release handler from inet_stream_ops and inet_dgram_ops. this
       will only cover IPv4 sockets */
    err = amp_scw_register_release(inet_stream_ops.release);
    if (err != 0) {
        amp_log_err("amp_scw_register_release(inet_stream_ops.release (%s NULL)) failed: %d", inet_stream_ops.release ? "!=" : "==", err);
        ret = err;
        /* do not goto deinit_scw and return right away - continue and try to
           register more probes so the logs contain more information */
    }
    err = amp_scw_register_release(inet_dgram_ops.release);
    if (err != 0) {
        amp_log_err("amp_scw_register_release(inet_dgram_ops.release (%s NULL)) failed: %d", inet_dgram_ops.release ? "!=" : "==", err);
        ret = err;
    }

    if (ret != 0) {
        goto deinit_scw;
    }

    /* success */
    goto done;

deinit_scw:
    err = amp_scw_deinit();
    if (err != 0) {
        amp_log_err("amp_scw_deinit failed");
    }

unreg:
    /* unregister generic netlink family */
    err = GENL_UNREGISTER_FAMILY_WITH_OPS(&_g_genl_family, _g_genl_ops);
    if (err != 0) {
        amp_log_err("GENL_UNREGISTER_FAMILY_WITH_OPS failed");
    }

deinit_skactg:
    amp_skactg_deinit(&_g_skactg);

deinit_addrcache:
    amp_addrcache_deinit(&_g_addrcache);

wq_destroy:
    /* must flush the proc_name workqueue before the msg_send workqueue because
       _proc_name_task submits to the msg_send workqueue */
    if (_g_state.proc_name_wq) {
        flush_workqueue(_g_state.proc_name_wq);
        destroy_workqueue(_g_state.proc_name_wq);
        _g_state.proc_name_wq = NULL;
    }
    if (_g_state.msg_send_wq) {
        flush_workqueue(_g_state.msg_send_wq);
        destroy_workqueue(_g_state.msg_send_wq);
        _g_state.msg_send_wq = NULL;
    }
    if (atomic_add_return(0, &_g_state.num_rec_queued) != 0) {
        amp_log_err("num_rec_queued != 0");
    }
    if (_g_state.register_release_kmem_cache) {
        kmem_cache_destroy(_g_state.register_release_kmem_cache);
        _g_state.register_release_kmem_cache = NULL;
    }
    if (_g_state.proc_name_kmem_cache) {
        kmem_cache_destroy(_g_state.proc_name_kmem_cache);
        _g_state.proc_name_kmem_cache = NULL;
    }

done:
    return ret;
}

void cleanup_module(void)
{
    int err;

    err = amp_scw_deinit();
    if (err != 0) {
        amp_log_err("amp_scw_deinit failed");
    }

    /* unregister generic netlink family */
    err = GENL_UNREGISTER_FAMILY_WITH_OPS(&_g_genl_family, _g_genl_ops);
    if (err != 0) {
        amp_log_err("GENL_UNREGISTER_FAMILY_WITH_OPS failed");
    }

    amp_skactg_deinit(&_g_skactg);

    amp_addrcache_deinit(&_g_addrcache);

    /* must flush the proc_name workqueue before the msg_send workqueue because
       _proc_name_task submits to the msg_send workqueue */
    flush_workqueue(_g_state.proc_name_wq);
    destroy_workqueue(_g_state.proc_name_wq);
    _g_state.proc_name_wq = NULL;
    flush_workqueue(_g_state.msg_send_wq);
    destroy_workqueue(_g_state.msg_send_wq);
    _g_state.msg_send_wq = NULL;
    if (atomic_add_return(0, &_g_state.num_rec_queued) != 0) {
        amp_log_err("num_rec_queued != 0");
    }
    kmem_cache_destroy(_g_state.register_release_kmem_cache);
    _g_state.register_release_kmem_cache = NULL;
    kmem_cache_destroy(_g_state.proc_name_kmem_cache);
    _g_state.proc_name_kmem_cache = NULL;

    amp_log_info("stopping ampnetworkflow");
}

