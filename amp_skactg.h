/**
 @brief AMP Device Flow Control
        Socket Accounting
        Copyright 2015-2018 Cisco Systems
        GNU Public License
 @author Craig Davison <crdaviso@cisco.com>
 @date 2015 Feb 27
*/

#ifndef AMP_SKACTG_H
#define AMP_SKACTG_H

#include <linux/rbtree.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <net/sock.h>
#include "amp_addrcache.h"

typedef struct {
    amp_addrcache_t *addrcache;
    uint32_t send_limit;
    bool ignore_ipv6;
    bool ignore_loopback;
    spinlock_t lock;
    struct rb_root sk_tree;
    struct rb_root proc_tree;
    uint32_t proc_count;
    uint32_t max_proc_count;
    uint32_t sk_count;
    uint32_t max_sk_count;
    uint64_t cur_sk_id;

    uint32_t last_proc_drop_msg;
    uint32_t dropped_procs;

    /** linked list head */
    struct amp_proc *newest_amp_proc;
    /** linked list tail */
    struct amp_proc *oldest_amp_proc;
    /** linked list head */
    struct amp_sk *newest_amp_sk;
    /** linked list tail */
    struct amp_sk *oldest_amp_sk;
} amp_skactg_t;

/**
 * @brief return whether we should monitor this sendmsg and relay it to
 *        userland.
 *
 * the caller should relay if:
 * - the socket is already being monitored, or the socket is being newly
 *   monitored and the process has not exceeded its socket monitoring or time
 *   limits, AND:
 *   - the socket is TCP, we are the client and we are within the sock send
 *     limit, OR
 *   - the socket is UDP and the sockaddr does not match the last sockaddr
 *     used in a sendmsg or recvmsg. in this case, *num_bytes will be set to 0.
 *
 * @param[in] handle - socket accounting handle
 * @param[in] tgid - the thread group ID (process)
 * @param[in] sk - the socket
 * @param[in] local_addr - the local address
 * @param[in,out] remote_addr - the peer address
 * @param[out] sk_id - the socket ID that should be relayed
 * @param[in,out] num_bytes - accept the number of bytes in the sendmsg call,
 *                            and return the number of bytes that should be
 *                            relayed
 * @param[out] seqnum - return the sequence number that should be relayed
 * @param[out] detect - return whether to send a detection for this socket
 *                      operation
 * @param[out] detection - a buffer in which to copy detection information,
 *                         if any.
 *
 * @return 1 if caller should relay, 0 if not. returns < 0 on error.
 */
int amp_skactg_sendmsg(amp_skactg_t *handle, pid_t tgid, struct sock *sk,
                       const struct sockaddr_storage *local_addr,
                       struct sockaddr_storage *remote_addr,
                       uint64_t *sk_id, uint32_t *num_bytes, uint32_t *seqnum,
                       bool *detect, amp_op_detection_t *detection);

/** @brief return whether we should monitor this recvmsg and relay it to
 *         userland
 *
 * the caller should relay if:
 * - the socket is already being monitored, or the socket is being newly
 *   monitored and the process has not exceeded its socket monitoring or time
 *   limits, AND:
 *   - the socket is UDP and the sockaddr does not match the last sockaddr
 *     used in a sendmsg or recvmsg. in this case, *num_bytes will be set to 0.
 *
 * @param[in] handle - socket accounting handle
 * @param[in] tgid - the thread group ID (process)
 * @param[in] sk - the socket
 * @param[in] local_addr - the local address
 * @param[in] remote_addr - the peer address
 * @param[out] sk_id - the socket ID that should be relayed
 * @param[in,out] num_bytes - accept the number of bytes in the sendmsg call,
 *                            and return the number of bytes that should be
 *                            relayed
 * @param[out] seqnum - return the sequence number that should be relayed
 * @param[out] detect - return whether to send a detection for this socket
 *                      operation
 * @param[out] detection - a buffer in which to copy detection information,
 *                         if any.
 * @return 1 if caller should relay, 0 if not. returns < 0 on error.
*/
int amp_skactg_recvmsg(amp_skactg_t *handle, pid_t tgid, struct sock *sk,
                       const struct sockaddr_storage *local_addr,
                       struct sockaddr_storage *remote_addr,
                       uint64_t *sk_id, uint32_t *num_bytes, uint32_t *seqnum,
                       bool *detect, amp_op_detection_t *detection);

/** @brief return whether we should monitor this connect and relay it to
 *         userland
 *
 * the caller should relay if:
 * - the socket is already being monitored, or the socket is being newly
 *   monitored and the process has not exceeded its socket monitoring or time
 *   limits
 *
 * @param[in] handle - socket accounting handle
 * @param[in] tgid - the thread group ID (process)
 * @param[in] sk - the socket
 * @param[in] local_addr - the local address
 * @param[in] remote_addr - the peer address
 * @param[out] sk_id - the socket ID that should be relayed
 * @param[out] detect - return whether to send a detection for this socket
 *                      operation
 * @param[out] detection - a buffer in which to copy detection information,
 *                         if any.
 * @return 1 if caller should relay, 0 if not. returns < 0 on error.
*/
int amp_skactg_connect(amp_skactg_t *handle, pid_t tgid, struct sock *sk,
                       const struct sockaddr_storage *local_addr,
                       struct sockaddr_storage *remote_addr,
                       uint64_t *sk_id, bool *detect,
                       amp_op_detection_t *detection);

/** @brief return whether we should monitor this accept and relay it to
 *         userland
 *
 * the caller should relay if:
 * - the socket is already being monitored, or the socket is being newly
 *   monitored and the process has not exceeded its socket monitoring or time
 *   limits
 *
 * @param[in] handle - socket accounting handle
 * @param[in] tgid - the thread group ID (process)
 * @param[in] sk - the socket
 * @param[in] local_addr - the local address
 * @param[in] remote_addr - the peer address
 * @param[out] sk_id - the socket ID that should be relayed
 * @param[out] detect - return whether to send a detection for this socket
 *                      operation
 * @param[out] detection - a buffer in which to copy detection information,
 *                         if any.
 * @return 1 if caller should relay, 0 if not. returns < 0 on error.
*/
int amp_skactg_accept(amp_skactg_t *handle, pid_t tgid, struct sock *sk,
                      const struct sockaddr_storage *local_addr,
                      struct sockaddr_storage *remote_addr,
                      uint64_t *sk_id, bool *detect,
                      amp_op_detection_t *detection);

/** @brief update limits for process
 *
 * @param[in] handle - socket accounting handle
 * @param[in] tgid - the thread group ID (process)
 * @param[in] sock_limit - the number of sockets to monitor for this process
 * @param[in] time_limit - the amount of time to monitor this process
 * @return 0 if successful, or nonzero on error.
*/
int amp_skactg_update_proc_limits(amp_skactg_t *handle, pid_t tgid,
                                  uint32_t sock_limit, uint32_t time_limit);

/** @brief set options
 *
 * @param[in] handle - socket accounting handle
 * @param[in] send_limit - the socket send limit, in bytes
 * @param[in] ignore_ipv6 - whether to ignore sockets with ipv6 addresses
 * @param[in] ignore_loopback - whether to ignore sockets with loopback
 *                              addresses
*/
void amp_skactg_set_opts(amp_skactg_t *handle, uint32_t send_limit,
                         bool ignore_ipv6, bool ignore_loopback);

/** @brief release sock
 *
 * @param[in] handle - socket accounting handle
 * @param[in] sk - the socket
 * @param[out] sk_id - the socket ID that should be relayed
 * @return 1 if the caller should relay the release, 0 if not. returns < 0 on
 *         error.
*/
int amp_skactg_release_sk(amp_skactg_t *handle, struct sock *sk,
                          uint64_t *sk_id);

/** @brief forget about process
 *
 * @param[in] handle - socket accounting handle
 * @param[in] tgid - the thread group ID (process)
*/
void amp_skactg_forget_proc(amp_skactg_t *handle, pid_t tgid);

/** @brief reset monitoring for all processes
 *
 * @param[in] handle - socket accounting handle
*/
void amp_skactg_reset_monitoring(amp_skactg_t *handle);

/** @brief dump info to syslog
 *
 * @param[in] handle - socket accounting handle
*/
void amp_skactg_dump(amp_skactg_t *handle);

/** @brief init
 *
 * @param[in] handle - socket accounting handle
 * @param[in] addrcache - a pointer to an amp_addrcache_t
 * @param[in] max_proc_count - maximum process count
 * @param[in] max_sk_count - maximum socket count
 * @return 0 if successful, or nonzero on error.
*/
int amp_skactg_init(amp_skactg_t *handle, amp_addrcache_t *addrcache,
                    uint32_t max_proc_count, uint32_t max_sk_count);

/** @brief deinit
 *
 * @param[in] handle - socket accounting handle
*/
void amp_skactg_deinit(amp_skactg_t *handle);

#endif

