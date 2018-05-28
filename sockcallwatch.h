/**
 @brief AMP Device Flow Control
        Socket Call Watcher
        Copyright 2014-2018 Cisco Systems
        GNU Public License
 @author Craig Davison <crdaviso@cisco.com>
 @date 2014 Jun 16
*/

#ifndef AMP_NKE_SOCKCALLWATCH_H
#define AMP_NKE_SOCKCALLWATCH_H

#include "compat.h"

#ifdef STRUCT_MSGHDR_HAS_IOCB
typedef int (*amp_scw_recvmsg_fn_t)(struct socket *sock, struct msghdr *msg,
                                    size_t size, int flags);
typedef int (*amp_scw_sendmsg_fn_t)(struct socket *sock, struct msghdr *msg,
                                    size_t size);
#else
typedef int (*amp_scw_recvmsg_fn_t)(struct kiocb *iocb, struct socket *sock,
                                    struct msghdr *msg, size_t size, int flags);
typedef int (*amp_scw_sendmsg_fn_t)(struct kiocb *iocb, struct socket *sock,
                                    struct msghdr *msg, size_t size);
#endif
typedef int (*amp_scw_connect_fn_t)(struct socket *sock,
                                    struct sockaddr * uaddr,
                                    int addr_len, int flags);
#ifdef PROTO_ACCEPT_HAS_KERN
typedef int (*amp_scw_accept_fn_t)(struct socket *sock,
                                   struct socket *newsock, int flags, bool kern);
#else
typedef int (*amp_scw_accept_fn_t)(struct socket *sock,
                                   struct socket *newsock, int flags);
#endif
typedef int (*amp_scw_release_fn_t)(struct socket *sock);

#ifdef PROTO_ACCEPT_HAS_KERN
typedef struct sock *(*amp_scw_post_accept_fn_t)(struct sock *sk, int flags, int *err,
                                                 bool kern);
#else
typedef struct sock *(*amp_scw_post_accept_fn_t)(struct sock *sk, int flags, int *err);
#endif
/* cast the function to amp_scw_dummy_fn_t when using amp_scw_register_dummy: */
typedef void (*amp_scw_dummy_fn_t)(void);

typedef void (*amp_scw_connect_cb_t)(struct socket *sock,
                                     struct sockaddr * uaddr,
                                     int addr_len, int flags);
typedef void (*amp_scw_accept_cb_t)(struct socket *sock,
                                    struct socket *newsock, int flags);
typedef void (*amp_scw_recvmsg_cb_t)(struct kiocb *iocb, struct socket *sock,
                                    struct msghdr *msg, size_t size, int flags);
typedef void (*amp_scw_sendmsg_cb_t)(struct kiocb *iocb, struct socket *sock,
                                    struct msghdr *msg, size_t size);
typedef void (*amp_scw_release_cb_t)(struct socket *sock);
typedef void (*amp_scw_post_accept_cb_t)(struct sock *sk);

/** @note the return value from these callbacks is ignored: */
typedef struct {
    amp_scw_connect_cb_t connect_cb;
    amp_scw_accept_cb_t accept_cb;
    amp_scw_recvmsg_cb_t recvmsg_cb;
    amp_scw_sendmsg_cb_t sendmsg_cb;
    amp_scw_release_cb_t release_cb;
    amp_scw_post_accept_cb_t post_accept_cb;
} amp_scw_cb_t;

/**
 * @brief init
 *
 * @param[in] cb - pointer to a structure defining callbacks
 * @return 0 if successful, or nonzero on error
 */
int amp_scw_init(amp_scw_cb_t *cb);

/**
 * @brief deinit
 *
 * @return 0 if successful, or nonzero on error
 */
int amp_scw_deinit(void);

/**
 * @brief watch a recvmsg function. the callback will be called before the
 *        function executes, and will be passed its parameters.
 *
 * @param[in] func - the function to watch
 * @return 0 if successful, or nonzero on error
 */
int amp_scw_register_recvmsg(amp_scw_recvmsg_fn_t func);

/**
 * @brief watch a sendmsg function. the callback will be called before the
 *        function executes, and will be passed its parameters.
 *
 * @param[in] func - the function to watch
 * @return 0 if successful, or nonzero on error
 */
int amp_scw_register_sendmsg(amp_scw_sendmsg_fn_t func);

/**
 * @brief watch a connect function. the callback will be called before the
 *        function executes, and will be passed its parameters.
 *
 * @param[in] func - the function to watch
 * @return 0 if successful, or nonzero on error
 */
int amp_scw_register_connect(amp_scw_connect_fn_t func);

/**
 * @brief watch an accept function. the callback will be called before the
 *        function executes, and will be passed its parameters.
 *
 * @param[in] func - the function to watch
 * @return 0 if successful, or nonzero on error
 */
int amp_scw_register_accept(amp_scw_accept_fn_t func);

/**
 * @brief watch a release function. the callback will be called before the
 *        function executes, and will be passed its parameters.
 *
 * @param[in] func - the function to watch
 * @return 0 if successful, or nonzero on error
 */
int amp_scw_register_release(amp_scw_release_fn_t func);

/**
 * @brief watch an accept function. the callback will be called after the
 *        function executes, and will be passed its return value.
 *
 * @param[in] func - the function to watch
 * @return 0 if successful, or nonzero on error
 */
int amp_scw_register_post_accept(amp_scw_post_accept_fn_t func);

/**
 * @brief watch a function. no callback will be called when the function
 *        executes. this function is for testing purposes.
 *
 * @param[in] func - the function to watch
 * @return 0 if successful, or nonzero on error
 */
int amp_scw_register_dummy(amp_scw_dummy_fn_t func);

/**
 * @brief return whether a function is being watched
 *
 * @param[in] func - the function
 * @return nonzero if the function is being watched, or 0 if it is not
 */
int amp_scw_is_registered(void *func);

#endif

