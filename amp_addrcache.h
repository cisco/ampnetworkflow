/**
 @brief AMP Device Flow Control
        IP Address Cache
        Copyright 2016-2018 Cisco Systems
        GNU Public License
 @author Craig Davison <crdaviso@cisco.com>
 @date 2016 May 27
*/

#ifndef AMP_ADDRCACHE_H
#define AMP_ADDRCACHE_H

#include <linux/rbtree.h>

#ifndef UINT32_MAX
#   define UINT32_MAX 0xFFFFFFFF
#endif

typedef struct {
    /** lock: */
    spinlock_t lock;
    /** clean TTL, in seconds: */
    uint32_t ttl_clean;
    /** malicious TTL, in seconds: */
    uint32_t ttl_malicious;
    /** # entries: */
    uint32_t max_size;
    /** # entries: */
    uint32_t size;
    /** tree: */
    struct rb_root tree;
    /** the most-recently used item in the cache: */
    struct amp_addrcache_entry *list_head;
    /** the least-recently used item in the cache: */
    struct amp_addrcache_entry *list_tail;
} amp_addrcache_t;

typedef struct {
    uint8_t remote_classification;
    char detection_name[64];
} amp_op_detection_t;

/** @brief add an item to the cache
 * @param handle A pointer to an amp_addrcache_t
 * @param remote_addr A pointer to a sockaddr to add to the cache. Fields other
 *                    than the family and addr are ignored. Only the AF_INET and
 *                    AF_INET6 families are supported.
 * @param detect The value to set detect to for the sockaddr
 * @param detection A pointer to detection information
 * @return 0 on success; nonzero on error
 */
int amp_addrcache_add(amp_addrcache_t *handle,
                      const struct sockaddr *remote_addr, bool detect,
                      amp_op_detection_t *detection);

/** @brief find an item in the cache
 * @param handle A pointer to an amp_addrcache_t
 * @param remote_addr A pointer to a sockaddr to find in the cache. Fields other
 *                    than the family and addr are ignored. Only the AF_INET and
 *                    AF_INET6 families are supported.
 * @param[out] found A pointer to a bool to receive true if the sockaddr was
 *                   found in the cache
 * @param[out] detect A pointer to a bool to receive the detect value for the
 *                    sockaddr in the cache
 * @param[out] detection A pointer to receive detection information
 * @return 0 on success; nonzero on error
 */
int amp_addrcache_lookup(amp_addrcache_t *handle,
                         const struct sockaddr *remote_addr, bool *found,
                         bool *detect, amp_op_detection_t *detection);

/** @brief Set cache options
 * @param handle A pointer to an amp_addrcache_t
 * @param max_size The maximum number of entries in the cache. Pass UINT32_MAX
 *                 to use the default size.
 * @param ttl_clean The clean TTL. Pass UINT32_MAX to use the default value.
 * @param ttl_malicious The malicious TTL. Pass UINT32_MAX to use the default
 *                      value.
 * @return 0 on success; nonzero on error
 */
int amp_addrcache_set_opts(amp_addrcache_t *handle, uint32_t max_size,
                           uint32_t ttl_clean, uint32_t ttl_malicious);

/** @brief Empty cache
 * @param handle A pointer to an amp_addrcache_t
 */
int amp_addrcache_empty(amp_addrcache_t *handle);

/** @brief init
 * @param handle A pointer to an amp_addrcache_t
 * @param max_size The maximum number of entries in the cache. Pass UINT32_MAX
 *                 to use the default size.
 * @param ttl_clean The clean TTL. Pass UINT32_MAX to use the default value.
 * @param ttl_malicious The malicious TTL. Pass UINT32_MAX to use the default
 *                      value.
 * @return 0 on success; nonzero on error
 */
int amp_addrcache_init(amp_addrcache_t *handle, uint32_t max_size,
                       uint32_t ttl_clean, uint32_t ttl_malicious);

/** @brief deinit
 * @param handle A pointer to an amp_addrcache_t
 */
int amp_addrcache_deinit(amp_addrcache_t *handle);

#endif

