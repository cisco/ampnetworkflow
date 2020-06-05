/**
 @brief AMP Device Flow Control
        Test client - interacts with ampnetworkflow.ko
        Copyright 2015-2018 Cisco Systems
        GNU Public License
 @author Craig Davison <crdaviso@cisco.com>
 @date 2015 Feb 12
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <libmnl/libmnl.h>
#include <linux/genetlink.h>
#include <syslog.h>
#include <string.h>

#include "../include/ampnetworkflow.h"

#define DUMP_CMD_FREQ 5
#define CMDLINE_OPTS "ap:d"
#define RECV_SOCKET_BUFFER_SIZE ((getpagesize() << 2) < 16384L ? (getpagesize() << 2) : 16384L)

struct cb_data {
    uint16_t amp_family_id;
    bool is_set;
    bool hello_rec;
    bool monitor_all;
    bool detect_all;
    struct mnl_socket *nl;
    unsigned int *seq;
};

static int _print_addr(const struct sockaddr_storage *addr)
{
    int ret = 0;
    char addr_str[INET6_ADDRSTRLEN];

    if (addr->ss_family == AF_INET) {
        if (!inet_ntop(addr->ss_family, &((const struct sockaddr_in *)addr)->sin_addr, addr_str, sizeof(addr_str))) {
            perror("inet_ntop");
            ret = 1;
            goto done;
        }
        printf("%s:%hu", addr_str, ntohs(((const struct sockaddr_in *)addr)->sin_port));
    } else if (addr->ss_family == AF_INET6) {
        if (!inet_ntop(addr->ss_family, &((const struct sockaddr_in6 *)addr)->sin6_addr, addr_str, sizeof(addr_str))) {
            perror("inet_ntop");
            ret = 1;
            goto done;
        }
        printf("[%s]:%hu", addr_str, ntohs(((const struct sockaddr_in6 *)addr)->sin6_port));
    }

done:
    return ret;
}

static struct nlmsghdr *_prepare_msg(char *buf, uint16_t type, uint16_t flags,
                                     uint32_t seq, uint8_t version, uint8_t cmd)
{
    struct genlmsghdr *genl;
    struct nlmsghdr *nlh;
    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = flags;
    nlh->nlmsg_seq = seq;
    genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
    genl->cmd = cmd;
    genl->version = version;
    return nlh;
}

static int _monitor_pid(struct mnl_socket *nl, uint16_t type, uint32_t seq,
                        pid_t pid)
{
    int ret = 0;
    char buf[RECV_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;

    printf("Monitoring PID %d\n", pid);

    nlh = _prepare_msg(buf, type, NLM_F_REQUEST, seq,
                       AMP_NKE_GENL_VERSION,
                       AMP_NKE_CMD_SET_MONITORING_FOR_PID);
    mnl_attr_put_u32(nlh, AMP_NKE_ATTR_PID, pid);
    mnl_attr_put_u32(nlh, AMP_NKE_ATTR_CONN_LIMIT, 1000);
    mnl_attr_put_u32(nlh, AMP_NKE_ATTR_TIME_LIMIT, 1000);
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_sendto");
        ret = -1;
    }

    return ret;
}

static int _set_action(struct mnl_socket *nl, uint16_t type, uint32_t seq,
                       struct sockaddr_storage *remote_addr)
{
    int ret = 0;
    char buf[RECV_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    const char *detection_name = "test_client";

    printf("Sending AMP_NKE_CMD_ACTION_DETECT for ");
    (void)_print_addr(remote_addr);
    printf("\n");

    nlh = _prepare_msg(buf, type, NLM_F_REQUEST, seq,
                       AMP_NKE_GENL_VERSION,
                       AMP_NKE_CMD_ACTION_DETECT);
    mnl_attr_put(nlh, AMP_NKE_ATTR_FLOW_REMOTE_SOCKADDR, sizeof(struct sockaddr_storage), remote_addr);
    mnl_attr_put_u8(nlh, AMP_NKE_ATTR_REMOTE_CLASSIFICATION, 123);
    /* put the AMP_NKE_ATTR_CACHE_REMOTE flag (length of 0) */
    mnl_attr_put(nlh, AMP_NKE_ATTR_CACHE_REMOTE, 0, NULL);
    mnl_attr_put_str(nlh, AMP_NKE_ATTR_DETECTION_NAME, detection_name);
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_sendto");
        ret = -1;
    }

    return ret;
}

static int _genl_ctrl_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    uint16_t type;
    int ret = MNL_CB_OK;

    if (mnl_attr_type_valid(attr, CTRL_ATTR_MAX) < 0) {
        perror("mnl_attr_type_valid");
        ret = MNL_CB_ERROR;
        goto done;
    }

    type = mnl_attr_get_type(attr);
    switch(type) {
        case CTRL_ATTR_FAMILY_NAME:
            if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
                perror("mnl_attr_validate");
                ret = MNL_CB_ERROR;
                goto done;
            }
            break;
        case CTRL_ATTR_FAMILY_ID:
            if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
                perror("mnl_attr_validate");
                ret = MNL_CB_ERROR;
                goto done;
            }
            break;
        default:
            break;
    }
    tb[type] = attr;

done:
    return ret;
}

static int _rec_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    uint16_t type;
    int ret = MNL_CB_OK;
    uint16_t len;

    if (mnl_attr_type_valid(attr, AMP_NKE_ATTR_COUNT-1) < 0) {
        perror("mnl_attr_type_valid");
        ret = MNL_CB_ERROR;
        goto done;
    }

    type = mnl_attr_get_type(attr);
    switch(type) {
        case AMP_NKE_ATTR_REC_PID:
        case AMP_NKE_ATTR_REC_PAYLOAD_SEQNUM:
            if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
                perror("mnl_attr_validate");
                ret = MNL_CB_ERROR;
                goto done;
            }
            break;
        case AMP_NKE_ATTR_REC_FLOW_PROTOCOL:
        case AMP_NKE_ATTR_REC_SK_OP:
        case AMP_NKE_ATTR_REC_REMOTE_CLASSIFICATION:
            if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0) {
                perror("mnl_attr_validate");
                ret = MNL_CB_ERROR;
                goto done;
            }
            break;
        case AMP_NKE_ATTR_REC_FLOW_LOCAL_SOCKADDR:
        case AMP_NKE_ATTR_REC_FLOW_REMOTE_SOCKADDR:
            len = mnl_attr_get_payload_len(attr);
            if (len != sizeof(struct sockaddr_storage)) {
                fprintf(stderr, "incorrect attribute payload length: %" PRIu16 " != %zu\n", len, sizeof(struct sockaddr_storage));
                ret = MNL_CB_ERROR;
                goto done;
            }
            break;
        case AMP_NKE_ATTR_REC_SOCK_ID:
            if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) {
                perror("mnl_attr_validate");
                ret = MNL_CB_ERROR;
                goto done;
            }
            break;
        case AMP_NKE_ATTR_REC_FILENAME:
        case AMP_NKE_ATTR_REC_DETECTION_NAME:
            if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
                perror("mnl_attr_validate");
                ret = MNL_CB_ERROR;
                goto done;
            }
            break;
        default:
            break;
    }
    tb[type] = attr;

done:
    return ret;
}

static void _print_payload(char *payload, ssize_t payload_len)
{
    ssize_t i;
    for (i = 0; i < payload_len; i++) {
        if (payload[i] < 0x20 || payload[i] > 0x7e) {
            /* mask unprintable characters */
            payload[i] = '.';
        }
    }
    fwrite(payload, 1, payload_len, stdout);
}

static int _data_cb(const struct nlmsghdr *nlh, void *data)
{
    struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
    struct cb_data *cb_data = data;
    int err;
    int ret = MNL_CB_OK;
    ssize_t payload_len;
    pid_t pid = -1;
    struct sockaddr_storage *remote_addr = NULL;

    if (nlh->nlmsg_type == cb_data->amp_family_id) {
        struct nlattr *tb[AMP_NKE_ATTR_COUNT] = {};
        printf("amp msg\n");
        err = mnl_attr_parse(nlh, sizeof(*genl), _rec_attr_cb, tb);
        if (err != MNL_CB_OK) {
            ret = err;
            goto done;
        }

        switch(genl->cmd) {
            case AMP_NKE_CMD_REC_SK_OP:
                printf("SK_OP");
                break;
            case AMP_NKE_CMD_REC_DETECT:
                printf("DETECT");
                break;
            case AMP_NKE_CMD_REC_END:
                printf("END");
                break;
            case AMP_NKE_CMD_REC_HELLO:
                printf("HELLO REC");
                cb_data->hello_rec = true;
                break;
            default:
                printf("???");
                break;
        }

        if (tb[AMP_NKE_ATTR_REC_SK_OP]) {
            switch (mnl_attr_get_u8(tb[AMP_NKE_ATTR_REC_SK_OP])) {
                case AMP_NKE_SK_OP_CONNECT:
                    printf(" CONNECT");
                    break;
                case AMP_NKE_SK_OP_ACCEPT:
                    printf(" ACCEPT");
                    break;
                case AMP_NKE_SK_OP_SEND:
                    printf(" SEND");
                    break;
                case AMP_NKE_SK_OP_RECV:
                    printf(" RECV");
                    break;
                case AMP_NKE_SK_OP_RELEASE:
                    printf(" RELEASE");
                    break;
                default:
                    printf(" ???");
                    break;
            }
        }
        if (tb[AMP_NKE_ATTR_REC_PID]) {
            printf(" pid %d", mnl_attr_get_u32(tb[AMP_NKE_ATTR_REC_PID]));
            pid = mnl_attr_get_u32(tb[AMP_NKE_ATTR_REC_PID]);
        }
        if (tb[AMP_NKE_ATTR_REC_UID]) {
            printf(" uid %d", mnl_attr_get_u32(tb[AMP_NKE_ATTR_REC_UID]));
        }
        if (tb[AMP_NKE_ATTR_REC_FILENAME]) {
            printf(" filename %s", mnl_attr_get_str(tb[AMP_NKE_ATTR_REC_FILENAME]));
        }
        if (tb[AMP_NKE_ATTR_REC_FLOW_LOCAL_SOCKADDR]) {
            printf(" local_addr ");
            (void)_print_addr(mnl_attr_get_payload(tb[AMP_NKE_ATTR_REC_FLOW_LOCAL_SOCKADDR]));
        }
        if (tb[AMP_NKE_ATTR_REC_FLOW_REMOTE_SOCKADDR]) {
            printf(" remote_addr ");
            remote_addr = mnl_attr_get_payload(tb[AMP_NKE_ATTR_REC_FLOW_REMOTE_SOCKADDR]);
            (void)_print_addr(remote_addr);
        }
        if (tb[AMP_NKE_ATTR_REC_FLOW_PROTOCOL]) {
            printf(" proto %d", mnl_attr_get_u8(tb[AMP_NKE_ATTR_REC_FLOW_PROTOCOL]));
        }
        if (tb[AMP_NKE_ATTR_REC_SOCK_ID]) {
            printf(" sock_id %" PRIu64, mnl_attr_get_u64(tb[AMP_NKE_ATTR_REC_SOCK_ID]));
        }
        if (tb[AMP_NKE_ATTR_REC_PAYLOAD]) {
            payload_len = mnl_attr_get_payload_len(tb[AMP_NKE_ATTR_REC_PAYLOAD]);
            if (payload_len > 0) {
                printf(" payload [");
                _print_payload(mnl_attr_get_payload(tb[AMP_NKE_ATTR_REC_PAYLOAD]), payload_len);
                printf("]");
            }
        }
        if (tb[AMP_NKE_ATTR_REC_PAYLOAD_SEQNUM]) {
            printf(" payload_seqnum %" PRIu32, mnl_attr_get_u32(tb[AMP_NKE_ATTR_REC_PAYLOAD_SEQNUM]));
        }
        if (tb[AMP_NKE_ATTR_REC_REMOTE_CLASSIFICATION]) {
            printf(" remote_classification %" PRIu8, mnl_attr_get_u8(tb[AMP_NKE_ATTR_REC_REMOTE_CLASSIFICATION]));
        }
        if (tb[AMP_NKE_ATTR_REC_DETECTION_NAME]) {
            printf(" detection_name %s", mnl_attr_get_str(tb[AMP_NKE_ATTR_REC_DETECTION_NAME]));
        }
        printf("\n");

        if (cb_data->monitor_all && pid != -1) {
            *(cb_data->seq) += 1;
            if (_monitor_pid(cb_data->nl, cb_data->amp_family_id, *(cb_data->seq), pid) != 0) {
                ret = -1;
                goto done;
            }
        }
        if (cb_data->detect_all && remote_addr &&
                genl->cmd == AMP_NKE_CMD_REC_SK_OP) {
            *(cb_data->seq) += 1;
            if (_set_action(cb_data->nl, cb_data->amp_family_id, *(cb_data->seq), remote_addr) != 0) {
                ret = -1;
                goto done;
            }
        }
    } else if (nlh->nlmsg_type == GENL_ID_CTRL) {
        struct nlattr *tb[CTRL_ATTR_MAX+1] = {};
        printf("genl ctrl msg\n");
        err = mnl_attr_parse(nlh, sizeof(*genl), _genl_ctrl_attr_cb, tb);
        if (err != MNL_CB_OK) {
            ret = err;
            goto done;
        }
        if (tb[CTRL_ATTR_FAMILY_ID]) {
            cb_data->amp_family_id = mnl_attr_get_u16(tb[CTRL_ATTR_FAMILY_ID]);
            cb_data->is_set = true;
        }
    }

done:
    return ret;
}

static int _rec_msg(struct cb_data *cb_data, char *buf, int buf_size, struct mnl_socket *nl, unsigned int seq, unsigned int portid)
{
    int n;
    int run = 1;
    int ret = -1;

    if (!cb_data || !buf || !nl) {
        fprintf(stderr, "_rec_msg: NULL argument passed\n");
        goto done;
    }

    while (run > 0) {
        n = mnl_socket_recvfrom(nl, buf, buf_size);
        if (n <= 0) {
            if (n < 0) {
                perror("mnl_socket_recvfrom");
            } else {
                fprintf(stderr, "mnl_socket_recvfrom: disconnected\n");
            }
            ret = EXIT_FAILURE;
            goto done;
        }
        run = mnl_cb_run(buf, n, seq, portid, _data_cb, cb_data);
        if (run < 0) {
            if (errno == ENOENT) {
                fprintf(stderr, "Can not find family %s - kernel module may not be loaded\n", AMP_NKE_GENL_FAM_NAME);
            }
            perror("mnl_cb_run");
            ret = EXIT_FAILURE;
            goto done;
        }
    }
    ret = 0;
done:
    return ret;
}

static void _usage(const char *name)
{
    printf("USAGE: %s [options]\n"
"Options: -p <PID> set in-kernel monitoring limits for a single PID\n"
"         -a set in-kernel monitoring limits for all PIDs from which any\n"
"            activity is seen\n"
"         -d set a detection for every remote IP address seen\n",
           name);
}

int main(int argc, char **argv)
{
    struct mnl_socket *nl = NULL;
    char buf[RECV_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    int ret = EXIT_SUCCESS;
    unsigned int seq, portid;
    struct cb_data cb_data = { 0, false, false, false, false, NULL, 0 };
    int n;
    time_t last_dump_cmd = 0;
    time_t now;
    char c;
    int pid;
    int run;
    int fd;
    fd_set rfds;
    int flags;
    int err;
    struct timeval timeout;
    bool reconnect;
    bool monitor_all = false;
    bool monitor_pids = false;
    bool detect_all = false;

    /* parse cmdline */
    while ((c = getopt(argc, argv, CMDLINE_OPTS)) != -1) {
        switch (c) {
            case 'a':
                if (monitor_pids) {
                    _usage(argv[0]);
                    ret = EXIT_FAILURE;
                    goto done;
                }
                monitor_all = true;
                break;
            case 'p':
                if (monitor_all) {
                    _usage(argv[0]);
                    ret = EXIT_FAILURE;
                    goto done;
                }
                monitor_pids = true;
                break;
            case 'd':
                detect_all = true;
                break;
            default:
                _usage(argv[0]);
                ret = EXIT_FAILURE;
                goto done;
        }
    }

    /* connect to generic netlink */
    nl = mnl_socket_open(NETLINK_GENERIC);
    if (nl == NULL) {
        perror("mnl_socket_open");
        ret = EXIT_FAILURE;
        goto done;
    }
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        ret = EXIT_FAILURE;
        goto done;
    }
    portid = mnl_socket_get_portid(nl);
    cb_data.nl = nl;
    cb_data.seq = &seq;
    cb_data.monitor_all = monitor_all;
    cb_data.detect_all = detect_all;

    /* get the family ID for AMP_NKE_GENL_FAM_NAME */
    seq = (time(NULL) & 0x00ffffff) << 8;
    nlh = _prepare_msg(buf, GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK, seq,
                       1 /* version */, CTRL_CMD_GETFAMILY);
    mnl_attr_put_u32(nlh, CTRL_ATTR_FAMILY_ID, GENL_ID_CTRL);
    mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, AMP_NKE_GENL_FAM_NAME);
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_sendto");
        ret = EXIT_FAILURE;
        goto done;
    }
    
    if(_rec_msg(&cb_data, buf, sizeof(buf), nl, seq, portid) != 0) {
        goto done;
    }

    if (!cb_data.is_set) {
        fprintf(stderr, "No response from genl_ctrl\n");
        ret = -1;
        goto done;
    }
    printf("Family ID: %" PRIu16 "\n", cb_data.amp_family_id);

    do {
        reconnect = false;

        if (!nl) {
            /* connect to generic netlink */
            nl = mnl_socket_open(NETLINK_GENERIC);
            if (nl == NULL) {
                perror("mnl_socket_open");
                ret = EXIT_FAILURE;
                goto done;
            }
            if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
                perror("mnl_socket_bind");
                ret = EXIT_FAILURE;
                goto done;
            }
            portid = mnl_socket_get_portid(nl);
        }

        /* send hello */
        printf("Sending Hello...\n");
        seq++;
        nlh = _prepare_msg(buf, cb_data.amp_family_id, NLM_F_REQUEST | NLM_F_ACK, seq,
                           AMP_NKE_GENL_VERSION, AMP_NKE_CMD_HELLO);
            if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
            perror("mnl_socket_sendto");
            ret = EXIT_FAILURE;
            goto done;
        }

        /* Recieve hello rec */
        printf("Looking for AMP_NKE_CMD_REC_HELLO response...\n");
        if(_rec_msg(&cb_data, buf, sizeof(buf), nl, seq, portid) != 0) {
            goto done;
        }

        if (!cb_data.hello_rec) {
            fprintf(stderr, "No AMP_NKE_CMD_REC_HELLO response from kernel module\n");
            goto done;
        }
        printf("AMP_NKE_CMD_REC_HELLO response recieved from kernel module\n");


        /* reset monitoring */
        seq++;
        nlh = _prepare_msg(buf, cb_data.amp_family_id, NLM_F_REQUEST, seq,
                           AMP_NKE_GENL_VERSION, AMP_NKE_CMD_RESET_MONITORING);
        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
            perror("mnl_socket_sendto");
            ret = EXIT_FAILURE;
            goto done;
        }

        /* set options */
        seq++;
        nlh = _prepare_msg(buf, cb_data.amp_family_id, NLM_F_REQUEST, seq,
                           AMP_NKE_GENL_VERSION, AMP_NKE_CMD_SET_OPTS);
        mnl_attr_put_u32(nlh, AMP_NKE_ATTR_SET_SEND_LIMIT, 16384);
        //mnl_attr_put(nlh, AMP_NKE_ATTR_IGNORE_IPV6, 0, NULL);
        //mnl_attr_put(nlh, AMP_NKE_ATTR_IGNORE_LOOPBACK, 0, NULL);
        mnl_attr_put_u8(nlh, AMP_NKE_ATTR_LOG_LEVEL, LOG_DEBUG);
        mnl_attr_put_u32(nlh, AMP_NKE_ATTR_CACHE_MAX_SIZE, detect_all ? UINT32_MAX : 0);
        mnl_attr_put_u32(nlh, AMP_NKE_ATTR_CACHE_TTL_CLEAN, UINT32_MAX);
        mnl_attr_put_u32(nlh, AMP_NKE_ATTR_CACHE_TTL_MALICIOUS, UINT32_MAX);
        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
            perror("mnl_socket_sendto");
            ret = EXIT_FAILURE;
            goto done;
        }

        /* process monitoring, if specified on the cmdline */
        optind = 1;
        while ((c = getopt(argc, argv, CMDLINE_OPTS)) != -1) {
            if (c == 'p') {
                pid = strtol(optarg, NULL, 10);
                if (pid == 0 && errno != 0) {
                    perror("strtol");
                    ret = EXIT_FAILURE;
                    goto done;
                }
                seq++;
                if (_monitor_pid(nl, cb_data.amp_family_id, seq, pid) != 0) {
                    ret = EXIT_FAILURE;
                    goto done;
                }
            }
        }

        /* put socket in non-blocking mode */
        fd = mnl_socket_get_fd(nl);
        flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) {
            perror("fcntl(F_GETFL)");
            ret = -1;
            goto done;
        }
        err = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        if (err != 0) {
            perror("fcntl(F_SETFL)");
            ret = -1;
            goto done;
        }

        /* start receiving events */
        do {
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            n = select(fd+1, &rfds, NULL, NULL, &timeout);
            if (n < 0) {
                perror("select");
                ret = EXIT_FAILURE;
                goto done;
            }
            if (n > 0) {
                n = mnl_socket_recvfrom(nl, buf, sizeof(buf));
                while (n > 0) {
                    run = mnl_cb_run(buf, n, 0 /* seq */, portid, _data_cb, &cb_data);
                    if (run < 0) {
                        if (errno == EPERM) {
                            fprintf(stderr, "Operation requires CAP_NET_ADMIN (run as root)\n");
                        }
                        perror("mnl_cb_run");
                        ret = EXIT_FAILURE;
                        goto done;
                    }
                    n = mnl_socket_recvfrom(nl, buf, sizeof(buf));
                }
                if (n < 0 && errno != EAGAIN) {
                    perror("mnl_socket_recvfrom");
                    if (errno != ENOBUFS) {
                        ret = EXIT_FAILURE;
                        goto done;
                    }
                }
                if (n == 0) {
                    fprintf(stderr, "mnl_socket_recvfrom: disconnected\n");
                    reconnect = true;
                    break;
                }
            }

            /* send a dump cmd at most every DUMP_CMD_FREQ seconds */
            now = time(NULL);
            if (now - last_dump_cmd >= DUMP_CMD_FREQ) {
                /* send dump_accounting */
                printf("sending dump_accounting (it has been %ld secs)\n", now - last_dump_cmd);
                seq++;
                nlh = _prepare_msg(buf, cb_data.amp_family_id, NLM_F_REQUEST, seq,
                                   AMP_NKE_GENL_VERSION,
                                   AMP_NKE_CMD_DUMP_ACCOUNTING);
                if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
                    perror("mnl_socket_sendto");
                    ret = EXIT_FAILURE;
                    goto done;
                }
                last_dump_cmd = now;
            }
        } while (1);
        if (reconnect) {
            mnl_socket_close(nl);
            nl = NULL;
            usleep(10000);
        }
    } while (reconnect);

done:
    if (nl) {
        mnl_socket_close(nl);
        nl = NULL;
    }

    return ret;
}

