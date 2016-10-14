/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing TCP SYN scans

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include "../../lib/includes.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"

probe_module_t module_tcp_synscan;
static uint32_t num_ports;

int synscan_global_initialize(struct state_conf *state) {
    num_ports = state->source_port_last - state->source_port_first + 1;
    return EXIT_SUCCESS;
}

int synscan_init_perthread(void *buf, macaddr_t *src,
                           macaddr_t *gw, port_h_t dst_port,
                           __attribute__((unused)) void **arg_ptr) {
    memset(buf, 0, MAX_PACKET_SIZE);
    struct ether_header *eth_header = (struct ether_header *) buf;
    make_eth_header(eth_header, src, gw);
    struct ip *ip_header = (struct ip *) (&eth_header[1]);
    uint16_t len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    make_ip_header(ip_header, IPPROTO_TCP, len);
    struct tcphdr *tcp_header = (struct tcphdr *) (&ip_header[1]);
    make_tcp_header(tcp_header, dst_port, TH_SYN);
    return EXIT_SUCCESS;
}

int synscan_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
                        uint32_t *validation, int probe_num, __attribute__((unused)) void *arg) {
    struct ether_header *eth_header = (struct ether_header *) buf;
    struct ip *ip_header = (struct ip *) (&eth_header[1]);
    struct tcphdr *tcp_header = (struct tcphdr *) (&ip_header[1]);
    uint32_t tcp_seq = validation[0];

    ip_header->ip_src.s_addr = src_ip;
    ip_header->ip_dst.s_addr = dst_ip;

    tcp_header->th_sport = htons(get_src_port(num_ports,
                                              probe_num, validation));
    tcp_header->th_seq = tcp_seq;
    tcp_header->th_sum = 0;
    tcp_header->th_sum = tcp_checksum(sizeof(struct tcphdr),
                                      ip_header->ip_src.s_addr, ip_header->ip_dst.s_addr, tcp_header);

    ip_header->ip_sum = 0;
    ip_header->ip_sum = zmap_ip_checksum((unsigned short *) ip_header);

    return EXIT_SUCCESS;
}

void synscan_print_packet(FILE *fp, void *packet) {
    struct ether_header *ethh = (struct ether_header *) packet;
    struct ip *iph = (struct ip *) &ethh[1];
    struct tcphdr *tcph = (struct tcphdr *) &iph[1];
    fprintf(fp, "tcp { source: %u | dest: %u | seq: %u | checksum: %#04X }\n",
            ntohs(tcph->th_sport),
            ntohs(tcph->th_dport),
            ntohl(tcph->th_seq),
            ntohs(tcph->th_sum));
    fprintf_ip_header(fp, iph);
    fprintf_eth_header(fp, ethh);
    fprintf(fp, "------------------------------------------------------\n");
}

int synscan_validate_packet(const struct ip *ip_hdr, uint32_t len,
                            __attribute__((unused))uint32_t *src_ip,
                            uint32_t *validation) {
    if (ip_hdr->ip_p != IPPROTO_TCP) {
        return 0;
    }
    if ((4 * ip_hdr->ip_hl + sizeof(struct tcphdr)) > len) {
        // buffer not large enough to contain expected tcp header
        return 0;
    }
    struct tcphdr *tcp = (struct tcphdr *) ((char *) ip_hdr + 4 * ip_hdr->ip_hl);
    uint16_t sport = tcp->th_sport;
    uint16_t dport = tcp->th_dport;
    // validate source port
    if (ntohs(sport) != zconf.target_port) {
        return 0;
    }
    // validate destination port
    if (!check_dst_port(ntohs(dport), num_ports, validation)) {
        return 0;
    }

    // We treat RST packets different from non RST packets
    if (tcp->th_flags & TH_RST) {
        // For RST packets, recv(ack) == sent(seq) + 0 or + 1
        if (htonl(tcp->th_ack) != htonl(validation[0])
            && htonl(tcp->th_ack) != htonl(validation[0]) + 1) {
            return 0;
        }
    } else {
        // For non RST packets, recv(ack) == sent(seq) + 1
        if (htonl(tcp->th_ack) != htonl(validation[0]) + 1) {
            return 0;
        }
    }

    return 1;
}

// [MOBI]
typedef struct {
    uint8_t kind;
    uint8_t size;
} tcp_option_t;

#define TH_OFF(th)    (((th)->th_off & 0xf0) >> 4)

void synscan_process_packet(const u_char *packet,
                            __attribute__((unused)) uint32_t len, fieldset_t *fs,
                            __attribute__((unused)) uint32_t *validation) {
    struct ip *ip_hdr = (struct ip *) &packet[sizeof(struct ether_header)];
    struct tcphdr *tcp = (struct tcphdr *) ((char *) ip_hdr
                                            + 4 * ip_hdr->ip_hl);

    fs_add_uint64(fs, "sport", (uint64_t) ntohs(tcp->th_sport));
    fs_add_uint64(fs, "dport", (uint64_t) ntohs(tcp->th_dport));
    fs_add_uint64(fs, "seqnum", (uint64_t) ntohl(tcp->th_seq));
    fs_add_uint64(fs, "acknum", (uint64_t) ntohl(tcp->th_ack));
    fs_add_uint64(fs, "window", (uint64_t) ntohs(tcp->th_win));

    if (tcp->th_flags & TH_RST) { // RST packet
        fs_add_string(fs, "classification", (char *) "rst", 0);
        fs_add_bool(fs, "success", 0);
    } else { // SYNACK packet
        fs_add_string(fs, "classification", (char *) "synack", 0);
        fs_add_bool(fs, "success", 1);
    }



    // [MOBI]
    // MSS Parsing
//    uint16_t mss = 0;
////    uint8_t *tmp = (uint8_t *) tcp;
//    if (tcp->th_off > 5) {
//        unsigned char *tmp = tcp;
////        uint8_t *opt = (uint8_t * )((char *) tcp + sizeof(struct tcphdr));
//        unsigned char* opt = tmp + sizeof(struct tcphdr);
//        printf("[TEST] src: %s\n", inet_ntoa(ip_hdr->ip_src));
//        printf("[TEST] dst: %s\n", inet_ntoa(ip_hdr->ip_dst));
//        while (*opt != 0) {
//            printf("[TEST] 33333333 \n");
//            tcp_option_t *_opt = (tcp_option_t *) opt;
//            if (_opt->kind == 1 /* NOP */ ) {
//                ++opt;  // NOP is one byte;
//                printf("[TEST] 4444444 \n");
//                continue;
//            }
//            if (_opt->kind == 2 /* MSS */ ) {
//                if (_opt->size == 4) {
//
//                }
////                mss = ((*(opt + (sizeof(*_opt)))) << 8) + *(opt + sizeof(*_opt) + 1);
////                unsigned int* mss_opt = (unsigned int*)(opt + sizeof(tcp_option_t));
////                mss = htons(*mss_opt);
//            }
//            opt += _opt->size;
//            printf("[TEST] 5555555 \n");
//
//            if (_opt->size == 0) {
//                break;
//            }
//        }
//    }

//    printf("[TEST] src: %s \t dst: %s\n", inet_ntoa(ip_hdr->ip_src), inet_ntoa(ip_hdr->ip_dst));
//    printf("[TEST] pid: %d \t ppid: %d \t tid: %d\n", getpid(), getppid(), syscall(SYS_gettid));

    uint16_t mss = 0;
    uint8_t *opt = (uint8_t * )(packet + 20 + sizeof(struct ether_header) + sizeof(struct tcphdr));
//    if (tcp->th_off > 5) {
        while (*opt != 0) {
            tcp_option_t *_opt = (tcp_option_t *) opt;

            if (_opt->size == 0) {
                break;
            }

            if (_opt->kind == 1 /* NOP */ ) {
                ++opt;  // NOP is one byte;
                continue;
            }
//        if( _opt->kind == 2 /* MSS */ ) {
//            mss = ntohs((uint16_t)*(opt + sizeof(opt)));
//            mss = ((*(opt + (sizeof(*_opt)))) << 8) + *(opt + sizeof(*_opt) + 1);
//        }

//            if (_opt->kind == 0) {
//                printf("[MOBI] KIND : 0 ===== 0\n");
//            }

            opt += _opt->size;
            if (_opt->kind == 0) {
//                printf("[MOBI] KIND : 0 ===== 1\n");
                break;
            }
            if (_opt->size == 0) {
                break;
            }
        }
//    }

//    if (mss != 0)
//        fs_add_uint64(fs, "mss", mss);
//    else
//        fs_add_uint64(fs, "mss", 0);
}

static fielddef_t fields[] = {
        {.name = "sport", .type = "int", .desc = "TCP source port"},
        {.name = "dport", .type = "int", .desc = "TCP destination port"},
        {.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
        {.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
        {.name = "window", .type = "int", .desc = "TCP window"},
        {.name = "classification", .type="string", .desc = "packet classification"},
        {.name = "success", .type="bool", .desc = "is response considered success"},
        {.name = "mss", .type="int", .desc = "mss value"}
};

probe_module_t module_tcp_synscan = {
        .name = "tcp_synscan",
        .packet_length = 54,
        .pcap_filter = "tcp && tcp[13] & 4 != 0 || tcp[13] == 18",
        .pcap_snaplen = 96,
        .port_args = 1,
        .global_initialize = &synscan_global_initialize,
        .thread_initialize = &synscan_init_perthread,
        .make_packet = &synscan_make_packet,
        .print_packet = &synscan_print_packet,
        .process_packet = &synscan_process_packet,
        .validate_packet = &synscan_validate_packet,
        .close = NULL,
        .helptext = "Probe module that sends a TCP SYN packet to a specific "
                "port. Possible classifications are: synack and rst. A "
                "SYN-ACK packet is considered a success and a reset packet "
                "is considered a failed response.",
        .output_type = OUTPUT_TYPE_STATIC,
        .fields = fields,
        .numfields = 8};

