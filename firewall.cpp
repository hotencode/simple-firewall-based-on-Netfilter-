#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#define NETLINK_TEST 29
#define TEST_PID 100
#define MAX_PAYLOAD 1024
#define MAX_RULE_NUM 50
#define MAX_LOG_NUM 100
#define MAX_CONNECTION_NUM 101
#define MAX_NAT_NUM 100
#define TCP 6
#define UDP 17
#define ICMP 1
#define ANY -1
// definition of Rules
typedef struct {
	char src_ip[20];
	char dst_ip[20];
	int src_port;
	int dst_port;
	char protocol;
	bool action;
	bool log;
}Rule;
static Rule rules[MAX_RULE_NUM];
static int rnum = 0;	//rules num

typedef struct {
	unsigned nat_ip;
	int firewall_port;
	int nat_port;
}NatEntry;
static NatEntry NatTable[MAX_NAT_NUM];
static int nnum = 0;
unsigned net_ip, net_mask, firewall_ip;
int firewall_port = 20000;

//definition of Logs
typedef struct {
	unsigned src_ip;
	unsigned dst_ip;
	int src_port;
	int dst_port;
	char protocol;
	bool action;
}Log;
static Log logs[MAX_LOG_NUM];
static int lnum = 0;	//logs num

//definition of Connections
typedef struct {
	unsigned src_ip;
	int src_port;
	unsigned dst_ip;
	int dst_port;
	char protocol;
	unsigned long t;
}Connection;
static Connection cons[MAX_CONNECTION_NUM];
static Connection cons2[MAX_CONNECTION_NUM];
static int cnum = 0;
/*-----------------------------------------tools----------------------------------*/
unsigned ipstr_to_num(const char *ip_str) {
	int count = 0;
	unsigned tmp = 0, ip = 0, i;
	for (i = 0; i < strlen(ip_str); i++) {
		if (ip_str[i] == '.') {
			ip = ip | (tmp << (8 * (3 - count)));
			tmp = 0;
			count++;
			continue;
		}
		tmp *= 10;
		tmp += ip_str[i] - '0';
	}
	ip = ip | tmp;
	return ip;
}
char * addr_from_net(char * buff, __be32 addr) {
	__u8 *p = (__u8*)&addr;
	snprintf(buff, 16, "%u.%u.%u.%u",
		(__u32)p[3], (__u32)p[2], (__u32)p[1], (__u32)p[0]);
	return buff;
}


/*-----------------------------------------nelink---------------------------------*/
//create a socket
int netlink_create_socket(void)
{
	return socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);
}
int netlink_bind(int sock_fd)
{
	struct sockaddr_nl addr;
	memset(&addr, 0, sizeof(struct sockaddr_nl));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = TEST_PID;
	addr.nl_groups = 0;
	return bind(sock_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_nl));
}
int netlink_send_message(int sock_fd, const unsigned char *message, int len, unsigned int pid = 0, unsigned int group = 0)
{
	struct nlmsghdr *nlh = NULL;
	struct sockaddr_nl dest_addr;
	struct iovec iov;
	struct msghdr msg;
	if (!message)
		return -1;

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(len));
	if (!nlh) {
		perror("malloc nlh error!\n");
		return -2;
	}
	nlh->nlmsg_len = NLMSG_SPACE(len);
	nlh->nlmsg_pid = TEST_PID;
	nlh->nlmsg_flags = 0;

	memcpy(NLMSG_DATA(nlh), message, len);
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&dest_addr, 0, sizeof(struct sockaddr_nl));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = pid;
	dest_addr.nl_groups = group;

	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(struct sockaddr_nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(sock_fd, &msg, 0) < 0)
	{
		perror("send error!\n");
		free(nlh);
		return -3;
	}
	free(nlh);
	return 0;
}

int netlink_recv_message(int sock_fd, unsigned char *message, int *len)
{
	struct nlmsghdr *nlh;
	struct sockaddr_nl source_addr;
	struct iovec iov;
	struct msghdr msg;
	if (!message || !len)
		return -1;
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	if (!nlh) {
		perror("malloc nlh error!\n");
		return -2;
	}
	iov.iov_base = (void *)nlh;
	iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
	memset(&source_addr, 0, sizeof(struct sockaddr_nl));
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = (void *)&source_addr;
	msg.msg_namelen = sizeof(struct sockaddr_nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (recvmsg(sock_fd, &msg, 0) < 0)
	{
		perror("recvmsg error!\n");
		return -3;
	}
	*len = nlh->nlmsg_len - NLMSG_SPACE(0);
	memcpy(message, (unsigned char *)NLMSG_DATA(nlh), *len);
	free(nlh);
	return 0;
}
/*----------------------------------------tools-----------------------------------*/
void print_IP(unsigned int src_ip)
{
	unsigned char src_i[4];
	int i;
	for (i = 0; i < 4; i++)
	{
		src_i[3 - i] = src_ip % 256;
		src_ip /= 256;
	}
	printf("%d.%d.%d.%d", src_i[0], src_i[1], src_i[2], src_i[3]);
}
void sprint_IP(char output[], unsigned int src_ip)
{
	unsigned char src_i[4];
	int i;
	for (i = 0; i < 4; i++)
	{
		src_i[3 - i] = src_ip % 256;
		src_ip /= 256;
	}
	sprintf(output, "%d.%d.%d.%d", src_i[0], src_i[1], src_i[2], src_i[3]);
}
void Convert(unsigned &ip, unsigned &mask, const char *ip_range)
{
	char tmp_ip[20];
	int p = -1, count = 0;
	unsigned len = 0, tmp = 0, i;
	ip = 0, mask = 0;
	strcpy(tmp_ip, ip_range);
	for (i = 0; i < strlen(tmp_ip); i++) {
		if (p != -1) {
			len *= 10;
			len += tmp_ip[i] - '0';
		}
		else if (tmp_ip[i] == '/')
			p = i;
	}
	if (p != -1) {
		tmp_ip[p] = '\0';
		mask = 0xFFFFFFFF << (32 - len);
	}
	else mask = 0xFFFFFFFF;
	for (i = 0; i < strlen(tmp_ip); i++) {
		if (tmp_ip[i] == '.') {
			ip = ip | (tmp << (8 * (3 - count)));
			tmp = 0;
			count++;
			continue;
		}
		tmp *= 10;
		tmp += tmp_ip[i] - '0';
	}
	ip = ip | tmp;
}
/*-----------------------------------------Rules---------------------------------------*/
bool AddRule(const char *src_ip, const char *dst_ip,
	int src_port, int dst_port,
	char protocol,
	bool action, bool log)
{
	if (rnum < 100) {
		strcpy(rules[rnum].src_ip, src_ip);
		strcpy(rules[rnum].dst_ip, dst_ip);
		rules[rnum].src_port = src_port;
		rules[rnum].dst_port = dst_port;
		rules[rnum].protocol = protocol;
		rules[rnum].action = action;
		rules[rnum].log = log;
		rnum++;
		return true;
	}
	return false;
}
bool DelRule(int pos)
{
	if (pos >= rnum || pos < 0)
		return false;
	memcpy(rules + pos, rules + pos + 1, sizeof(Rule)*(rnum - pos));
	rnum--;
	return true;
}
int SendRules()
{
	int sock_fd;
	unsigned char buf[MAX_RULE_NUM * sizeof(Rule) + 10];
	int len;
	sock_fd = netlink_create_socket();
	if (sock_fd == -1)
	{
		perror("send rules socket error!");
		return -1;
	}
	if (netlink_bind(sock_fd) < 0)
	{
		perror("rules bind error!");
		close(sock_fd);
		exit(EXIT_FAILURE);
	}
	buf[0] = 0;
	buf[1] = rnum;
	memcpy(buf + 2, rules, rnum * sizeof(Rule));
	netlink_send_message(sock_fd, (const unsigned char *)buf, rnum * sizeof(Rule) + 2);
	close(sock_fd);
	return 1;
}
void PrintRules()
{
	printf("|----------------------------------------------------------------------------|\n");
	printf("|   src_ip      |   dst_ip      |src_port|dst_port|protocol| action |   log  |\n");
	printf("|----------------------------------------------------------------------------|\n");
	for (int i = 0; i < rnum; i++) {
		printf("|%15.20s|%15.20s|%8d|%8d|%8hhd|%8d|%8d|\n", rules[i].src_ip, rules[i].dst_ip, rules[i].src_port, rules[i].dst_port, rules[i].protocol, rules[i].action, rules[i].log);
		printf("|----------------------------------------------------------------------------|\n");
	}
	return;
}
/*------------------------------NAT RULES--------------------------*/
bool AddNatRule(unsigned nat_ip, int nat_port, int firewall_port)
{
	if (nnum < 100)
	{
		NatTable[nnum].nat_ip = nat_ip;
		NatTable[nnum].nat_port = nat_port;
		NatTable[nnum].firewall_port = firewall_port;
		nnum++;
		return true;
	}
	return false;
}
bool DelNatRule(int pos)
{
	if (pos >= nnum || pos < 0)
		return false;
	memcpy(rules + pos, rules + pos + 1, sizeof(Rule)*(nnum - pos));
	nnum--;
	return true;
}
int SendNatRules()
{
	int sock_fd;
	unsigned char buf[MAX_NAT_NUM * sizeof(NatEntry) + 20];
	sock_fd = netlink_create_socket();
	if (sock_fd == -1)
	{
		perror("send nat rules socket error!");
		return -1;
	}
	if (netlink_bind(sock_fd) < 0)
	{
		perror("send nat rules bind error!");
		close(sock_fd);
		exit(EXIT_FAILURE);
	}
	buf[0] = 1;
	buf[1] = nnum;
	memcpy(buf + 2, &net_ip, sizeof(unsigned));
	memcpy(buf + 6, &net_mask, sizeof(unsigned));
	memcpy(buf + 10, &firewall_ip, sizeof(unsigned));
	memcpy(buf + 14, NatTable, nnum * sizeof(NatEntry));
	netlink_send_message(sock_fd, (const unsigned char *)buf, nnum * sizeof(NatEntry) + 14);
	close(sock_fd);
	return 1;

}

void SetNat(unsigned net, unsigned mask, unsigned firewall)
{
	net_ip = net;
	net_mask = mask;
	firewall_ip = firewall;
}
void PrintNatRules() {
	printf("|-----------------------------------------------------|\n");
	printf("|   nat_ip      |    firewall_port   |    nat_port    |\n");
	printf("|-----------------------------------------------------|\n");
	for (int i = 0; i < nnum; i++) {
		char buff[20], buff2[20];
		printf("|%15.20s|%20d|%16d|\n", addr_from_net(buff2, NatTable[i].nat_ip), NatTable[i].firewall_port, NatTable[i].nat_port);
		printf("|-----------------------------------------------------|\n");
	}
	return;
}

/*----------------------------------------Log---------------------------------------*/
int GetLogs()
{
	int sock_fd;
	int len;
	unsigned char a[2];
	unsigned char buf[MAX_LOG_NUM * sizeof(Log)];
	sock_fd = netlink_create_socket();
	if (sock_fd == -1)
	{
		perror("Get logs create socke error!");
		return -1;
	}
	if (netlink_bind(sock_fd) < 0)
	{
		perror("Get logs bind error!");
		close(sock_fd);
		exit(EXIT_FAILURE);
	}
	a[0] = 2;
	netlink_send_message(sock_fd, (const unsigned char *)a, 1);
	if (netlink_recv_message(sock_fd, buf, &len) == 0)
	{
		printf("recvln:%d\n", len);
		memcpy(logs, buf, len);
		lnum = len / sizeof(Log);
	}
	close(sock_fd);
	return 1;
}
void PrintLogs()
{
	printf("Logs:\n");
	printf("|-------------------------------------------------------------------|\n");
	printf("|   src_ip      |   dst_ip      |src_port|dst_port|protocol| action |\n");
	printf("|-------------------------------------------------------------------|\n");
	for (int i = 0; i < lnum; i++) {
		char buff[20], buff2[20];
		printf("|%15.20s|%15.20s|%8d|%8d|%8hhd|%8d|\n", addr_from_net(buff, logs[i].src_ip), addr_from_net(buff2, logs[i].dst_ip), logs[i].src_port, logs[i].dst_port, logs[i].protocol, logs[i].action);
		printf("|-------------------------------------------------------------------|\n");
	}
}

/*-----------------------------------------Status list--------------------------------------*/
int GetConnections()
{
	int sock_fd;
	int len;
	unsigned char a[2];
	unsigned char buf[MAX_CONNECTION_NUM * sizeof(Connection)];
	sock_fd = netlink_create_socket();
	if (sock_fd == -1)
	{
		perror("Get connection create socke error!");
		return -1;
	}
	if (netlink_bind(sock_fd) < 0)
	{
		perror("Get connection bind error!");
		close(sock_fd);
		exit(EXIT_FAILURE);
	}
	a[0] = 3;
	netlink_send_message(sock_fd, (const unsigned char *)a, 1);
	if (netlink_recv_message(sock_fd, buf, &len) == 0)
	{
		printf("recvln:%d\n", len);
		memcpy(cons, buf, len);
		cnum = len / sizeof(Connection);
	}
	close(sock_fd);
	return 1;
}
void PrintConnections() {
	printf("Connections:\n");
	printf("|----------------------------------------------------------|\n");
	printf("|   src_ip      |   dst_ip      |src_port|dst_port|protocol|\n");
	printf("|----------------------------------------------------------|\n");
	for (int i = 0; i < cnum; i++) {
		char buff[20], buff2[20];
		printf("|%15.20s|%15.20s|%8hu|%8hu|%8hhd|\n", addr_from_net(buff, cons[i].src_ip), addr_from_net(buff2, cons[i].dst_ip), cons[i].src_port, cons[i].dst_port, cons[i].protocol);
		printf("|----------------------------------------------------------|\n");
	}
}
void PrintMenu()
{
	printf("\n\n\n");
	printf("1. add a rule\n");
	printf("2. del a rule\n");
	printf("3. print rules\n");
	printf("4. send rules\n");
	printf("5. set NAT\n");
	printf("6. add a nat rule\n");
	printf("7. del a nat rule\n");
	printf("8. print NAT rules\n");
	printf("9. send nat rules\n");
	printf("10. print logs\n");
	printf("11. print connections\n");
	printf("input your choice(1-10) or 0 to quit:\n");
}
int main()
{
	printf("*-----------------welcome to use MyFW------------------*\n");
	int op;
	while (true) {
		PrintMenu();
		scanf("%d", &op);
		if (op == 0)
		{
			printf("exit!\n");
			getchar();
			break;
		}
		else
		{
			switch (op)
			{
				case 1:
				{
					printf("0 for refuse or no,1 for yes or permit\n");
					char input[20];
					char src_ip[20] = "any", dst_ip[20] = "any";
					int src_port = -1, dst_port = -1;
					char protocol = -1;
					bool action = false;
					bool log = false;
					printf("src_ip(or any):");
					scanf("%s", input);
					if (strcmp(input, "any"))
						strncpy(src_ip, input, strlen(input));
					printf("\n");
					printf("dst_ip(or any):");
					scanf("%s", input);
					if (strcmp(input, "any"))
						strncpy(dst_ip, input, strlen(input));
					printf("\n");
					printf("src_port(or any):");
					scanf("%s", input);
					if (strcmp(input, "any"))
						src_port = atoi(input);
					printf("\n");
					printf("dst_port(or any):");
					scanf("%s", input);
					if (strcmp(input, "any"))
						dst_port = atoi(input);
					printf("\n");
					printf("protocol(6 for TCP,17 for UDP,1 for ICMP, or any):");
					scanf("%s", input);
					if (strcmp(input, "any"))
						protocol = atoi(input);
					printf("\n");

					printf("action(0 for no,1 for yes)");
					scanf("%s", input);
					action = atoi(input);
					printf("\n");
					printf("log(0 for no,1 for yes)");
					scanf("%s", input);
					log = atoi(input);
					printf("\n");
					AddRule(src_ip, dst_ip, src_port, dst_port, protocol, action, log);
					break;
				}
				case 2:
				{
					printf("input which rule you want to delete(0-%d):", rnum - 1);
					int pos;
					scanf("%d", &pos);
					printf("\n");
					if (DelRule(pos))
						printf("successful delete rule:%d\n", pos);
					else
						printf("select error\n");
					break;
				}
				case 3:
				{
					PrintRules();
					break;
				}
				case 4:
				{
					printf("send rules:\n");
					SendRules();
					printf("send end!\n");
					break;
				}
				case 5:
				{
					char net_ip[20], firewall_ip[20];
					unsigned int mask;
					printf("net ip:");
					scanf("%s", net_ip);
					printf("\n");
					printf("net mask:");
					scanf("%x", &mask);
					printf("\n");
					printf("firewall ip:");
					scanf("%s", firewall_ip);
					printf("\n");
					printf("net ip:%s\nnet mask:%x\nfirewall ip:%s\n", net_ip, net_mask, firewall_ip);
					SetNat(ipstr_to_num(net_ip), mask, ipstr_to_num(firewall_ip));
					printf("Set Nat success!\n");
					break;
				}
				case 6:
				{	
					char nat_ip[20];
					int nat_port, firewall_port;
					printf("nat ip:");
					scanf("%s", nat_ip);
					printf("\n");
					printf("nat port:");
					scanf("%d", &nat_port);
					printf("\n");
					printf("firewall port:");
					scanf("%d", &firewall_port);
					printf("\n");
					if (AddNatRule(ipstr_to_num(nat_ip), nat_port, firewall_port))
						printf("Add nat rule success!\n");
					else
						printf("Nat rules full!\n");
					break;
				}
				case 7:
				{	
					printf("input which nat rule you want to delete(0-%d):", nnum - 1);
					int pos;
					scanf("%d", &pos);
					printf("\n");
					if (DelNatRule(pos))
						printf("successful delete nat rule:%d\n", pos);
					else
						printf("select error\n");
					break;
				}
				case 8:
				{
					PrintNatRules();
					break;
				}
				case 9:
				{
					printf("send nat rules:\n");
					SendNatRules();
					printf("send end!\n");
					break;
				}
				case 10:
				{
					if (GetLogs() == 1)
					{
						printf("get logs success!\n");
						PrintLogs();
					}
					else
						printf("get logs error!\n");
					break;
				}
				case 11:
				{
					if (GetConnections() == 1)
					{
						printf("get connections success!\n");
						PrintConnections();
					}
					else
						printf("get connections error!\n");
					break;
				}
				default:
					printf("check your choice and reinput\n");
					break;

			}
		}
	}
	////PrintMenu();
	//AddRule("any", "127.0.0.1", ANY, ANY, ANY, 1, 0);
	//AddRule("127.0.0.1", "any", ANY, ANY, ANY, 1, 0);
	//AddRule("192.168.152.1", "any", ANY, ANY, ANY, 1, 1);
	//AddRule("any", "192.168.152.1", ANY, ANY, ANY, 1, 1);
	//AddRule("192.168.164.1", "any", -1, -1, -1, 1, 1);
	//AddRule("any", "192.168.164.1", -1, -1, -1, 1, 1);
	//AddRule("192.168.164.0/24", "any", ANY, ANY, ANY, 1, 1);
	//AddRule("any", "192.168.164.0/24", ANY, ANY, ANY, 1, 1);
	//AddRule("any", "any", -1, -1, -1, 1, 0);
	//////AddRule("192.168.1.1", "any", -1, -1, -1, 1, 0);
	//PrintRules();
	//printf("sending\n");
	//SendRules();
	//printf("send end\n");

	//char firewall_ip[20] = "192.168.152.1";
	//char nat_ip[20] = "192.168.164.2";
	//int firewall_port = 8888;
	//int nat_port = 80;
	//SetNat(ipstr_to_num("192.168.164.0"), 0xffffff00, ipstr_to_num("192.168.152.1"));
	//AddNatRule(ipstr_to_num(nat_ip), nat_port, firewall_port);
	//PrintNatRules();
	//SendNatRules();

	//GetLogs();
	//PrintLogs();
	return 0;
}
