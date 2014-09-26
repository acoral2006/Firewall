//gcc project.c -o project -lnetfilter_queue
//./project <ip> <port> <count>
//all data stored in logtextfile.csv
//sudo ./test 192.168.10.4 896 20 KANN
//sudo ./test 192.168.10.1 13568 200 yahoo
//gcc -o test firewall.c -lnetfilter_queue -lnfnetlink -Wall



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>

	char *find_ip;
	char *find_port;
	char *global_i;
	FILE *logtext;
	char *find_word;
	char *table0[2056];
	int table1[2056];
	int j,x;
	int count;


/* returns packet id */

 static int nfqueue_cb(struct nfq_q_handle *qh, //queue handle created by nfq_create_queue
                      struct nfgenmsg *nfmsg,
                      struct nfq_data *nfa,
                      void *data) {

  uint32_t ip_src;
  struct in_addr s_ip;
  uint16_t src_port;
  int id,i;
  int ret, rez_ip, rez_port;
  unsigned char *buffer;
  char nbuffer[1024];
  
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr (nfa); //get the metaheader of the packet

  if (ph)
    {
      id = ntohl (ph->packet_id);
    }
 	
  ret = nfq_get_payload (nfa, &buffer);//data handle passed to the callback, pointer to pointer to the payload
  ip_src = *((uint32_t *) (buffer + 12));
  src_port = *((uint16_t *) (buffer + 20));
  s_ip.s_addr = (uint32_t) ip_src;
  *(buffer + 26) = 0x00;
  *(buffer + 27) = 0x00;
  

  	//Check if port and IP are the ones we need
 	rez_ip = (strcmp (find_ip, inet_ntoa(s_ip)));
 	if ((atoi(find_port)) == src_port) rez_port=1;
  	else rez_port=0;

//  uncomment this to see the IPs, ports and payloads in order to know what input to give to program
/*
	printf ("\nsource IP %s \n, ", inet_ntoa (s_ip));
	printf ( "source port %d \n, ", src_port); 
	for ( i = 0; i < ret; i++) {
    		 if (isprint(buffer[i])){
       		 printf("%c",buffer[i]);
       		}
	   	}

*/
		*nbuffer=0;
    	for ( i = 0; i < ret; i++) 
    	{
    		 if (isprint(buffer[i]))
    		 	{
       		 	sprintf(nbuffer + strlen(nbuffer),"%c",buffer[i]);
       			}
	   	}
	if ((rez_ip == 0) && (rez_port == 1) && ((strstr(nbuffer,find_word) != NULL))) 
		{
			table0[j] = malloc(strlen(nbuffer) + 1);
			strcpy (table0[j], nbuffer);
			table1[j]=1;
			j++;     	
		}
		nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		count--;
			
return 0; //The callback should return < 0 to stop processing.
}


int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd,i;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	char random[1000];
	
	system ("sudo iptables -A INPUT -p UDP -j QUEUE");
	printf ("iptables rule set!\n");

	logtext = fopen("logtextfile.csv", "wa");
  
    if (!logtext) {
        printf("can not open logtextfile.txt for writing.\n");
        exit(1);
    }
  	j=1;
	find_ip = argv[1];	 
	find_port =  argv[2];
	global_i =  argv[3];
	find_word = argv[4];
	count = atoi (global_i);

	printf("opening library NFQ handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}
//tell userspace that the userspace queuing is handled by NFQUEUE
	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");

	qh = nfq_create_queue(h,  0, &nfqueue_cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}
	
	nh = nfq_nfnlh(h);
    fd = nfnl_fd(nh);
	
	while   (((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)  && (count > 0) ) {
			nfq_handle_packet(h, buf, rv);
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif
	
//Check if duplicates exist and count them
	for(i=1;i<j;i++)
	{ 	
		strcpy(random,table0[i]);
		
		if (table1[i]>0)
		{
		for (x=i+1;x<j;x++)
			{ if (strcmp(random,table0[x])==0)
					{
						table1[i]+=1;
						table1[x]=0;
					}
			}
		}	
	}
//print all data to a csv file
	for(i=1;i<j;i++)
			{ if (table1[i]>0)
			fprintf(logtext,"%s , %s , %s , %i \n",find_ip, find_port, table0[i], table1[i]);
		}

	system("sudo iptables --flush");
	printf("iptables rules deleted\n");
	printf("closing library handle\n");
	fclose(logtext);
	nfq_close(h);
	exit(0);
}

