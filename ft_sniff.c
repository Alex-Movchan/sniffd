#include "daemon_sniff.h"

extern char			config[20];

static void handle_packet(uint8_t* user, const struct pcap_pkthdr *hdr, const uint8_t* bytes)
{
	t_nod				*pack;
	struct iphdr		*ip_header;
	struct sockaddr_in	source;

	UNUSED(user);
	ip_header = (struct iphdr*)(bytes + sizeof(struct ethhdr));
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip_header->saddr;
	/*
	 * initializing a new node
	 */
	if (!(pack = (t_nod*)malloc(sizeof(t_nod))))
	{
		syslog(LOG_ERR, "Error malloc");
		pcap_freealldevs(alldevs);
		pcap_close(pcap);
		exit(EXIT_FAILURE);
	}
	pack->left = NULL;
	pack->right = NULL;
	ft_strncpy(pack->ip_adrr, inet_ntoa(source.sin_addr), 16);
	pack->count = 1;
	ft_add_tree(pack, &root_nod);
}

bool	list_devs(void) //check the device
{
	int			errcode;
	pcap_if_t	*currdev;

	errcode = pcap_findalldevs(&alldevs, errbuff);
	if (errcode != 0)
	{
		printf("pcap_findalldevs failed: %s", errbuff);

		syslog(LOG_ERR, "pcap_findalldevs failed: %s", errbuff);
		exit(EXIT_FAILURE);
	}
	currdev = alldevs;
	while (currdev)
	{
		if (!ft_strcmp(currdev->name, config))
			return (true);
		currdev = currdev->next;
	}
	return (false);
}

void	*ft_sniff(void *arg)
{
	struct bpf_program	filterprog;

	if (list_devs() == false)
	{
		syslog(LOG_ERR, "Error iface");
		pcap_freealldevs(alldevs);
		exit(EXIT_FAILURE);
	}
	/*
	 * Getting the descriptor of the packet capture structure
	 */
	if (!(pcap = pcap_open_live(config, MAX_LEN_BUFF, 1, 100, errbuff)))
	{
		syslog(LOG_ERR, "ppcap_open_live failed: %s", errbuff);
		pcap_freealldevs(alldevs);
		exit(EXIT_FAILURE);
	}
	/*
	 * compile a textual description of the filter into a pseudocode
	 */
	if (pcap_compile(pcap, &filterprog, FILTER, 0, PCAP_NETMASK_UNKNOWN) != 0)
	{
		syslog(LOG_ERR, "pcap_compile failed: %s", pcap_geterr(pcap));
		printf("pcap_compile failed: %s", errbuff);

		pcap_close(pcap);
		pcap_freealldevs(alldevs);
		exit(EXIT_FAILURE);
	}
	/*
	 * Install the filtering program for the calling application
	 */
	if (pcap_setfilter(pcap, &filterprog) != 0)
	{
		syslog(LOG_ERR, "pcap_setfilter failed %s", pcap_geterr(pcap));
		pcap_freealldevs(alldevs);
		pcap_close(pcap);
		exit(EXIT_FAILURE);
	}
	/*
	 * Capturing packets before an error occurs
	 */
	pcap_loop(pcap, PCAP_ERROR, handle_packet, NULL);
	syslog(LOG_INFO, "pcap_loop returned");
	pcap_close(pcap);
	exit(EXIT_FAILURE);
}