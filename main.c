#include "daemon_sniff.h"

char		config[20];
pcap_if_t   *alldevs;
char		errbuff[PCAP_ERRBUF_SIZE];
pcap_t		*pcap;
t_nod		*root_nod;
pthread_t	tid;


int			main(int ac, char **av)
{
	char *dev;
	if (ac > 2)
	{
		ft_putendl_fd("Error count argument", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
	/* check for super administrator privileges */
	if (getuid() != 0)
	{
		ft_putendl_fd("Error permission denied", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
	dev = start_config(av[1]);
	start_daemon(dev);
}
