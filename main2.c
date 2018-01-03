#include "client_head.h"
#include "./daemon_sniff.h"

char		config[20];
pcap_if_t   *alldevs;
char		errbuff[PCAP_ERRBUF_SIZE];
pcap_t		*pcap;
t_nod		*root_nod;
pthread_t	tid;

static int	ft_conect_cli(void)
{
	int					sock;
	struct sockaddr_in	addr;

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		ft_putendl_fd("Error init socket", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)SNIFFD_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		ft_putendl_fd("Error  connect", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
	return (sock);
}

int			main(int ac, char **av)
{
	int		sock;
	int		len;
	char	buff[MAX_LINE_LEN];

	if (ac < 2)
	{
		ft_putendl_fd("Error arguments. Use cli --help", STDERR_FILENO);
		return (1);
	}
	ft_bzero(buff, MAX_LINE_LEN);
	if (!ft_strcmp(av[1], "start"))
		start_sniffd(ac, av);
	else if (!ft_strcmp(av[1], "--help"))
	{
		if (ac != 2)
		{
			ft_putendl_fd("Error count arguments", STDERR_FILENO);
			exit(EXIT_FAILURE);
		}
		ft_hellp(len);
	}
	/* communication with sniffd deamon */
	sock = ft_conect_cli();
	if (!ft_strcmp(av[1], "stat"))
	{
		if (ac != 2)
		{
			ft_putendl_fd("Error count arguments", STDERR_FILENO);
			exit(EXIT_FAILURE);
		}
		send(sock, "stat", 5, 0);
		ft_stat(sock);
	}
	else if (!ft_strcmp(av[1], "select"))
		ft_select(ac, av, sock);
	else if (!ft_strcmp(av[1], "show"))
		ft_show_count(ac, av, sock, buff);
	else if (!ft_strcmp(av[1], "stop"))
	{
		if (ac != 2)
		{
			ft_putendl_fd("Error count arguments", STDERR_FILENO);
			exit(EXIT_FAILURE);
		}
		if (getuid() != 0)
		{
			ft_putendl_fd("Error permission denied", STDERR_FILENO);
			exit(EXIT_FAILURE);
		}
		send(sock, "stop", 5, 0);
	}
	else
		ft_putendl_fd("Error arguments. Use cli --help", STDERR_FILENO);
	return (0);

}

