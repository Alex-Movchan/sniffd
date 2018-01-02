#include "daemon_sniff.h"

char		config[20];
pcap_if_t   *alldevs;
char		errbuff[PCAP_ERRBUF_SIZE];
pcap_t		*pcap;
t_nod		*root_nod;
pthread_t	tid;

char	*start_config(char *str)
{
	pcap_if_t   *alldevs, *lst;
	char        errbuff[PCAP_ERRBUF_SIZE];

	if(pcap_findalldevs(&alldevs, errbuff) != 0)
	{
		ft_putstr_fd("pcap_findalldevs failed:", STDERR_FILENO);
		ft_putendl_fd(errbuff, STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
	lst = alldevs;
	if (str)
	{
		while (lst)
		{
			if (!ft_strcmp(str, lst->name))
				break;
			lst = lst->next;
		}
		if (lst)
			return (lst->name);
		else
		{
			ft_putstr_fd("Device not found: ", STDERR_FILENO);
			ft_putendl_fd(str, STDERR_FILENO);
			lst = alldevs;
			ft_putendl_fd("Try these devices:", STDERR_FILENO);
			while (lst)
			{
				ft_putendl_fd(lst->name, STDERR_FILENO);
				lst = lst->next;
			}
			exit(EXIT_FAILURE);
		}
	}
	else
	{
		while (lst)
		{
			if (!ft_strcmp(lst->name, "eth0"))
				break;
			lst = lst->next;
		}
		if (lst)
			return (lst->name);
		else
			return (alldevs->name);
	}
}

void		start_daemon(char *str)
{

	daemonize();
	if (ft_already_running())
	{
		syslog(LOG_ERR, "The daemon is already running");
		exit(EXIT_FAILURE);
	}
	pcap = NULL;
	root_nod = NULL;
	ft_strcpy(config, str);
	if (pthread_create(&tid, NULL, ft_sniff, 0))
	{
		syslog(LOG_ERR, "Can not create thread");
		exit(EXIT_FAILURE);
	}
	ft_conect(NULL);
}

//int			main(int ac, char **av)
//{
//	char *dev;
//	if (ac > 2)
//	{
//		ft_putendl_fd("Error count argument", STDERR_FILENO);
//		exit(EXIT_FAILURE);
//	}
//	if (getuid() != 0)
//	{
//		ft_putendl_fd("Error permission denied", STDERR_FILENO);
//		exit(EXIT_FAILURE);
//	}
//	dev = start_config(av[2]);
//	start_daemon(dev);
//}