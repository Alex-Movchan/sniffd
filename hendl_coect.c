#include "daemon_sniff.h"

static void	hendle_select(char *readbuf)
{

	pcap_close(pcap);
	pcap = NULL;
	ft_dell_tree(root_nod);
	root_nod = NULL;
	ft_bzero(config, ft_strlen(config));
	ft_strcpy(config, readbuf + 6);
	/* stop pthread sniffing */
	if (pthread_cancel(tid))
	{
		syslog(LOG_ERR, "Can not cancel thread");
		pcap_freealldevs(alldevs);
		exit(EXIT_FAILURE);
	}
	/* create a thread for sniffing */
	if (pthread_create(&tid, NULL, ft_sniff, 0))
	{
		syslog(LOG_ERR, "Can not create thread");
		pcap_freealldevs(alldevs);
		exit(EXIT_FAILURE);
	}
}

static void	handle_show(const int sock, char *readbuf)
{
	t_nod	*lst;
	char	*nbr = NULL;

	lst =ft_search_intree(readbuf + 4, root_nod);
	if (lst)
	{
		nbr = ft_itoa(lst->count);
		send(sock, nbr, ft_strlen(nbr), 0);
		ft_strdel(&nbr);
	}
	else
		send(sock, "ip not found", 13, 0);
}

int		handle_connec(const int sock)
{
	t_nod		*lst;
        char		*nbr = NULL;
	char		readbuf[MAX_CONECT_BUFF];
	int		len;

	len = (int)recv(sock,readbuf, MAX_CONECT_BUFF, 0);
	readbuf[len] = '\0';
	if (!ft_strcmp(readbuf, "stop"))
	{
		if (pcap)
			pcap_close(pcap);
		pcap_freealldevs(alldevs);
		ft_dell_tree(root_nod);
		exit(EXIT_SUCCESS);
	}
	else if (!ft_strcmp(readbuf, "stat"))
	{
		ft_tree_traversal(root_nod, sock);
		return (1);
	}
	else if (!ft_strncmp(readbuf, "show", 4))
	{
		handle_show(sock, readbuf);
		return (1);
	}
	else if (!ft_strncmp(readbuf, "select", 6))
		hendle_select(readbuf);
	return (1);
}
