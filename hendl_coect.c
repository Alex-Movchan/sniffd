#include "daemon_sniff.h"

static void	hendle_select(const int sock, char *readbuf)
{

	pcap_close(pcap);
	pcap = NULL;
	ft_dell_tree(root_nod);
	root_nod = NULL;
	ft_bzero(config, ft_strlen(config));
	ft_strcpy(config, readbuf + 6);
	if (pthread_cancel(tid))
	{
		syslog(LOG_ERR, "Can not cancel thread");
		pcap_freealldevs(alldevs);
		exit(EXIT_FAILURE);
	}
	if (pthread_create(&tid, NULL, ft_sniff, 0))
	{
		syslog(LOG_ERR, "Can not create thread");
		pcap_freealldevs(alldevs);
		exit(EXIT_FAILURE);
	}
}

static void	handle_stat(const int sock, char *readbuf)
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
	char		readbuf[MAX_CONECT_BUFF];
	int			len;

	len = (int)recv(sock,readbuf, MAX_CONECT_BUFF, 0);
	readbuf[len] = '\0';
	if (!ft_strcmp(readbuf, "stop"))
	{
		if (pcap)
			pcap_close(pcap);
		pcap_freealldevs(alldevs);//dell_tree
		exit(EXIT_SUCCESS);
	}
	if (!ft_strcmp(readbuf, "stat"))
	{
		ft_tree_traversal(root_nod, sock);
		return (1);
	}
	if (!ft_strncmp(readbuf, "show", 4))
	{
		hendle_select(sock, readbuf);
		return (1);
	}
	if (!ft_strncmp(readbuf, "select", 6))
		hendle_select(sock, readbuf);

	return (1);
}
