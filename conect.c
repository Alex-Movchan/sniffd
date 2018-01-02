#include "daemon_sniff.h"

int		sendall(int sock, char *buf, int len, int flags)
{
	int total = 0;
	int n = 0;

	while(total < len)
	{
		n = (int)send(sock, buf+total, len-total, flags);
		if(n == -1)
			break ;
		total += n;
	}
	return (n == -1 ? -1 : total);
}

int		bind_passive_socket(int * sock)
{
	struct sockaddr_in	sin;
	int 				newsock, optval;
	socklen_t			optlen;

	memset(&sin.sin_zero, 0, 8);
	sin.sin_port = htons(SNIFFD_PORT);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	if ((newsock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		return -1;
	optval = 1;
	optlen = sizeof(int);
	setsockopt(newsock, SOL_SOCKET, SO_REUSEADDR, &optval, optlen);
	if (bind(newsock, (struct sockaddr *) &sin, sizeof(struct sockaddr_in)) < 0)
		return -1;
	if (listen(newsock, SOMAXCONN) < 0)
		return -1;
	*sock = newsock;
	return 0;
}

int 	accept_connections(const int master)
{
	int					proceed, slave, retval;
	struct sockaddr_in	client;
	socklen_t			clilen;

	proceed = 1;
	retval = 0;
	while ((proceed == 1))
	{
		clilen = sizeof(client);
		slave = accept(master, (struct sockaddr *) &client, &clilen);
		if (slave < 0)
		{
			if (errno == EINTR)
				continue;
			syslog(LOG_ERR, "accept() failed");
			proceed = 0;
			retval = -1;
		}
		else
		{
			retval = handle_connec(slave);
			if (retval)
				proceed = 0;
		}
		close(slave);
	}
	return retval;
}

void	*ft_conect(void *arg)
{
	int		sock;

	if (bind_passive_socket(&sock) != 0)
	{
		syslog(LOG_ERR, "bind() failed");
		if (pcap)
			pcap_close(pcap);
		exit(EXIT_FAILURE);
	}
	while (1)
		accept_connections(sock);
}