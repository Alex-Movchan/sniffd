#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pcap.h>
#include <fcntl.h>
#include "../daemon_sniff/daemon_sniff.h"

#define SNIFFD_PORT 30333
#define LOCKMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
#define CONFIG_FILE "/etc/sniffd.conf"
#define MAX_LINE_LEN 128


void	ft_stat(int sock)
{
	char	buff[MAX_LINE_LEN];
	ssize_t len;
	char	**map;
	char	*dst;
	char	*leaks;

	dst = NULL;
	while(1)
	{
		leaks = dst;
		ft_bzero(buff, MAX_LINE_LEN);
		if ((len = recv(sock, buff, MAX_LINE_LEN, 0)) < 0)
		{
			ft_putendl_fd("Error recv", STDERR_FILENO);
			exit(EXIT_FAILURE);
		}
		if (len == 0)
			break;
		dst = dst != NULL ? ft_strjoin(dst, buff) : ft_strdup(buff);
		ft_strdel(&leaks);
	}
	if (!(map = ft_strsplit(dst, 'a')))
		return;
	ft_strdel(&dst);
	for(int i = 0; map[i]; i++)
	{
		ft_putendl(map[i]);
		ft_strdel(&(map[i]));
	}
	free(map);
}



void	start_sniffd(int ac, char **av)
{
	char	*dev;

	if (getuid() != 0)
	{
		ft_putendl_fd("Error permission denied", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
	if (ac > 3)
	{
		ft_putendl_fd("Error count arguments", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
	if (ft_already_running())
	{
		ft_putendl_fd( "The daemon is already running", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
	dev = start_config(av[2]);
	start_daemon(dev);
}

int		ft_conect_cli()
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

void	ft_select(int ac, char **av, int sock)
{
	char	*buf;

	if (ac != 4)
	{
		ft_putendl_fd("Error count arguments", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
	if (ft_strcmp(av[2], "iface"))
	{
		ft_putendl_fd("Arguments must be: select iface [iface]", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
	buf = ft_strjoin(av[1], start_config(av[3]));
	send(sock, buf, ft_strlen(buf), 0);
	ft_strdel(&buf);
}

void	ft_show_count(int ac, char **av, const int sock, char *buff)
{
	char	*comand;
	int		len;

	if (ac != 4 || ft_strcmp(av[3], "count"))
	{
		ft_putendl_fd("Error  arguments", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
	comand = ft_strjoin(av[1], av[2]);
	send(sock, comand, ft_strlen(comand), 0);
	if ((len = recv(sock, buff, MAX_LINE_LEN, 0)) < 0)
	{
		ft_putendl_fd("Error recv", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
	ft_putendl(buff);
}

void	ft_hellp(int len)
{
	int		fd;
	char	buff[1024];

	if ((fd = open("./help.txt", O_RDONLY)) < 0)
	{
		ft_putendl_fd("Error opening", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
	ft_bzero(buff, 1024);
	while(len = read(fd, buff, 1024) > 0)
	{
		ft_putstr(buff);
		ft_bzero(buff, 1024);
	}
	ft_putchar('\n');
	exit(EXIT_SUCCESS);

}

int main(int ac, char **av)
{
	int		sock;
	int		len;
	char	buff[MAX_LINE_LEN];

	if (ac < 2)
		return (1);
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

