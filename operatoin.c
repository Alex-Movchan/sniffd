#include "client_head.h"

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
