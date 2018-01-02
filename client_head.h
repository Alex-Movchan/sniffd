#ifndef CLIENT_HEAD_H
#define CLIENT_HEAD_H

#define MAX_LINE_LEN 128


/*
 * operatiion.c
 */
void	ft_show_count(int ac, char **av, const int sock, char *buff);
void	ft_select(int ac, char **av, int sock);
void	start_sniffd(int ac, char **av);
void	ft_stat(int sock);
void	ft_hellp(int len);

#endif
