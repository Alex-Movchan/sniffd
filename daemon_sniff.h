#ifndef DAEMON_SNIFF_H
#define DAEMON_SNIFF_H

#include <syslog.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <pthread.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include "../libft/libft.h"
#include "ft_net.h"

#define FILTER "ip"
#define LOCKFILE "/var/run/sniffd.pid"
#define CONFIG_FILE "/etc/sniffd.conf"
#define LOG_PREFIX "/dev/sniffd.log"
#define LOCKMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
#define MAX_LEN_BUFF 65536
#define SNIFFD_PORT 30333
#define MAX_CONECT_BUFF 128
#define UNUSED(x) ((void)(x))

typedef struct		s_nod
{
	struct s_nod	*left;
	struct s_nod	*right;
	char			ip_adrr[17];
	int				count;
}					t_nod;

extern pcap_if_t	*alldevs;
extern pcap_t		*pcap;
extern char			errbuff[PCAP_ERRBUF_SIZE];
extern t_nod		*root_nod;
extern pthread_t	tid;
extern char			config[20];

void				ft_pthread_config(void);
int					ft_already_running(void);
void				daemonize(void);
void				*ft_sniff(void *arg);
void				ft_read_config();
void				*ft_conect(void *arg);
void				ft_add_tree(t_nod *pack, t_nod **root);
void				ft_tree_traversal(t_nod *nod, int sock);
t_nod				*ft_search_intree(char *ip, t_nod *root);
int					sendall(int s, char *buf, int len, int flags);
void				start_daemon(char *str);
char				*start_config(char *str);
int					handle_connec(const int sock);


#endif
