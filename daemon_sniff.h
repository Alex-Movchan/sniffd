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
#include "libft/libft.h"
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

extern pcap_if_t	*alldevs; //structure of available devices
extern pcap_t		*pcap;
extern char			errbuff[PCAP_ERRBUF_SIZE]; //error buffer for pcap
extern t_nod		*root_nod; //pointer to the root of a tree
extern pthread_t	tid; //flow identifier sniffs
extern char			config[20]; //configuration string




/*
 * daemonize.c
 */
int					ft_already_running(void);
/* check for the presence of a daemon in the system, file lock */
void				daemonize(void);
/* demonization of the process */

/*
 * sniff.c
 */
void				*ft_sniff(void *arg);
/* sniffs a packets */

/*
 * conect.c
 */
void				*ft_conect(void *arg);
/* creates a link with command line interface */
int					sendall(int s, char *buf, int len, int flags);
/* sending a message */

/*
 * binary_tree.c
 */
void				ft_add_tree(t_nod *pack, t_nod **root);
/* addition of an element of a tree */
void				ft_tree_traversal(t_nod *nod, int sock);
/* tree traversal */
t_nod				*ft_search_intree(char *ip, t_nod *root);
/* searching for an element in the tree */
void				ft_dell_tree(t_nod *lst);

/*
 * start_daemon.c
 */
void				start_daemon(char *str);
/* preparation for demonization of the process */
char				*start_config(char *str);
/*  checking the startup configuration */

/*
 * handle_conect
 */
int					handle_connec(const int sock);
/* receiving requests and sending replies */


#endif
