#include "daemon_sniff.h"


int		ft_ipcmp(char *ip1, char *ip2)
{
	int		nbr1;
	int		nbr2;

	nbr1 = ft_atoi(ip1);
	nbr2 = ft_atoi(ip2);
	if (nbr1 == nbr2 && *ip1 && *ip2)
	{
		while (*ip1)
		{
			if (*ip1 == '.')
			{
				ip1++;
				break;
			}
			ip1++;
		}
		while (*ip2)
		{
			if (*ip2 == '.')
			{
				ip2++;
				break;
			}
			ip2++;
		}
		return (ft_ipcmp(ip1, ip2));
	}
	return (nbr1 - nbr2);
}

void	ft_add_tree(t_nod *pack, t_nod **root)
{
	t_nod	*nod;
	int		flag;

	if (!(*root))
		*root = pack;
	else
	{
		nod = *root;
		while (nod)
		{

			if (!(flag = ft_ipcmp(nod->ip_adrr, pack->ip_adrr)))
			{
				nod->count += pack->count;
				free(pack);
				break;
			}
			else if (flag > 0)
			{
				if (!nod->left)
				{
					nod->left = pack;
					break;
				}
				nod = nod->left;
			}
			else
			{
				if (!nod->right)
				{
					nod->right = pack;
					break;
				}
				nod = nod->right;
			}
		}
	}
}

t_nod	*ft_search_intree(char *ip, t_nod *root)
{
	t_nod	*nod;
	int 	flag;

	nod = root;
	while (nod)
	{
		if (!(flag = ft_ipcmp(nod->ip_adrr, ip)))
			break ;
		if (flag > 0)
			nod = nod->left;
		else
			nod = nod->right;
	}
	return (nod);
}
char	*ft_strcpych(char *s1, char *s2, char c)
{
	int i;

	i = -1;
	while (s2[++i])
		s1[i] = s2[i];
	s1[i++] = c;
	s1[i] = '\0';
	return (s1);
}

void	ft_tree_traversal(t_nod *nod, int sock)
{
	char	str[17];

	if (nod)
	{
		ft_strcpych(str, nod->ip_adrr, 'a');
		sendall(sock, str, (int)ft_strlen(str), 0);
		ft_tree_traversal(nod->right, sock);
		ft_tree_traversal(nod->left, sock);
	}
}

void	ft_dell_tree(t_nod *lst)
{
	if (lst)
	{
		ft_dell_tree(lst->left);
		ft_dell_tree(lst->right);
		free(lst);
	}

}