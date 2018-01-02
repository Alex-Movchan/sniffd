#include "daemon_sniff.h"

extern char			config[20];

static void handle_packet(uint8_t* user, const struct pcap_pkthdr *hdr, const uint8_t* bytes)
{
	t_nod				*pack;
	struct iphdr		*ip_header;
	struct sockaddr_in	source;

	UNUSED(user);
	ip_header = (struct iphdr*)(bytes + sizeof(struct ethhdr));
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip_header->saddr;
	if (!(pack = (t_nod*)malloc(sizeof(t_nod))))
	{
		syslog(LOG_ERR, "Error malloc");
		pcap_freealldevs(alldevs);
		pcap_close(pcap);
		exit(EXIT_FAILURE);
	}
	pack->left = NULL;
	pack->right = NULL;
	ft_strncpy(pack->ip_adrr, inet_ntoa(source.sin_addr), 16);
	pack->count = 1;
	ft_add_tree(pack, &root_nod);
}

bool	list_devs(void)
{
	int			errcode;
	pcap_if_t	*currdev;

	errcode = pcap_findalldevs(&alldevs, errbuff);
	if (errcode != 0)
	{
		printf("pcap_findalldevs failed: %s", errbuff);

		syslog(LOG_ERR, "pcap_findalldevs failed: %s", errbuff);
		exit(EXIT_FAILURE);
	}
	currdev = alldevs;
	while (currdev)
	{
		if (!ft_strcmp(currdev->name, config))
			return (true);
		currdev = currdev->next;
	}
	return (false);
}

void	*ft_sniff(void *arg)
{
	struct bpf_program	filterprog;

	if (list_devs() == false)
	{
		syslog(LOG_ERR, "Error iface");
		pcap_freealldevs(alldevs);
		exit(EXIT_FAILURE);
	}
	if (!(pcap = pcap_open_live(config, MAX_LEN_BUFF, 1, 100, errbuff)))
	{
		syslog(LOG_ERR, "ppcap_open_live failed: %s", errbuff);
		pcap_freealldevs(alldevs);
		exit(EXIT_FAILURE);
	}
	/*
	 * PCAP_T pcap_open_live (char *device, int snaplen, boolean promisc, int to_ms, char *ebuf)
	 * Функция предназначена для получения дескриптора структуры захвата пакетов, используемой для записии
	 * просмотра пакетов, передаваемых по сети (режим он-лайн). Device – это строка, задающая открываемый
	 * сетевой адаптер. Переменная Snaplen задает максимальное число захватываемых байт. Флаг Promisc переводит
	 * адаптер в режим работы “прием всех входящих пакетов”. Переменная to_ms содержит время ожидания пакета
	 * в миллисекундах. При возникновении ошибки функция возвращает значение NULL и записывает строку,
	 * характеризующую ошибку, в буфер ebuf.
	 */
	if (pcap_compile(pcap, &filterprog, FILTER, 0, PCAP_NETMASK_UNKNOWN) != 0)
	{
		syslog(LOG_ERR, "pcap_compile failed: %s", pcap_geterr(pcap));
		printf("pcap_compile failed: %s", errbuff);

		pcap_close(pcap);
		pcap_freealldevs(alldevs);
		exit(EXIT_FAILURE);
	}
	/*
	 *  INT pcap_compile (pcap_t *p, struct bpf_program *fp, char *str, int optimize, bpf_u_int32 *netmask)
	 *  Функция компилирует текстовое описание фильтра str в псевдокод (см. далее).
	 *  Переменная fp содержит указатель на структуру bpf_program и заполняется функцией pcap_compile().
	 *  Переменная optimize определяет наличие оптимизации псевдокода компилируемой программы.
	 *  Переменная netmask задает сетевую маску локальной сети
	 */
	if (pcap_setfilter(pcap, &filterprog) != 0)
	{
		syslog(LOG_ERR, "pcap_setfilter failed %s", pcap_geterr(pcap));
		pcap_freealldevs(alldevs);
		pcap_close(pcap);
		exit(EXIT_FAILURE);
	}
	/*
	 * INT pcap_setfilter (pcap_t *p, struct bpf_program *fp)
	 * Функция устанавливает программу фильтра для вызвавшего ее приложения.
	 * Переменная fp содержит указатель на программу фильтра,
	 * полученный при вызове функции pcap_compile().
	 */
	pcap_loop(pcap, -1, handle_packet, NULL);
	/*
	 *   INT pcap_loop (pcap_t *p, int cnt, pcap_handler callback, u_char *user)
	 *   Действия данной функции аналогичны pcap_dispatch(), за тем исключением,
	 *   что она считывает пакеты до тех пор, пока не обнулится счетчик cnt или не возникнет ошибка,
	 *   и не прекращает работы при окончании времени ожидания.
	 *   Отрицательное значение cnt заставит функцию работать бесконечно, до возникновения первой ошибки.
	 */
	syslog(LOG_INFO, "pcap_loop returned");
	pcap_close(pcap);
	exit(EXIT_FAILURE);
}