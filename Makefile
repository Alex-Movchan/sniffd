NAME_P = sniffd
NAME_C = cli

G = gcc
FLAG_P = -pthread
FLAGS = -lpcap -lrt

SRC_P =	main.c \
	binary_tree.c \
	conect.c \
	daemonize.c \
	ft_sniff.c \
	hendl_coect.c \
	start_daemon.c

OBJ_P = $(SRC_P:.c=.o)

SRC_C =	binary_tree.c \
	conect.c \
	daemonize.c \
	ft_sniff.c \
 	hendl_coect.c \
	start_daemon.c \
 	operatoin.c \
	main2.c

OBJ_C= $(SRC_C:.c=.o)

LIBFT = libft/libft.a

all: $(NAME_P) $(NAME_C)

$(NAME_P): $(OBJ_P)
	@make -C libft/
	$(G)  -o $@ $(OBJ_P) $(LIBFT) $(FLAGS) $(FLAG_P)

$(NAME_C): $(OBJ_C)
	$(G)  -o $@ $(OBJ_C) $(LIBFT) $(FLAGS) $(FLAG_P)

%.o: %.c
	$(G) $(FLAGS) -c $< -o $@

clean:
	@make -C libft/ clean
	@rm -f $(OBJ_P)
	@rm -f $(OBJ_C)

fclean: clean
	@make -C libft/ fclean
	@rm -f $(NAME_P) $(NAME_C)

re: fclean all
	@make -C libft/ re
