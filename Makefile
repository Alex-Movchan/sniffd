NAME_P = sniffd
NAME_C = cli

G = gcc
FLAGS = -lpcap -lrt -pthread

SRC_P =   main.c \
          binary_tree.c \
          conect.c \
          daemonize.c \
          ft_sniff.c \
          hendl_coect.c \
          start_daemon.c

OBJ_NAME_P = $(SRC_NAME_P:.c=.o)

SRC_C =    main_cli.c \
           binary_tree.c \
           conect.c \
           daemonize.c \
           ft_sniff.c \
           hendl_coect.c \
           start_daemon.c \
           operatoin.c

SRC_C = $(SRC_P:.c=.o)

LIBFT = libft/libft.a

all: $(NAME_P) $(NAME_C)
$(NAME_P): $(OBJ_P)
	@make -C libft/
	@$(G) $(FLAGS) -o $@ $(OBJ_P) $(LIBFT)

$(NAME_C): $(OBJ_C)
	@$(G) $(FLAGS) -o $@ $(OBJ_C) $(LIBFT)

%.o: %.c
	$(G) $(FLAGS) -c $< -o $@

clean:
	@make -C libft/ clean
	@rm -f $(OBJ_P)
	@rm -f $(OBJ_C)

fclean: clean
	@make -C libft/ fclean
	@rm -f $(NAME_P) $(NAME_C)
