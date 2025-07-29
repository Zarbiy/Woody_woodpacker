COLOR_RESET = \033[0m
COLOR_RED = \033[91m
COLOR_GREEN = \033[92m
COLOR_YELLOW = \033[93m
COLOR_BOLD = \033[1m

MAKEFLAGS += --no-print-directory

NAME		= woody_woodpacker
SRC			= woody_packer.c init.c function_32bits.c function_64bits.c utils.c
OBJ_DIR		= obj
OBJS		= $(OBJ_DIR)/woody_packer.o $(OBJ_DIR)/init.o $(OBJ_DIR)/function_32bits.o $(OBJ_DIR)/function_64bits.o $(OBJ_DIR)/utils.o

CC			= cc
CFLAGS		= -g3 #-Wall -Wextra -Werror
CHFLAGS		= -I include

RM			= rm -f
DIR_DUP		= mkdir -p $(@D)

NAME_FILE = bonjour.c

NAME_EXEC_64 = exec64
NAME_EXEC_32 = exec32

all: $(NAME)

$(NAME): $(OBJS) woody_packer.h
	@$(CC) $(OBJS) -o $(NAME)
	@printf "$(COLOR_RED)$(COLOR_BOLD)Compilation réussie !$(COLOR_RESET)\n"

$(OBJ_DIR)/%.o: %.c
	@$(DIR_DUP)
	@$(CC) $(CFLAGS) $(CHFLAGS) -c -o $@ $<

exec:
	cc -m32 $(NAME_FILE) -o $(NAME_EXEC_32)
	cc $(NAME_FILE) -o $(NAME_EXEC_64)

clean:
	@$(RM) $(OBJS)

fclean: clean
	@$(RM) $(NAME) $(NAME_EXEC_32) $(NAME_EXEC_64) woody_test


re: fclean all
