COLOR_RESET = \033[0m
COLOR_RED = \033[91m
COLOR_GREEN = \033[92m
COLOR_YELLOW = \033[93m
COLOR_BOLD = \033[1m

MAKEFLAGS += --no-print-directory

NAME		= woody_woodpacker
SRC			= woody_packer.c
OBJ_DIR		= obj
OBJS		= $(OBJ_DIR)/woody_packer.o

CC			= cc
CFLAGS		= #-Wall -Wextra -Werror
CHFLAGS		= -I include

RM			= rm -f
DIR_DUP		= mkdir -p $(@D)

all: $(NAME)

$(NAME): $(OBJS)
	@$(CC) $(OBJS) -o $(NAME)
	@printf "$(COLOR_RED)$(COLOR_BOLD)Compilation réussie !$(COLOR_RESET)\n"

$(OBJ_DIR)/%.o: %.c
	@$(DIR_DUP)
	@$(CC) $(CFLAGS) $(CHFLAGS) -c -o $@ $<

clean:
	@$(RM) $(OBJS)

fclean: clean
	@$(RM) $(NAME)

re: fclean all
