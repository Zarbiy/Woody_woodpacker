COLOR_RESET = \033[0m
COLOR_RED = \033[91m
COLOR_GREEN = \033[92m
COLOR_YELLOW = \033[93m
COLOR_BOLD = \033[1m

MAKEFLAGS += --no-print-directory

NAME		= woody_woodpacker
SRC			= woody_packer.c init.c function_32bits.c function_64bits.c utils.c crypt.c utils_32.c utils_64.c
OBJ_DIR		= obj
OBJS		= $(OBJ_DIR)/woody_packer.o $(OBJ_DIR)/init.o $(OBJ_DIR)/function_32bits.o $(OBJ_DIR)/function_64bits.o $(OBJ_DIR)/utils.o $(OBJ_DIR)/crypt.o $(OBJ_DIR)/utils_32.o $(OBJ_DIR)/utils_64.o

CC			= cc
CFLAGS		= -g3 -Wall -Wextra -Werror
CHFLAGS		= -I include

RM			= rm -f
DIR_DUP		= mkdir -p $(@D)

NAME_FILE = bonjour.c

NAME_EXEC_64 = exec64
NAME_EXEC_32 = exec32

NAME_PACKER = woody

all: $(NAME)

$(NAME): $(OBJS)
	@$(CC) $(OBJS) -o $(NAME)
	@printf "$(COLOR_RED)$(COLOR_BOLD)Compilation réussie !$(COLOR_RESET)\n"

$(OBJ_DIR)/%.o: %.c woody_packer.h
	@$(DIR_DUP)
	@$(CC) $(CFLAGS) $(CHFLAGS) -c -o $@ $<

exec:
	cc -m32 $(NAME_FILE) -o $(NAME_EXEC_32)
	cc $(NAME_FILE) -o $(NAME_EXEC_64)

show_info_elf:
	readelf -h $(NAME_EXEC_64)
	@printf "$(COLOR_RED)  --------------------------------  $(COLOR_RESET)\n"
	readelf -h $(NAME_PACKER)

show_ptload:
	readelf -l $(NAME_EXEC_64)
	@printf "$(COLOR_RED)  --------------------------------  $(COLOR_RESET)\n"
	readelf -l $(NAME_PACKER)

show_elf:
	readelf -S $(NAME_EXEC_64)
	@printf "$(COLOR_RED)  --------------------------------  $(COLOR_RESET)\n"
	readelf -S $(NAME_PACKER)

show_dynamic:
	readelf -d $(NAME_EXEC_64)
	@printf "$(COLOR_RED)  --------------------------------  $(COLOR_RESET)\n"
	readelf -d $(NAME_PACKER)

all_show: show_info_elf show_ptload show_elf show_dynamic

clean:
	@$(RM) $(OBJS)

fclean: clean
	@$(RM) $(NAME) $(NAME_EXEC_32) $(NAME_EXEC_64) $(NAME_PACKER)


re: fclean all