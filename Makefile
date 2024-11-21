
NAME = pestilence

ASM = nasm
LD = ld

ASMFLAGS = -f elf64

SRC = pestilence.asm routine.asm

OBJ = $(SRC:.asm=.o)

RM	=	rm -f

all: $(NAME)

$(OBJ): $(SRC)
	$(ASM) $(ASMFLAGS) $< -o $@

$(NAME): $(OBJ)
		$(LD) $< -o $@

clean:
		$(RM) $(OBJ)

fclean:		clean
			$(RM) $(NAME)

re:	fclean all

.PHONY: all clean fclean re
