##
## EPITECH PROJECT, 2025
## G-CNA-500-COT-5-1-cryptography-25
## File description:
## Makefile
##

NAME	= my_pgp

SRCDIR	= src
INCDIR	= include

SOURCES	= $(SRCDIR)/main.cpp \
		  $(SRCDIR)/convert.cpp \
		  $(SRCDIR)/xor.cpp \
		  ${SRCDIR}/AES.cpp \
		  ${SRCDIR}/handle_pgp_aes.cpp \
		  ${SRCDIR}/handle_pgp_xor.cpp \
		  ${SRCDIR}/RSA.cpp

OBJECTS = $(SOURCES:.cpp=.o)

CXX		= g++
CXXFLAGS = -Wall -Wextra -Werror -I$(INCDIR) -std=c++17
LDFLAGS = -lgmp

all: $(NAME)

$(NAME): $(OBJECTS)
	$(CXX) -o $(NAME) $(OBJECTS) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
