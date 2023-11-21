CC = gcc
CFLAGS = -g -Wall -Wextra -Wshadow -Wunreachable-code \
		 -Wredundant-decls -Wmissing-declarations \
		 -Wold-style-definition -Wmissing-prototypes \
		 -Wdeclaration-after-statement -Wno-return-local-addr \
		 -Wunsafe-loop-optimizations -Wuninitialized -Werror \
		 -Wno-unused-parameter -pthread
PROG = thread_crypt
INCLUDES = thread_crypt.h

all: $(PROG)

$(PROG): $(PROG).o
	$(CC) $(CFLAGS) -o $@ $^ -lcrypt

$(PROG).o: $(PROG).c $(INCLUDES)
	$(CC) $(CFLAGS) -c $<

clean cls:
	rm -f $(PROG) *.o *.out \#*

tar:
	tar cvfa lab3_${LOGNAME}.tar.gz *.[ch] [mM]akefile

val:
	valgrind -v --tool=memcheck --leak-check=full --track-origins=yes ./thread_crypt -i words10.txt -a5 -t20
