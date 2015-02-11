
build: tweetnacl.o
default: tweetnacl.o

all.c: tweetnacl.c extras.c
	cat $^ > $@

CFLAGS = -g -O2 -Wall

tweetnacl.o: all.c tweetnacl.h
	gcc $(CFLAGS) -o $@ -c $< 

clean:
	rm -rf *.o all.c

.PHONY: clean
