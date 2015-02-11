
build: all.c
default: all.c

all.c: ../c/tweetnacl.c ../c-wrap/extras.c
	cat $^ > $@

clean:
	rm all.c

.PHONY: clean
