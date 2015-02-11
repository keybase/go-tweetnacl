
build: all.c
default: all.c

go: all.c
	go build

all.c: ../cr.yp.to/tweetnacl.c ../ext/extras.c
	cat $^ > $@

clean:
	rm all.c

.PHONY: clean go
