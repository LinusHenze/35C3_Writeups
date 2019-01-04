CC = clang

.PHONY: run clean

pillow_exploit: exploit.c shelld.mig
	mig shelld.mig
	gcc exploit.c shelldUser.c -o exploit

clean:
	rm -f exploit shelld.h shelldServer.c shelldUser.c

run: pillow_exploit
	sandbox-exec -f sandbox.sb -DBINARY=$(shell pwd)/exploit ./exploit