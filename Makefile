.PHONY: manager 


sender: bpf_sender.c
	clang -O2 -g -Wall -target bpf -c bpf_sender.c -o bpf_sender.o
manager:
	$(MAKE) -C manager
	cp -f manager/bpf_map_manager .
clean:
	rm -f bpf_sender.o
receiver: receiver.c
	gcc receiver.c -o receiver -Wall -O2 -lpcap -lpthread

