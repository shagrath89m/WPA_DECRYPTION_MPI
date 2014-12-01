CC=mpicc
CFLAGS="-Wall"
O_OBJS=sha1-sse2.o\
	common.o\
	crypto.o\
	wpa_decrypt.o\
	main.o
LINKF= -lpthread -lssl -lcrypto
debug:clean
	$(CC) $(CFLAGS) -g -c sha1-sse2.S 
	$(CC) $(CFLAGS) -g -c common.c
	$(CC) $(CFLAGS) -g -c crypto.c 
	$(CC) $(CFLAGS) -g -c wpa_decrypt.c 
	$(CC) $(CFLAGS) -g -c main.c 
	$(CC) $(CFLAGS) -g -o wpa_decryption_mpi $(O_OBJS) $(LINKF)
stable:clean
	$(CC) $(CFLAGS)  -c sha1-sse2.S 
	$(CC) $(CFLAGS)  -c common.c
	$(CC) $(CFLAGS)  -c crypto.c 
	$(CC) $(CFLAGS)  -c wpa_decrypt.c 
	$(CC) $(CFLAGS)  -c main.c 
	$(CC) $(CFLAGS)  -o wpa_decryption_mpi  $(O_OBJS) $(LINKF)
clean:
	rm -vfr *~ wpa_decryption_mpi
	rm -vfr *.o