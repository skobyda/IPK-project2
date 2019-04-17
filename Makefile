all:
	gcc -Wall -pedantic -o ipk ipk-scann.c -lpcap -Wno-deprecated-declarations

clean:
	rm -rf ipk-scann *~

