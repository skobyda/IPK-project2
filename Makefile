all:
	gcc -Wall -pedantic -o ipk-scan ipk-scan.c -lpcap -Wno-deprecated-declarations

clean:
	rm -rf ipk-scan *~

