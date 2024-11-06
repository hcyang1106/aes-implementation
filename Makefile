all:
	gcc -Isrc -Itest src/main.c src/AES.c test/test.c -o aes