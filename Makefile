CC=gcc
CFLAGS=-Wall
LIBS=-lpam

all: pam_realm.so

pam_realm.so: pam_realm.o
	$(CC) -o $@ -shared $< $(LIBS)

clean:
	rm -f *.o *.so
