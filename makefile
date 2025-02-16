all : user1 user2

user1 :user1.c ksocket.h ksocket.c
	gcc -Wall -o user1 user1.c ksocket.c

user2 :user2.c ksocket.h ksocket.c
	gcc -Wall -o user2 user2.c ksocket.c

clean:
	rm -f user1 user2 output.txt