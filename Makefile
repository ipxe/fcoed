CFLAGS = -O3 -Wall -Wextra -Werror
HEADERS = $(wildcard *.h)
OBJECTS = $(patsubst %.c,%.o,$(wildcard *.c))

all : fcoed

clean :
	rm -f *.o
	rm -f fcoed

fcoed : $(OBJECTS)
	$(CC) -o $@ $^ -lpcap

%.o : %.c $(HEADERS)
	$(CC) $(CFLAGS) -o $@ -c $<
