CC=gcc
CFLAGS=-I. -Wall -Wextra
DEPS = PcapGenerator.h
OBJ = PcapGenerator.o
OUTPUT = PcapGenerator

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

default: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) -o $(OUTPUT)

clean:
	rm $(OUTPUT)
	rm *.o
