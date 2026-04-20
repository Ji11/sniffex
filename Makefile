CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LIBS = -lpcap -lmysqlclient
TARGET = sniffex
SRC = sniffex.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
