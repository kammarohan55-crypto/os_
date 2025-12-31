CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = runner/launcher
SRC = runner/launcher.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)
	rm -f /tmp/sandbox_exec_*
