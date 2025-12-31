CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS = -lseccomp
TARGET = runner/launcher
SRC = runner/launcher.c runner/telemetry.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)


clean:
	rm -f $(TARGET)
	rm -f /tmp/sandbox_exec_*
