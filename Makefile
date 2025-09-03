# Makefile for GPS Tracker Server
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
TARGET = gps_server
SRCS = main_file.c login_map.c
OBJS = $(SRCS:.c=.o)
HEADERS = conn.h login_map.h

# Default target
all: $(TARGET)

# Create executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Compile object files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build files
clean:
	rm -f $(TARGET) $(OBJS)

# Run the server
run: $(TARGET)
	./$(TARGET)

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: clean all

# Phony targets
.PHONY: all clean run debug
