# Makefile for GPS Tracker Server

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
LDFLAGS = -lm

# Directories
SRC_DIR = .
OBJ_DIR = obj
BIN_DIR = bin

# Source files
SOURCES = main_file.c login_map.c json_writer.c offline_data.c
OBJECTS = $(SOURCES:%.c=$(OBJ_DIR)/%.o)
TARGET = $(BIN_DIR)/tracker

# Header files
HEADERS = conn.h login_map.h json_writer.h offline_data.h

# Default target
all: $(TARGET)

# Create directories
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Build the main executable
$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo "Build complete: $@"

# Compile source files to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS) | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	rm -f *.o tracker
	@echo "Clean complete"

# Install (copy to system path)
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	@echo "Installed to /usr/local/bin/"

# Uninstall
uninstall:
	sudo rm -f /usr/local/bin/tracker
	@echo "Uninstalled from /usr/local/bin/"

# Run the tracker
run: $(TARGET)
	./$(TARGET)

# Debug build
debug: CFLAGS += -DDEBUG -O0
debug: $(TARGET)

# Release build
release: CFLAGS += -O2 -DNDEBUG
release: clean $(TARGET)

# Check for compilation errors
check:
	@echo "Checking compilation..."
	$(CC) $(CFLAGS) -c $(SOURCES)
	@echo "All files compile successfully"

# Show help
help:
	@echo "Available targets:"
	@echo "  all      - Build the tracker (default)"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to /usr/local/bin/"
	@echo "  uninstall- Remove from /usr/local/bin/"
	@echo "  run      - Build and run the tracker"
	@echo "  debug    - Build with debug flags"
	@echo "  release  - Build optimized release version"
	@echo "  check    - Check compilation without linking"
	@echo "  help     - Show this help"

# Dependencies
$(OBJ_DIR)/main_file.o: main_file.c conn.h login_map.h json_writer.h offline_data.h
$(OBJ_DIR)/login_map.o: login_map.c conn.h login_map.h
$(OBJ_DIR)/json_writer.o: json_writer.c json_writer.h
$(OBJ_DIR)/offline_data.o: offline_data.c offline_data.h conn.h json_writer.h

.PHONY: all clean install uninstall run debug release check help