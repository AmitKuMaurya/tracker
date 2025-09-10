# Makefile for GPS Tracker Server

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -fPIC
LDFLAGS = -lm -lcjson -lpthread -lssl -lcrypto

# Try to use pkg-config for libcurl if available, else fall back to -lcurl
CURL_CFLAGS := $(shell pkg-config --cflags libcurl 2>/dev/null)
CURL_LIBS := $(shell pkg-config --libs libcurl 2>/dev/null)
ifneq ($(strip $(CURL_CFLAGS)),)
CFLAGS += $(CURL_CFLAGS)
endif
ifneq ($(strip $(CURL_LIBS)),)
LDFLAGS += $(CURL_LIBS)
else
LDFLAGS += -lcurl
endif

# Try to use pkg-config for cjson if available
CJSON_CFLAGS := $(shell pkg-config --cflags libcjson 2>/dev/null)
CJSON_LIBS := $(shell pkg-config --libs libcjson 2>/dev/null)
ifneq ($(strip $(CJSON_CFLAGS)),)
CFLAGS += $(CJSON_CFLAGS)
endif
ifneq ($(strip $(CJSON_LIBS)),)
LDFLAGS := $(filter-out -lcjson,$(LDFLAGS))
LDFLAGS += $(CJSON_LIBS)
endif

# Directories
SRC_DIR = .
OBJ_DIR = obj
BIN_DIR = bin

# Source files
SOURCES = main_file.c login_map.c json_writer.c offline_data.c lbs_latlong.c data_processing.c gps_data.c websocket_server.c
OBJECTS = $(SOURCES:%.c=$(OBJ_DIR)/%.o)
TARGET = $(BIN_DIR)/tracker

# Header files
HEADERS = conn.h login_map.h json_writer.h offline_data.h lbs_latlong.h data_processing.h gps_data.h websocket_server.h

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
	rm -f *.o tracker *.log lbs_data.json
	@echo "Clean complete"

# Deep clean (including generated files)
distclean: clean
	@echo "Deep clean complete"

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

# Format code (if clang-format is available)
format:
	@if command -v clang-format >/dev/null 2>&1; then \
		echo "Formatting code..."; \
		clang-format -i *.c *.h; \
		echo "Code formatted"; \
	else \
		echo "clang-format not found, skipping formatting"; \
	fi

# Check for memory leaks with valgrind
memcheck: $(TARGET)
	@if command -v valgrind >/dev/null 2>&1; then \
		echo "Running memory check..."; \
		valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET); \
	else \
		echo "valgrind not found, skipping memory check"; \
	fi

# Test build with different optimization levels
test-builds: clean
	@echo "Testing debug build..."
	@$(MAKE) debug
	@echo "Testing release build..."
	@$(MAKE) release
	@echo "All test builds successful"

# Show help
help:
	@echo "Available targets:"
	@echo "  all        - Build the tracker (default)"
	@echo "  clean      - Remove build artifacts"
	@echo "  distclean  - Deep clean including generated files"
	@echo "  install    - Install to /usr/local/bin/"
	@echo "  uninstall  - Remove from /usr/local/bin/"
	@echo "  run        - Build and run the tracker"
	@echo "  debug      - Build with debug flags"
	@echo "  release    - Build optimized release version"
	@echo "  check      - Check compilation without linking"
	@echo "  format     - Format code with clang-format"
	@echo "  memcheck   - Run memory leak check with valgrind"
	@echo "  test-builds- Test debug and release builds"
	@echo "  help       - Show this help"

# Dependencies
$(OBJ_DIR)/main_file.o: main_file.c conn.h login_map.h data_processing.h
$(OBJ_DIR)/login_map.o: login_map.c conn.h login_map.h
$(OBJ_DIR)/json_writer.o: json_writer.c json_writer.h offline_data.h
$(OBJ_DIR)/offline_data.o: offline_data.c offline_data.h conn.h json_writer.h lbs_latlong.h
$(OBJ_DIR)/lbs_latlong.o: lbs_latlong.c lbs_latlong.h offline_data.h json_writer.h
$(OBJ_DIR)/data_processing.o: data_processing.c data_processing.h conn.h gps_data.h login_map.h offline_data.h
$(OBJ_DIR)/gps_data.o: gps_data.c gps_data.h conn.h websocket_server.h json_writer.h
$(OBJ_DIR)/websocket_server.o: websocket_server.c websocket_server.h login_map.h

.PHONY: all clean distclean install uninstall run debug release check format memcheck test-builds help