# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

This is a **365GPS 2G and 4G GPS Tracker Communication Server** - a C-based TCP server that communicates with GPS tracking devices using the Zhongxun Locator Communication Protocol V1.3. The server handles multiple concurrent device connections and processes various GPS protocols including location data, heartbeats, and LBS (Location Based Services) positioning.

## Key Build Commands

```bash
# Build the tracker server
make

# Build with debug symbols
make debug

# Build optimized release version
make release

# Clean build artifacts
make clean

# Install to system
make install

# Run the server (default port 8080)
make run

# Run with custom port
./bin/tracker 9000

# Memory leak check with valgrind
make memcheck

# Format code (if clang-format available)
make format

# Check compilation without linking
make check
```

## Architecture Overview

### Core Server Architecture
- **Event-driven server**: Uses Linux epoll for high-performance I/O multiplexing
- **Multi-connection support**: Handles up to 10,000 concurrent device connections
- **Non-blocking I/O**: All socket operations are non-blocking for maximum throughput
- **Connection timeout management**: Each connection has an individual timer (60s timeout) managed via timerfd

### Key Modules and Responsibilities

**main_file.c**: Core server implementation
- Epoll event loop management
- Connection lifecycle (accept, read, cleanup)
- Timer-based connection timeout handling
- Non-blocking socket operations

**data_processing.c/h**: Protocol frame processing
- GPS protocol frame extraction (0x7878...0x0D0A format)
- Command dispatching based on protocol ID
- Input buffer management and frame validation

**gps_data.c/h**: GPS positioning data handling
- GPS coordinate parsing and conversion (BCD to decimal degrees)
- Datetime parsing from GPS packets
- GPS positioning status validation
- Coordinate system conversion (30000 scale factor)

**login_map.c/h**: Device session management  
- IMEI-to-connection mapping (up to 8192 devices)
- Device authentication and registration
- Connection lookup by device ID

**offline_data.c/h**: LBS data processing
- WiFi hotspot data parsing with MAC deduplication
- Cell tower data parsing with Cell ID deduplication  
- BCD datetime parsing
- Memory management for dynamic arrays

**json_writer.c/h**: Data serialization
- JSON output formatting for LBS data
- Google Geolocation API payload creation
- Response parsing utilities

**lbs_latlong.c/h**: Location resolution
- Google Geolocation API integration via libcurl
- Cell tower and WiFi-based positioning
- HTTP request/response handling

### Protocol Architecture
The server implements the 365GPS protocol stack:
- **Frame format**: `0x7878 + [length] + [protocol] + [data] + 0x0D0A`
- **Key protocols**: 0x01 (login), 0x08 (heartbeat), 0x10/0x11 (GPS), 0x17/0x18/0x19 (LBS)
- **Response handling**: Each protocol generates appropriate acknowledgment responses

### Memory Management Pattern
- Dynamic allocation for variable-length data (WiFi, cell arrays)
- Explicit cleanup functions for each data structure
- RAII-style resource management in connection handling
- Buffer overflow protection with fixed-size limits

### Concurrency Design
- Single-threaded event loop with epoll
- Timer-based connection management (no pthread dependency)
- Event data structures to distinguish socket vs timer events
- Connection state isolated per file descriptor

## Dependencies

**System Libraries:**
- `libm` - Math operations for coordinate conversion
- `libcjson` - JSON processing (with pkg-config detection)
- `libcurl` - HTTP client for geolocation API calls

**System Requirements:**
- Linux with epoll support
- pthread support (for connection management)
- GCC with C99 support

## Testing and Development

**Port Configuration:**
- Default: 8080 (for development)  
- Production: 12345 (hardcoded in main_file.c:18)
- Configurable via command line argument

**Log Output:**
- Console output with module prefixes (GPS_DATA, LBS_PROCESSOR, DATA_PROC)
- Syslog integration available
- Detailed protocol-level debugging information

**Common Development Tasks:**
- **Add new protocol**: Modify `dispatch_command()` in data_processing.c
- **Debug connections**: Check login_map entries and connection timeouts
- **Test with device**: Use telnet/netcat with hex data matching protocol format
- **Memory debugging**: Use `make memcheck` to detect leaks

## Important Implementation Details

**Connection Timeout**: Each device connection has a 60-second timeout managed by individual timerfd instances. Reset on any data activity.

**Protocol Frame Processing**: The server expects exact frame format `0x7878[len][protocol][data]0x0D0A`. Malformed frames are discarded.

**IMEI Handling**: Device IMEIs are extracted from BCD format in login packets and used as primary device identifiers.

**Coordinate Conversion**: GPS coordinates use a 30000 scale factor and require conversion from minutes to decimal degrees.

**Deduplication**: LBS processing includes built-in deduplication for both WiFi MAC addresses and cell tower IDs.

**API Integration**: Google Geolocation API is used for WiFi/cell-based positioning with proper error handling and response parsing.
