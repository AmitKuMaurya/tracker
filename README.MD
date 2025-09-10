# 365GPS 2G and 4G GPS Tracker Communication Server

A C-based TCP server implementation for handling communication with 365GPS 2G and 4G GPS tracking devices according to the Zhongxun Locator Communication Protocol V1.3.

## Features

- **Multi-threaded TCP server** supporting up to 100 concurrent device connections
- **Complete protocol support** for all major 365GPS tracker protocols:
  - Device login and authentication (0x01)
  - Heartbeat monitoring (0x08)
  - GPS positioning data (0x10, 0x11)
  - Status information (0x13)
  - WiFi/LBS positioning (0x17, 0x18, 0x19, 0x69)
  - Time synchronization (0x30)
  - SOS alarms (0x99)
  - And many more...

- **Device management** with automatic connection tracking and timeout handling
- **Comprehensive logging** to both console and syslog
- **Signal handling** for graceful shutdown
- **Memory efficient** with proper cleanup and resource management

## Protocol Support

### Core Protocols (Required for Location Functionality)
- **0x01** - Login data packet
- **0x08** - Heartbeat data packet  
- **0x10** - GPS online location data
- **0x11** - GPS offline location data
- **0x13** - Status data packet
- **0x17** - Offline WiFi/LBS location data
- **0x18** - Online WiFi/LBS location data
- **0x19** - Offline 4G WiFi/LBS location data
- **0x30** - Time synchronization
- **0x69** - WiFi positioning data packet

### Additional Protocols
- **0x05** - Monitor number status
- **0x14** - Device sleep instruction
- **0x15** - Factory reset
- **0x16** - Whitelist management
- **0x33** - LBS positioning control
- **0x34** - GPS/LBS switch control
- **0x40-0x43** - Phone number management (SOS, Dad, Mom)
- **0x44** - Stop data upload
- **0x46** - GPS timing period setting
- **0x47** - Do not disturb settings
- **0x48** - Device restart/shutdown
- **0x49** - Find device
- **0x50** - Alarm clock
- **0x56** - Off alarm
- **0x57** - Settings synchronization
- **0x58** - Whitelist synchronization
- **0x61** - Light switch
- **0x64** - Recording requests
- **0x65** - File transfer
- **0x66** - Server IP/port modification
- **0x67** - Password recovery
- **0x72** - Attendance tracking
- **0x73** - Geofence alarms
- **0x80** - Manual positioning
- **0x81-0x83** - Charging status
- **0x86** - Overspeed alarm
- **0x92-0x94** - Vibration alarm
- **0x97-0x98** - Upload interval settings
- **0x99** - SOS alarm
- **0xB3** - ICCID information

## Building and Installation

### Prerequisites
- GCC compiler
- Make
- Linux/Unix system with pthread support

### Build
```bash
# Clone or download the source code
cd tracker/

# Build the server
make

# Or build with debug symbols
make debug
```

### Installation
```bash
# Install to system (requires sudo)
make install

# The server will be installed to /usr/local/bin/365gps_server
```

### Running
```bash
# Run with default port (8080)
./365gps_server

# Run with custom port
./365gps_server 9000

# If installed system-wide
/usr/local/bin/365gps_server 8080
```

## Usage

### Starting the Server
```bash
# Basic usage
./365gps_server [port]

# Examples
./365gps_server          # Use default port 8080
./365gps_server 9000     # Use port 9000
```

### Configuration
The server accepts the following configuration:

- **Port**: Specify the TCP port to listen on (default: 8080)
- **Max Clients**: Up to 100 concurrent device connections
- **Timeout**: 5-minute heartbeat timeout for device connections

### Logging
The server logs to both:
- **Console**: Real-time output for monitoring
- **Syslog**: System log for persistent logging

Log messages include:
- Device connections/disconnections
- Protocol messages received
- GPS data with coordinates and speed
- Status information (battery, signal strength)
- Error conditions and warnings

## Protocol Details

### Packet Format
All packets follow the format:
```
0x7878 + [length] + [protocol] + [data] + 0x0D0A
```

### Example Packets

#### Login (0x01)
```
7878 0A 01 0123456789012345 01 0D0A
```

#### GPS Data (0x10)
```
7878 12 10 0A03170F3217 9C 026B3F3E 0C22AD65 1F 3460 0D0A
```

#### Heartbeat (0x08)
```
7878 01 08 0D0A
```

### Response Format
Server responses follow the same format:
```
0x7878 + [length] + [protocol] + [data] + 0x0D0A
```

## Device Management

The server maintains a registry of connected devices with:
- **IMEI tracking** for device identification
- **Connection status** monitoring
- **Heartbeat tracking** for timeout detection
- **Battery level** and signal strength monitoring

## Security Considerations

- **Input validation** for all protocol packets
- **Buffer overflow protection** with fixed-size buffers
- **Connection limits** to prevent resource exhaustion
- **Timeout handling** for stale connections

## Performance

- **Multi-threaded** design for concurrent device handling
- **Efficient memory usage** with proper cleanup
- **Non-blocking I/O** for responsive operation
- **Optimized packet parsing** for high throughput

## Troubleshooting

### Common Issues

1. **Port already in use**
   ```bash
   # Check what's using the port
   netstat -tulpn | grep :8080
   
   # Use a different port
   ./365gps_server 9000
   ```

2. **Permission denied**
   ```bash
   # Make sure the executable has proper permissions
   chmod +x 365gps_server
   ```

3. **Firewall blocking connections**
   ```bash
   # Allow the port through firewall
   sudo ufw allow 8080/tcp
   ```

### Debug Mode
```bash
# Build with debug symbols
make debug

# Run with verbose output
./365gps_server 8080
```

## Development

### Adding New Protocols
To add support for additional protocols:

1. Add protocol constant in the header section
2. Implement handler function
3. Add case in the main switch statement in `client_handler()`

### Testing
```bash
# Run test mode
make test

# This starts the server on port 8080 for testing
```

## License

This implementation is provided as-is for educational and development purposes.

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review the protocol documentation
3. Enable debug mode for detailed logging

## Version History

- **v1.0** - Initial implementation with core protocol support
- **v1.1** - Added comprehensive protocol coverage
- **v1.2** - Enhanced error handling and logging
- **v1.3** - Added device management and timeout handling



