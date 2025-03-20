# WireGuard Windows Client (Fork)

## Original Project

This is a fork of the official WireGuard Windows client. The original project can be found at:
https://git.zx2c4.com/wireguard-windows

## Overview

WireGuard is a modern, fast, and secure VPN tunnel that aims to be faster, simpler, leaner, and more useful than IPsec, while avoiding the massive headache. It intends to be considerably more performant than OpenVPN.

## Features

- Native Windows integration
- System tray interface
- Automatic service management
- Secure tunneling
- High performance
- Modern cryptography
- Enhanced error handling
- Improved resource management
- Better timeout handling
- Optimized string handling
- More robust pipe management
- Better memory management

## Technical Improvements

This fork includes several technical improvements over the original:

### Service Layer
- Enhanced error handling with detailed error messages
- Improved resource cleanup and management
- Better panic recovery mechanisms
- Optimized shutdown sequence
- Improved deadlock detection and handling
- Better memory management for stack traces
- More robust adapter creation with retry mechanism

### Performance Optimizations
- Efficient channel usage
- Optimized string handling
- Better memory allocation patterns
- Improved resource cleanup
- Enhanced error reporting

### Security Enhancements
- Better privilege management
- Improved resource isolation
- Enhanced error logging
- More secure shutdown procedures

### DNS Resolution Performance Improvements
- **DNS Caching:**  
  Implemented an in-memory cache for resolved hostnames with a 5-minute expiration time, significantly reducing repetitive DNS lookups.
  
- **Parallel Endpoint Resolution:**  
  Peer endpoints are now resolved in parallel using goroutines, dramatically improving connection setup time when multiple peers are configured.
  
- **Exponential Backoff:**  
  DNS retry mechanism now uses exponential backoff instead of fixed intervals, improving responsiveness while reducing unnecessary network traffic.
  
- **Timeout Handling:**  
  Added a 10-second timeout for DNS operations to prevent hanging on unresponsive DNS servers, with graceful fallback to retries.
  
- **Reduced Maximum Retries:**  
  Optimized the maximum number of retries from 10/30 to 5/10 (normal/boot mode), reducing connection setup time while maintaining reliability.

### UI/Tray Optimization (Performance Improvements)
- **Reduced Redundant Processing:**  
  The tray component now caches frequently used UI elements such as menu action arrays to reduce repeated method calls.
  
- **Preallocation and Batching:**  
  Slices are preallocated (e.g., when sorting tunnel names or gathering active addresses), minimizing memory reallocations.  
  UI updates are batched via synchronized calls, reducing overhead on the main UI thread.
  
- **Efficient Goroutine Usage:**  
  Instead of copying tunnel objects, pointers are passed into goroutines for state updates, lowering memory usage and improving responsiveness.
  
These changes help in creating a more fluid and responsive system tray experience without sacrificing the clarity or functionality of the application.

## Building

To build the WireGuard Windows client, you need:

- Go 1.16 or later
- Windows SDK
- Visual Studio Build Tools

## Usage

The client supports the following command-line options:

- `(no argument)`: Elevate and install manager service
- `/installmanagerservice`: Install the manager service
- `/installtunnelservice CONFIG_PATH`: Install a tunnel service
- `/uninstallmanagerservice`: Uninstall the manager service
- `/uninstalltunnelservice TUNNEL_NAME`: Uninstall a tunnel service
- `/managerservice`: Run the manager service
- `/tunnelservice CONFIG_PATH`: Run a tunnel service
- `/ui CMD_READ_HANDLE CMD_WRITE_HANDLE CMD_EVENT_HANDLE LOG_MAPPING_HANDLE`: Run the UI
- `/dumplog [/tail]`: Dump the log file
- `/update`: Update the client
- `/removedriver`: Remove the driver

## Security

WireGuard uses state-of-the-art cryptography:
- ChaCha20 for symmetric encryption
- Poly1305 for message authentication
- Curve25519 for key exchange
- BLAKE2s for hashing
- SipHash24 for hashtable keys
- HKDF for key derivation

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

WireGuard is a registered trademark of Jason A. Donenfeld.

This is an unofficial fork and is not affiliated with or endorsed by WireGuard LLC or Jason A. Donenfeld.

## Contributing

For contributing to the original project, please visit the official WireGuard repository.

## Support

For official support, please visit the official WireGuard website or GitHub repository.

## Fork Information

This fork is maintained independently and may contain modifications or improvements not present in the original project. While we strive to maintain compatibility with the original project, please be aware that this is not an official release.

## Development Status

This fork is actively maintained and includes various performance optimizations and bug fixes. However, it is not officially supported by the WireGuard team.

## Technical Details

### Service Improvements
- Added panic recovery mechanism
- Improved resource cleanup with structured management
- Enhanced error handling with detailed context
- Better timeout handling for shutdowns
- Optimized adapter creation with retry mechanism
- Improved logging and error reporting
- Panic recovery and enhanced error handling with full context and localization
- Graceful shutdown using context cancellation and coordinated cleanup via wait groups
- Robust logging and error reporting mechanisms
- Improved adapter creation with retry and exponential backoff

### Performance Optimizations
- Efficient channel usage for service communication
- Better memory management for resource cleanup
- Optimized string handling in logging
- Improved pipe management for inter-process communication
- Enhanced error handling with proper context
- Efficient inter-process communication using channels and optimized memory management
- Improved pipe and handle management for better resource usage

### Security Enhancements
- Better privilege management during service operations
- Improved resource isolation
- Enhanced error logging for security events
- More secure shutdown procedures
- Better handling of system resources
- Enhanced privilege management and resource isolation
- Secure shutdown procedures and improved token handling

## Recent MTU Monitor Performance Improvements

The MTU monitor module (`mtumonitor.go`) has been significantly optimized for better performance and reliability:

### Performance Optimizations
- **Efficient Route Filtering:**  
  Implemented pre-filtering of routes to reduce unnecessary processing, only considering eligible default routes (PrefixLength 0) that don't belong to the current interface.

- **State Management:**  
  Introduced a `mtuState` struct with proper mutex synchronization to prevent race conditions and ensure thread-safe updates of shared variables.

- **Update Throttling:**  
  Added a 250ms throttling mechanism to prevent excessive updates and reduce system overhead when multiple network changes occur in quick succession.

- **Optimized MTU Updates:**  
  Implemented smarter MTU update logic that only applies changes when the new MTU value actually differs from the current value, reducing unnecessary system calls.

### Code Quality Improvements
- **Better Error Handling:**  
  Enhanced error handling in callback functions with proper logging of errors during MTU updates.

- **Improved Code Organization:**  
  Restructured the code for better maintainability with clear separation of concerns between route selection and MTU management.

- **Memory Efficiency:**  
  Optimized memory usage through pre-allocation of slices and better variable scoping.

### Technical Details
- **Route Selection Algorithm:**  
  The `findDefaultLUID` function now uses a more efficient two-pass approach:
  1. First pass filters eligible routes
  2. Second pass selects the route with the lowest metric

- **State Synchronization:**  
  All state updates are now protected by a mutex, ensuring thread safety in concurrent scenarios.

- **Resource Management:**  
  Improved cleanup and resource management in callback functions to prevent memory leaks.

These improvements result in:
- Reduced CPU usage during network changes
- Better handling of rapid network state changes
- More reliable MTU updates
- Improved system stability
- Better resource utilization

## UI Enhancements in TunnelsPage

The following improvements have been implemented in the `TunnelsPage` component to enhance UI responsiveness, maintainability, and overall performance:

- **Enhanced Control Layout and Event Handling:**  
  - The "Edit" button is now dynamically enabled or disabled based on the current selection in the tunnel list.  
  - Specific event handlers (e.g., for `CurrentIndexChanged`, `ItemActivated`) are attached to update UI components only when necessary, reducing redundant processing.

- **Improved Asynchronous Processing:**  
  - Intensive operations (such as the import of configuration files) now run in parallel using goroutines. This minimizes UI blocking and accelerates file processing.
  
- **Optimized UI Refresh and Resource Management:**  
  - Bulk actions (like importing or deleting tunnels) suspend list updates to provide a smoother user experience.  
  - UI updates are batched and synchronized efficiently to avoid unnecessary redrawing or locking.

- **Better Component Separation and Maintenance:**  
  - The structure of the UI components (e.g., `fillerContainer`, `currentTunnelContainer`, and `listContainer`) has been refined to improve readability and facilitate future modifications.

# Changes in main.go

## Bug Fixes and Improvements

- **Logging Setup:**  
  The `setLogFile` function now attempts to retrieve the standard error handle, and if that fails, it falls back to the output handle. If both are unavailable, logging is disabled by directing output to `io.Discard`.

- **Error Handling:**  
  The `fatal` and `fatalf` functions have been updated to provide clearer error messages when logging is not available, showing a message box for errors in non-logging environments.

- **Usage Function Optimization:**  
  The `usage` function now uses a pre-allocated `strings.Builder` to efficiently construct the usage description with improved performance.

- **WOW64 Check Refinement:**  
  The `checkForWow64` function now better handles errors while determining if the process is running under WOW64, ensuring that the native version of WireGuard is used.

- **Administrative Checks:**  
  Additional checks are added in `checkForAdminGroup` and `checkForAdminDesktop` to ensure that only authorized users have access, with clear error messages if the checks fail.

- **Elevated Manager Service Installer:**  
  The `execElevatedManagerServiceInstaller` function has been simplified by removing unreachable code after the `os.Exit(0)` call.

- **Pipe Handling Improvement:**  
  The `pipeFromHandleArgument` function now validates that the provided handle is not zero, returning a clear error if an invalid handle is encountered.

- **Command Handler Refactoring:**  
  The command handler map in `main` has been updated to improve clarity and error handling for various command-line options.

  ## Parser Improvements

### Overview
The parser in `parser.go` has been optimized for improved performance and readability. The following changes have been implemented:

- **Case-Insensitive Comparisons Without Allocations:**  
  Instead of converting strings to lower case for each comparison, the parser now uses `strings.EqualFold` for case-insensitive comparisons. This change eliminates unnecessary string allocations, leading to less memory usage and improved performance.

- **Streamlined Parsing Logic:**  
  The parsing code has been refactored for clarity while preserving its core functionality. Error messages and validations have been standardized to maintain consistency across different parsing steps.

- **Minor Validation and Error Handling Enhancements:**  
  Adjustments have been made in helper functions (e.g., `parseIPCidr`, `parseEndpoint`, etc.) to handle edge cases and ensure robust error handling. These changes improve the stability of the parser when processing various configuration file formats.

These enhancements contribute to a more efficient and maintainable configuration parser.

## UI Process Performance Optimizations

The `uiprocess.go` module has been optimized for better performance and resource management:

### Memory Optimizations
- **Pre-allocated Handles:**  
  Handles slice is now pre-allocated to avoid runtime reallocation, reducing memory fragmentation.
  
- **Efficient Resource Management:**  
  Improved cleanup of system resources with proper handle management and finalizer implementation.
  
- **Optimized String Handling:**  
  More efficient UTF16 string conversions with better error handling.

### Process Management Improvements
- **Enhanced Process Creation:**  
  Optimized process creation flags and improved environment block handling.
  
- **Better Handle Management:**  
  Immediate cleanup of unused thread handles and improved process handle validation.
  
- **Robust Error Handling:**  
  Added early validation of process handles and more specific error messages.

### Code Structure and Performance
- **Improved Code Organization:**  
  Better structured code with clear section separation for improved maintainability.
  
- **Optimized Resource Cleanup:**  
  More efficient cleanup of system resources with proper defer statements.
  
- **Enhanced Error Propagation:**  
  Better error handling structure with more specific error messages and proper context.

  
## License

This repository is MIT-licensed.

```text
Copyright (C) 2018-2022 WireGuard LLC. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

These optimizations result in:
- Reduced memory allocations and fragmentation
- More efficient process creation and management
- Better resource cleanup and system stability
- Improved error handling and recovery
- Enhanced overall performance
