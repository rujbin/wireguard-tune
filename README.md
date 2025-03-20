# WireGuard Windows Client (Fork)

## Original Project

This is a fork of the official WireGuard Windows client. The original project can be found at:
https://git.zx2c4.com/wireguard-windows

## Copyright Notice

Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.

This software is licensed under the MIT License. See the LICENSE file for details.

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