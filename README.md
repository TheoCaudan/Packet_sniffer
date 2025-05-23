# Network Intrusion Detection System

This project is a simple Network Intrusion Detection System (NIDS) implemented in C. It captures network packets and analyzes them to detect potential security threats such as port scanning, DoS attacks, malware, and anomalies.

## Features

- **Port Scanning Detection**: Identifies potential port scanning activities by monitoring the number of connection attempts from a single IP address.
- **DoS Attack Detection**: Detects potential Denial of Service attacks by tracking the number of packets received from a single IP address.
- **Malware Detection**: Compares packet data against known malware signatures to identify potential threats.
- **Anomaly Detection**: Monitors packet sizes to detect anomalies that deviate significantly from the average size.

## Files

- `detection.c`: Contains the core logic for detecting various types of network intrusions.
- `detection.h`: Header file declaring the functions and structures used in `detection.c`.
- `main.c`: The entry point of the application, responsible for capturing network packets and invoking detection functions.

## Prerequisites

- A Linux-based system with root privileges (required for raw socket operations).
- GCC compiler for compiling the C code.
- A text file named `signatures.txt` containing malware signatures in the format: `protocol pattern`.

## Compilation

To compile the code, use the following command:

```bash
gcc -o nids main.c detection.c -lpcap
```

## Running the Program

Run the compiled program with root privileges:

```bash
sudo ./nids
```

The program will start capturing network packets and analyzing them for potential threats. Detected threats will be logged and printed to the console.

## Logging

Detected threats are logged in a file specified by the `LOG_FILE` macro in `detection.c`. Ensure that the log file path is writable by the program.

## Known Issues

- The code uses raw sockets, which require root privileges.
- The `print_data` function may not correctly print non-alphanumeric characters.

## Future Improvements

- Enhance the signature matching algorithm for better performance.
- Implement a more sophisticated anomaly detection mechanism.
- Add support for additional protocols and threat types.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

### Notes:
- Ensure that the `LOG_FILE` macro is defined in your code to specify the log file path.
- Correct any typos or logical errors in the code before running it.
- The `signatures.txt` file should be formatted correctly to ensure proper loading of signatures.
