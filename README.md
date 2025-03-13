# DNS Tester

DNS Tester is a command-line tool written in Go that benchmarks various DNS providers by measuring key performance metrics such as ping latency, jitter, DNS resolution time, and packet loss. It then computes a composite score based on these metrics and recommends the top-performing providers for fast and consistent DNS resolution.

## Features

- **Comprehensive Metrics**: Computes average, median, minimum, maximum, and jitter for both ping and DNS resolution.
- **Packet Loss Detection**: Measures packet loss to evaluate the reliability of each provider.
- **Composite Scoring**: Uses a weighted composite score to rank DNS providers.
- **Cross-Platform**: Works on Linux, macOS, and Windows.
- **CI/CD Integration**: Automatically builds and releases binaries via GitHub Actions.

## Requirements

- Go 1.24 or later
- The following commands must be available on your system:
  - `ping` for latency tests
  - `dig` for DNS resolution tests

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/dns-tester.git
   cd dns-tester

2. **Build the Binary:**

    ```bash
    go build -o dns-tester

## Usage

   ```bash
   ./dns-tester
