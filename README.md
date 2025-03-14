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

## Run

### Linux / MacOS:
```bash
curl -L "https://raw.githubusercontent.com/hawshemi/dns-tester/main/dns-tester-run.sh" -o dns-tester-run.sh && chmod +x dns-tester-run.sh && bash dns-tester-run.sh
```

### Windows: ([Broken for now](https://github.com/hawshemi/dns-tester/issues/4))

1. Download from [Releases](https://github.com/hawshemi/dns-tester/releases/latest).
2. Open `CMD` or `Powershell` in the directory.
3.
    ```
    .\dns-tester.exe
    ```

    
## Usage

**Flags:**

`--output (-o): Output format (table, json, csv), default: table`

`--runs (-r): Number of test runs, default: 3`

`--help (-h): Show help`

Examples:

```bash
./dns-tester
./dns-tester -o json -r 5
./dns-tester --output=csv --runs=2
```

## Build

#### 0. Install `golang`.
```bash
wget "https://raw.githubusercontent.com/hawshemi/tools/main/go-installer/go-installer.sh" -O go-installer.sh && chmod +x go-installer.sh && bash go-installer.sh
```

#### 1. Clone the repository
```bash
git clone https://github.com/hawshemi/dns-tester.git 
```

#### 2. Navigate into the repository directory
```bash
cd dns-tester
```

#### 3. Prepare for build
```bash
go mod init dns-tester && go mod tidy
```
#### 4. Build
```bash
CGO_ENABLED=0 go build
```
