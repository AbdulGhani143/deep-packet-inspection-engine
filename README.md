# DPI Engine

A multithreaded C++17 packet analyzer with a local web dashboard. It reads PCAP
files, classifies traffic using signals such as TLS server names, and shows
which packets match IP, domain, or application rules.

## Run the dashboard

On macOS or Linux, install Clang, the libpcap development headers, and Python 3.
The launcher builds the engine and generates a synthetic capture for the demo.

```sh
bash start_dashboard.sh
```

Open [localhost:8080](http://localhost:8080) and select Synthetic mode.

## Run from the command line

```sh
make
python3 generate_test_pcap.py
./dpi_engine test_dpi.pcap output.pcap
```
