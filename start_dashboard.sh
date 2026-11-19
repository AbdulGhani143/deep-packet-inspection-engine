#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "========================================================"
echo "  Starting DPI Engine Visual Console (macOS / Linux)"
echo "========================================================"

# Check if native binary exists, if not build it
if [ ! -f "dpi_engine" ]; then
    echo "Compiling native C++ DPI engine..."
    clang++ -std=c++17 -O3 -pthread -Iinclude src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp -o dpi_engine -lpcap
fi

# Check if test_dpi.pcap exists, if not generate it
if [ ! -f "test_dpi.pcap" ]; then
    echo "Generating test_dpi.pcap..."
    python3 generate_test_pcap.py
fi

echo "Launching local bridge server at http://localhost:8080 ..."
echo "(Press Ctrl+C in this terminal window to stop the server)"
echo ""

python3 bridge_server.py

