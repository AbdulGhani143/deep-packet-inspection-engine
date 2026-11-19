CXX ?= clang++
CXXFLAGS = -std=c++17 -O3 -pthread -Iinclude

SRCS = src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
TARGET = dpi_engine

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) -lpcap

run: $(TARGET)
	./$(TARGET) test_dpi.pcap output.pcap

dashboard: $(TARGET)
	python3 bridge_server.py

clean:
	rm -f $(TARGET) output.pcap

