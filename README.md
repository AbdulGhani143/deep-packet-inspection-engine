# Deep Packet Inspection Engine

A C++17 packet analyzer with a web dashboard that captures traffic from your laptop, identifies some of the services it connects to, and can enforce local blocking rules on macOS and Linux. This semester project extends a packet analyzer to show how a rule moves from a packet-level decision to something you can observe in your browser.

## Try live blocking on your laptop

Install Clang, the libpcap development headers, and Python 3. Use `bash start_dashboard.sh` for the synthetic demo. For live capture and OS blocking, launch with administrator privileges using `sudo bash start_dashboard.sh`. The dashboard listens on network interfaces and has no sign-in, so run the privileged demo on an isolated test network or one where your firewall restricts access to port 8080 to your own machine.

1. Open [localhost:8080](http://localhost:8080), select **Live WiFi/Network Capture**, and choose your active interface. Start **Capture New Live Traffic** while opening a website to see real packets in the dashboard.
2. To try a narrow block, enter `www.youtube.com` in **Block Domain Substring**, leave the app presets unchecked, and enable **Enforce Real OS Blocking**. Run the inspection to apply the rule, then try opening the site in a fresh browser session.
3. Click **Clear OS Blocks** when done and try the site again. In the macOS demo, Brave failed to load that hostname while the rule was active and loaded it again after cleanup. Cached addresses, open connections, and other YouTube hostnames can produce different results.

## How inspection and enforcement work

The engine reads either a saved packet capture (PCAP) or a short live capture from libpcap. It groups packets by connection and uses signals such as IP addresses, ports, and visible TLS server names to classify traffic. The dashboard shows which packets matched your IP, domain, or app rules. A dashboard **Drop** verdict means the packet was left out of the output capture. **Enforce Real OS Blocking** applies rules to the laptop itself.

Domain-only enforcement adds exact hostnames to the system hosts file. IP rules use PF on macOS or iptables on Linux. App presets can cover several hostnames and may also block IPs from matching traffic. An IP can be shared by multiple services, so those rules can have a broader effect than a single-hostname block.

## What happens when you open a website?

Your browser typically uses DNS to look up the site's IP address. Your laptop sends packets through your router and across the internet, and the browser establishes a secure connection to the server. HTTPS uses TLS to protect request paths, passwords, and page content. The engine works alongside HTTPS by using metadata it can see, such as the destination IP and, when visible, the server name (SNI) sent during the TLS handshake. Blocking a hostname or IP can stop a connection without decrypting what the browser sends. [HTTPS](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.2) · [TLS server names](https://www.rfc-editor.org/rfc/rfc6066.html#section-3)

## Run the synthetic demo from the command line

```sh
make
python3 generate_test_pcap.py
./dpi_engine test_dpi.pcap output.pcap
```
