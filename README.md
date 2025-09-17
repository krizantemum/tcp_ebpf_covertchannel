# tcp\_ebpf\_covertchannel

TimeLSB, a covert channel based on TCP timestamps.

## Requirements

On Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm make pkg-config libbpf-dev libpcap-dev
```

---

## Quick start (local testbed)

1. **Build**

compiles bpf_sender.c to bpf object code:
```bash
make sender 
```

compiles manager, which is used to load and unload the bpf program, and managing maps:
```bash
make manager
```

compiles libpcap receiver:
```bash
make receiver
```



2. **Create the two-namespace lab**

```bash
sudo ./setup_env.sh up
```

This script creates two network namespaces—`sec` and `insec`—and connects them with a veth pair (addresses like `10.0.0.1/10.0.0.2`). Then enter the sec namespace:

```bash
sudo ip netns exec sec bash
```
then in sec namespace execute following commands:
```bash
mkdir -p /sys/fs/bpf
mount -t bpf bpffs /sys/fs/bpf
```

3. **Launch the demo traffic**
   Open two terminals:

```bash
# Terminal A: TCP server in the secure side
sudo ip netns exec sec python3 server.py --port 1234

# or use iperf
iperf3 -s 

# Terminal B: TCP client in the insecure side
sudo ip netns exec insec python3 client.py 10.0.0.1 1234
# or use iperf
iperf3 -c 10.0.0.1 -t  0
```

4. **Attach the eBPF sender**
```bash
sudo ip netns exec sec

#inside sec ns
./bpf_map_manager


# to collect stats after run is complete, cleanup and report statistics with
./bpf_map_manager -d

```

5. **Run the receiver**

```bash
# Replace <IFACE_INSEC> with the insec-side interface
sudo ip netns exec insec ./receiver
```

The receiver reconstructs the bitstream from observed TCP timestamps.


---

## Experiments

`experiment_script.py` automates sweeps over loss, delay, rate, reordering, and duplication via `tc netem`. Configuration is adjusted inside the script.

create a python 3.12 venv first.
```bash
python3.12 -m venv venv
source venv/bin/activate
pip install scapy
deactivate
```

then you can run the experiment script with the appropriate path:

```bash
sudo -E /path/to/venv/bin/python experiment_script.py
```
It is an odd way to run scripts like this ,however, to workaround permission issues it has been done this way. 

