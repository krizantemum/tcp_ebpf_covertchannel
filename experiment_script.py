from scapy.all import sniff, TCP
import subprocess
import os
import json
from time import sleep
from scapy.config import conf
conf.sniff_promisc = False


CLONE_NEWNET = 0x40000000
ROOT_NS_FD = os.open("/proc/self/ns/net", os.O_RDONLY)
# CAPTURE_COUNT = 20000
# REPETITION = 30
# LOSS_RANGE = range(0, 4)
# DELAY_RANGE = range(0, 101, 20)
# CHANNEL_CAP = range(5, 21, 5)
# REORDER = range(0, 4)
# RUN_TYPE = ["covert", "normal"]


def enter_ns(nsname: str):
    fd = os.open(f"/var/run/netns/{nsname}", os.O_RDONLY)
    os.setns(fd, CLONE_NEWNET)
    os.close(fd)


def leave_ns():
    os.setns(ROOT_NS_FD, CLONE_NEWNET)


def sh(cmd: str):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def setup_sec_fq():
    enter_ns("sec")
    try:
        sh("tc qdisc replace dev eth0 root fq")
        sh("tc qdisc replace dev eth0 clsact")  # to host your TC egress BPF
    finally:
        leave_ns()


def setup_insec_ingress_netem(loss_pct, delay_ms, jitter_ms, rate_mbit, reorder_pct, dup_pct):
    enter_ns("insec")
    try:
        sh("tc qdisc del dev ifb0 root")
        if delay_ms > 0:
            netem = (f"tc qdisc replace dev ifb0 root netem "
                     f"loss {loss_pct}% delay {delay_ms}ms {jitter_ms}ms "
                     f"rate {rate_mbit}mbit reorder {reorder_pct}% duplicate {dup_pct}%")
        else:
            netem = (f"tc qdisc replace dev ifb0 root netem "
                     f"loss {loss_pct}% delay {delay_ms}ms {jitter_ms}ms "
                     f"rate {rate_mbit}mbit")

        r = sh(netem)
        if r.returncode != 0:
            print("Failed to set netem on insec/ifb0:", r.stderr)
            exit(1)
    finally:
        leave_ns()


def capture_in_insec(interface="eth0", n=200):
    enter_ns("insec")
    try:
        return capture_packets(interface=interface, n=n)
    finally:
        leave_ns()


def run_in_sec(cmd_list):
    enter_ns("sec")
    try:
        return subprocess.run(cmd_list, capture_output=True, text=True)
    finally:
        leave_ns()


def capture_packets(interface="eth0", n=200):
    # capture exactly n TCP packets and return them
    def collect_ts(packets):
        ts = []
        for packet in packets:
            if TCP in packet:
                opts = packet[TCP].options
                for opt in opts:
                    if opt[0] == "Timestamp":
                        tsval, _ = opt[1]
                        ts.append(tsval)
        return ts
    pkts = sniff(iface=interface, filter="tcp and ip dst host 10.0.0.2", count=n, store=True)
    duration = pkts[-1].time - pkts[0].time
    return duration, collect_ts(pkts)


def set_netem(loss, delay, rate, reorder, dup):
    jitter = round(delay * 0.1, 2)
    setup_insec_ingress_netem(loss, delay, jitter, rate, reorder, dup)


def runexperiment(loss, delay, rate, reorder, dup, repetition, run_types, capture_count=20000, iface="ifb0"):
    """
    Run one experiment setup and update the result dict.
    """
    global res

    # one-time setup (safe to call multiple times if idempotent)
    setup_sec_fq()
    run_in_sec(["./bpf_map_manager", "-d"])
    set_netem(loss, delay, rate, reorder, dup)
    sleep(0.05)

    for t in run_types:
        for i in range(repetition):
            if delay > 0:
                run_name = f"loss_{loss}_delay_{delay}_rate_{rate}_reorder_{reorder}_dup_{dup}_{t}_#{i}"
            else:
                run_name = f"loss_{loss}_delay_{delay}_rate_{rate}_reorder_{0}_dup_{0}_{t}_#{i}"

            unload_res = None
            if t == "covert":
                # prepare random input and load eBPF sender
                subprocess.run(
                    "head -c 10000 /dev/urandom | tr -cd '[:print:]' > input.txt",
                    shell=True, check=True
                )
                run_in_sec(["./bpf_map_manager"])

            sleep(0.002)
            dur, stamps = capture_in_insec(interface=iface, n=capture_count)

            if t == "covert":
                unload_res = run_in_sec(["./bpf_map_manager", "-d"])

            # compute metrics
            dif = (stamps[-1] - stamps[0]) if len(stamps) >= 2 else 0
            count = len(set(stamps))
            distinct_ratio = (count / dif) if dif > 0 else -1

            res[run_name] = {
                "distinct_ratio": distinct_ratio,
                "dur": dur,
                "packet_count": len(stamps),
                "ebpf_stats": (unload_res.stdout if unload_res else None),
            }

            print(f"[{run_name}] pkts={len(stamps)} dur={dur:.3f}s distinct_ratio={distinct_ratio:.4f} dif={dif:.3f}ms count={count} cap={capture_count/dur:.1f}/s")

# CAPTURE_COUNT = 20000
# REPETITION = 30
# LOSS_RANGE = range(0, 4)
# DELAY_RANGE = range(0, 101, 20)
# CHANNEL_CAP = range(5, 21, 5)
# REORDER = range(0, 4)
# RUN_TYPE = ["covert", "normal"]


# none
res = {}
CAPTURE_COUNT = 20000
REPETITION = 30
LOSS = 0
DELAY = 1
CHANNEL_CAP = 20
REORDER = 0
DUP = 0
RUN_TYPE = ["covert", "normal"]

setup_sec_fq()
runexperiment(LOSS, DELAY, CHANNEL_CAP, REORDER, DUP, REPETITION, RUN_TYPE, capture_count=CAPTURE_COUNT)

REPETITION = 30
LOSS = 0
DELAY = 1
CHANNEL_CAP = 20
REORDER = 10
DUP = 0
RUN_TYPE = ["covert", "normal"]

setup_sec_fq()
runexperiment(LOSS, DELAY, CHANNEL_CAP, REORDER, DUP, REPETITION, RUN_TYPE, capture_count=CAPTURE_COUNT)

#
# # mid
# CAPTURE_COUNT = 20000
# REPETITION = 30
# LOSS = 0.5
# DELAY = 50
# CHANNEL_CAP = 10
# REORDER = 0.2
# DUP = 0.001
# RUN_TYPE = ["covert", "normal"]
#
# setup_sec_fq()
# runexperiment(LOSS, DELAY, CHANNEL_CAP, REORDER, DUP, REPETITION, RUN_TYPE, capture_count=CAPTURE_COUNT)
#
# # high
# CAPTURE_COUNT = 20000
# REPETITION = 30
# LOSS = 1
# DELAY = 100
# CHANNEL_CAP = 5
# REORDER = 0.4
# DUP = 0.01
# RUN_TYPE = ["covert", "normal"]
#
# setup_sec_fq()
# runexperiment(LOSS, DELAY, CHANNEL_CAP, REORDER, DUP, REPETITION, RUN_TYPE, capture_count=CAPTURE_COUNT)

with open("experiment_data.json", "w") as f:
    json.dump(res, f, indent=4)

# print(stamps)
