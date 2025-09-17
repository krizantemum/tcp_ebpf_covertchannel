#!/usr/bin/env bash
set -euo pipefail

NS1=sec
NS2=insec

# veth names in the root namespace
IF1=veth-$NS1
IF2=veth-$NS2

IP1=10.0.0.1/24
IP2=10.0.0.2/24

usage() {
  echo "Usage: $0 {up|down|status|ping}"
  exit 1
}

have_ns() { ip netns list | awk '{print $1}' | grep -qx "$1"; }

disable_offloads() {
  local ns="$1"
  ip netns exec "$ns" sh -lc 'command -v ethtool >/dev/null 2>&1 && ethtool -K eth0 tso off gso off gro off lro off rx off tx off' || true
}

setup_insec_ingress_ifb_netem() {
  # Everything below runs *inside* the insec namespace
  ip netns exec "$NS2" bash -lc '
    set -e
    modprobe ifb || true
    ip link add ifb0 type ifb 2>/dev/null || true
    ip link set ifb0 up

    # Recreate ingress (special qdisc: no parent/handle)
    tc qdisc del dev eth0 ingress 2>/dev/null || true
    tc qdisc add dev eth0 ingress

    # Redirect all ingress traffic to ifb0
    tc filter replace dev eth0 ingress prio 1 matchall \
      action mirred egress redirect dev ifb0
  '
}

cleanup_insec_ingress_ifb() {
  ip netns exec "$NS2" bash -lc '
    tc qdisc del dev eth0 ingress 2>/dev/null || true
    tc qdisc del dev ifb0 root 2>/dev/null || true
    ip link del ifb0 2>/dev/null || true
  ' || true
}

up() {
  # Create namespaces if missing
  have_ns "$NS1" || ip netns add "$NS1"
  have_ns "$NS2" || ip netns add "$NS2"

  # Clean any stale veth in root ns
  ip link show "$IF1" >/dev/null 2>&1 && ip link del "$IF1" || true
  ip link show "$IF2" >/dev/null 2>&1 && ip link del "$IF2" || true

  # Create veth pair and move into namespaces
  ip link add "$IF1" type veth peer name "$IF2"
  ip link set "$IF1" netns "$NS1"
  ip link set "$IF2" netns "$NS2"

  # Rename ends to eth0 inside namespaces
  ip -n "$NS1" link set "$IF1" name eth0
  ip -n "$NS2" link set "$IF2" name eth0

  ip -n "$NS1" link set lo up
  ip -n "$NS2" link set lo up

  ip -n "$NS1" addr flush dev eth0 || true
  ip -n "$NS2" addr flush dev eth0 || true

  ip -n "$NS1" addr add "$IP1" dev eth0
  ip -n "$NS2" addr add "$IP2" dev eth0

  ip -n "$NS1" link set eth0 up
  ip -n "$NS2" link set eth0 up

  # Optional: disable offloads
  disable_offloads "$NS1"
  disable_offloads "$NS2"


  ip netns exec "$NS1" tc qdisc replace dev eth0 root fq
  # ip netns exec "$NS1" mkdir -p /sys/fs/bpf
  # ip netns exec "$NS1" mount -t bpf bpffs /sys/fs/bpf

  # >>> Add IFB/netem on insec ingress <<<
  setup_insec_ingress_ifb_netem

  echo "Namespaces ${NS1} (${IP1}) and ${NS2} (${IP2}) are up with IFB/netem on ${NS2} ingress."
}

down() {
  # Clean IFB/ingress in insec before deleting ns
  have_ns "$NS2" && cleanup_insec_ingress_ifb

  # Delete namespaces (removes veths inside)
  have_ns "$NS1" && ip netns del "$NS1" || true
  have_ns "$NS2" && ip netns del "$NS2" || true

  # Remove any leftover veths in root ns
  ip link show "$IF1" >/dev/null 2>&1 && ip link del "$IF1" || true
  ip link show "$IF2" >/dev/null 2>&1 && ip link del "$IF2" || true

  echo "Namespaces removed."
}

status() {
  ip netns list
  echo "--- ${NS1} ---"
  have_ns "$NS1" && ip -n "$NS1" addr show || echo "missing"
  echo "--- ${NS2} ---"
  have_ns "$NS2" && ip -n "$NS2" addr show || echo "missing"
  echo "--- qdiscs in ${NS2} ---"
  have_ns "$NS2" && ip netns exec "$NS2" tc qdisc show || true
}

ping_test() {
  ip netns exec "$NS1" ping -c1 -W1 10.0.0.2 && echo "sec → insec OK" || echo "sec → insec FAIL"
  ip netns exec "$NS2" ping -c1 -W1 10.0.0.1 && echo "insec → sec OK" || echo "insec → sec FAIL"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  ping) ping_test ;;
  *) usage ;;
esac

