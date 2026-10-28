#!/usr/bin/env bash
set -euo pipefail
if [[ "$EUID" -ne 0 ]]; then
  echo 'Run this script with sudo in your Ubuntu terminal.' >&2
  exit 1
fi
apt-get update
apt-get install -y mininet openvswitch-switch python3-os-ken python3-venv python3-pip
systemctl enable --now openvswitch-switch
ovs-vsctl --version
mn --version
python3 -c 'from os_ken.ofproto import ofproto_v1_3_parser; print("OS-Ken OpenFlow 1.3 import OK")'
