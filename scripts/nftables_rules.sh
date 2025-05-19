#!/bin/bash

echo "⚙️ Setting up nftables rules..."

sudo nft flush ruleset

sudo nft add table inet ddos_inspector
sudo nft add chain inet ddos_inspector input { type filter hook input priority 0 \; }
sudo nft add rule inet ddos_inspector input ip saddr 192.168.0.0/16 drop

echo "✅ nftables rules have been applied."
nft list ruleset
