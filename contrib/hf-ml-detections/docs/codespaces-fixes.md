# Codespaces workarounds

These are local settings from the Codespace setup that passed `make smoke`
10/10, as reported by the operator. Day 1 ran `make doctor` against that
running stack.

## Kafka memory limit

The local `docker-compose.override.yml` removes Kafka's `mem_limit`.
The Codespace's cgroup v2 setup rejected the setting with the error
`cannot enter cgroupv2 ... it is in threaded mode`.

## Docker forwarding

Kafka timed out connecting to Zookeeper when Docker's FORWARD policy dropped
traffic between containers. In this Codespace the operator applies the policy
on all three iptables backends:

```bash
sudo iptables -P FORWARD ACCEPT
sudo iptables-legacy -P FORWARD ACCEPT
sudo iptables-nft -P FORWARD ACCEPT
```

The local `~/aisoc-start.sh` applies those commands and then runs `make up`
and `make smoke`. Keep the script and Compose override local.
