# crabctl systemd integration

## Installation

```bash
# Install the unit files
install -m 644 certbundle.service certbundle.timer /etc/systemd/system/

# Create required directories
install -d -m 755 /etc/crab
install -d -m 755 /var/lib/crab/staging
install -d -m 755 /var/cache/crab
install -d -m 755 /var/log/crab

# Copy your config
install -m 640 /path/to/config.yaml /etc/crab/config.yaml

# Reload systemd and enable the timer
systemctl daemon-reload
systemctl enable --now certbundle.timer

# Run once immediately to verify
systemctl start certbundle.service
journalctl -u certbundle.service -f
```

## Status and logs

```bash
# Check timer status
systemctl status certbundle.timer

# View last run logs
journalctl -u certbundle.service --since "24 hours ago"

# List all timers
systemctl list-timers certbundle.timer
```

## Cron alternative

If you prefer cron over systemd timers, add to `/etc/cron.d/crabctl`:

```cron
# Run crabctl daily at 04:00, log to syslog via logger
0 4 * * *  root  /usr/local/bin/crabctl --config /etc/crab/config.yaml build 2>&1 | logger -t crabctl
```
