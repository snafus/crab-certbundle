# certbundle systemd integration

## Installation

```bash
# Install the unit files
install -m 644 certbundle.service certbundle.timer /etc/systemd/system/

# Create required directories
install -d -m 755 /etc/certbundle
install -d -m 755 /var/lib/certbundle/staging
install -d -m 755 /var/cache/certbundle
install -d -m 755 /var/log/certbundle

# Copy your config
install -m 640 /path/to/config.yaml /etc/certbundle/config.yaml

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

If you prefer cron over systemd timers, add to `/etc/cron.d/certbundle`:

```cron
# Run certbundle daily at 04:00, log to syslog via logger
0 4 * * *  root  /usr/local/bin/certbundle --config /etc/certbundle/config.yaml build 2>&1 | logger -t certbundle
```
