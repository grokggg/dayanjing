#!/bin/sh
mount -t tmpfs -o rw,nosuid,nodev tmpfs /run 2>&1
mkdir -p /run/systemd /run/systemd/system /run/systemd/private.d 2>&1
mount -t tmpfs tmpfs /tmp 2>&1
mount -t tmpfs tmpfs /var/log 2>&1
exec /lib/systemd/systemd --system --unit=multi-user.target --log-level=info --log-target=console
