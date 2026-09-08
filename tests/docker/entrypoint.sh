#!/bin/sh -eu
# Start FreeRADIUS (debug logs to its own file), then run charon in the
# foreground. Both share the container; charon reaches RADIUS on 127.0.0.1.
freeradius -X > /var/log/freeradius.log 2>&1 &
RADIUS_PID=$!
trap 'kill $RADIUS_PID 2>/dev/null || true' EXIT

# Give radiusd a moment to bind before charon starts.
sleep 1
exec /usr/sbin/ipsec start --nofork