#!/usr/bin/env bash
# Weather pill for Waybar (wttr.in). Change CITY to your location.
CITY="${WEATHER_CITY:-Guwahati}"
out=$(curl -sf --max-time 10 "https://wttr.in/${CITY}?format=%c+%t" | sed 's/+//')
if [ -z "$out" ]; then
    echo '{"text": "󰖐 --", "tooltip": "weather unavailable"}'
else
    printf '{"text": "%s", "tooltip": "%s"}\n' "$out" "$CITY"
fi
