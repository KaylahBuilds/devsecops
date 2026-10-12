#!/usr/bin/env bash
# "  30°C  󰍎 Guwahati, Assam, India" — set WEATHER_CITY to change.
CITY="${WEATHER_CITY:-Guwahati}"
cache=/tmp/tmux-weather
if [ ! -f "$cache" ] || [ "$(find "$cache" -mmin +15 2>/dev/null)" ]; then
    curl -sf --max-time 10 "https://wttr.in/${CITY}?format=%t+󰍎+%l" | sed 's/+//' > "$cache.new" \
        && mv "$cache.new" "$cache"
fi
cat "$cache" 2>/dev/null || echo "weather n/a"
