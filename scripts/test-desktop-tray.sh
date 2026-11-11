#!/bin/sh
set -eu

app=$1
screenshot=${2:-}
test_dir=$(mktemp -d)
app_pid=
panel_pid=
wm_pid=
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        cat "$test_dir/app.log" "$test_dir/panel.log" "$test_dir/wm.log" 2>/dev/null || :
        if window_visible; then
            xdotool getdisplaygeometry
            xdotool getwindowgeometry "$(window_id)"
        fi
        if [ -n "$screenshot" ] && window_visible; then
            import -window "$(window_id)" "$screenshot" || :
        fi
    fi
    for pid in "$app_pid" "$panel_pid" "$wm_pid"; do
        if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || :; fi
    done
    rm -rf "$test_dir"
}
trap cleanup EXIT

export XDG_CONFIG_HOME="$test_dir/config"
export GDK_BACKEND=x11
export GDK_SCALE=1
export GTK_THEME=Adwaita:dark
xfwm4 --compositor=off > "$test_dir/wm.log" 2>&1 &
wm_pid=$!

panel_config="$XDG_CONFIG_HOME/xfce4/xfconf/xfce-perchannel-xml"
mkdir -p "$panel_config"
cat > "$panel_config/xfce4-panel.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfce4-panel" version="1.0">
  <property name="configver" type="int" value="2"/>
  <property name="panels" type="array">
    <value type="int" value="1"/>
    <property name="panel-1" type="empty">
      <property name="position" type="string" value="p=6;x=0;y=0"/>
      <property name="size" type="uint" value="30"/>
      <property name="plugin-ids" type="array"><value type="int" value="1"/></property>
    </property>
  </property>
  <property name="plugins" type="empty">
    <property name="plugin-1" type="string" value="systray"/>
  </property>
</channel>
XML
xfce4-panel > "$test_dir/panel.log" 2>&1 &
panel_pid=$!

watcher_property() {
    gdbus call --session --timeout 1 --dest org.kde.StatusNotifierWatcher \
        --object-path /StatusNotifierWatcher --method org.freedesktop.DBus.Properties.Get \
        org.kde.StatusNotifierWatcher "$1" 2>/dev/null
}
tray_host() {
    watcher_property IsStatusNotifierHostRegistered | grep -q true
}
tray_item() {
    watcher_property RegisteredStatusNotifierItems |
        tr "'" '\n' | awk '/StatusNotifierItem/ && !/\[/ { print; exit }'
}
window_id() {
    xdotool search --onlyvisible --name '^MySafeAI$' 2>/dev/null | head -1
}
window_visible() {
    [ -n "$(window_id)" ]
}
window_hidden() {
    kill -0 "$app_pid" 2>/dev/null && ! window_visible
}
item_registered() {
    [ -n "$(tray_item)" ]
}
item_gone() {
    [ -z "$(tray_item)" ]
}
wait_for() {
    attempts=0
    until "$@"; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 75 ]; then
            printf 'Timed out waiting for %s\n' "$*" >&2
            return 1
        fi
        sleep 0.2
    done
}
activate_item() {
    item=$(tray_item)
    destination=${item%%/*}
    path=/StatusNotifierItem
    if [ "$item" != "$destination" ]; then path="/${item#*/}"; fi
    icon=$(gdbus call --session --timeout 2 --dest "$destination" --object-path "$path" \
        --method org.freedesktop.DBus.Properties.Get org.kde.StatusNotifierItem IconPixmap)
    printf '%s\n' "$icon" | grep -q 'byte'
    gdbus call --session --timeout 2 --dest "$destination" --object-path "$path" \
        --method org.kde.StatusNotifierItem.Activate 0 0 >/dev/null
}
start_app() {
    "$app" > "$test_dir/app.log" 2>&1 &
    app_pid=$!
    wait_for item_registered
}

wait_for tray_host
start_app
wait_for window_visible
window=$(window_id)
xdotool windowactivate --sync "$window"
xdotool key alt+F4
wait_for window_hidden
activate_item
wait_for window_visible
printf 'Opened, closed to Xfce tray and reopened through StatusNotifierItem.Activate\n'

# Enter Settings through the visible navigation. Reverse Tab order reaches the
# checkbox before the four navigation buttons, independent of title bar height.
window=$(window_id)
xdotool windowactivate --sync "$window"
sleep 1
dimensions=$(xdotool getwindowgeometry --shell "$window")
width=$(printf '%s\n' "$dimensions" | sed -n 's/^WIDTH=//p')
height=$(printf '%s\n' "$dimensions" | sed -n 's/^HEIGHT=//p')
xdotool mousemove --window "$window" "$((width - 59))" "$((height - 28))" click 1
sleep 0.4
xdotool key --delay 100 Shift+Tab Shift+Tab Shift+Tab Shift+Tab space
wait_for window_hidden
grep -q '"trayOnly":true' "$XDG_CONFIG_HOME/MySafeAI/window.json"
if [ -n "$screenshot" ]; then
    activate_item
    wait_for window_visible
    import -window "$(window_id)" "$screenshot"
fi
kill -INT "$app_pid"
wait "$app_pid"
app_pid=
wait_for item_gone

start_app
sleep 1
window_hidden
activate_item
wait_for window_visible
printf 'Tray-only setting persisted and the next launch started hidden\n'

window=$(window_id)
xdotool windowactivate --sync "$window"
xdotool key alt+F4
wait_for window_hidden
kill "$panel_pid"
wait "$panel_pid" || :
panel_pid=
wait_for window_visible
printf 'Window returned automatically when the tray host closed\n'
kill -INT "$app_pid"
wait "$app_pid"
app_pid=
