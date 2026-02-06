#!/bin/bash
# WiFi Card Mode Manager
# Handles mode switching and status checking for alfa0 and alfa1

ACTION="$1"
INTERFACE="$2"
TARGET_MODE="$3"

show_usage() {
    echo "Usage: $0 <action> <interface> [mode]"
    echo ""
    echo "Actions:"
    echo "  status <interface>           - Show current mode"
    echo "  set <interface> <mode>       - Set card to specific mode"
    echo "  ensure <interface> <mode>    - Switch only if needed"
    echo ""
    echo "Interfaces: alfa0, alfa1"
    echo "Modes: monitor, managed, master"
    exit 1
}

notify() {
    local title="$1"
    local message="$2"
    sudo -u ov3rr1d3 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus DISPLAY=:0 notify-send "$title" "$message"
}

get_mode() {
    local iface="$1"
    
    if ! ip link show "$iface" &>/dev/null; then
        echo "down"
        return 1
    fi
    
    # Check mode via iw
    local mode=$(iw dev "$iface" info 2>/dev/null | grep "type" | awk '{print $2}')
    
    if [ -z "$mode" ]; then
        echo "unknown"
        return 1
    fi
    
    echo "$mode"
    return 0
}

set_monitor() {
    local iface="$1"
    
    echo "[*] Setting $iface to monitor mode..."
    sudo ip link set "$iface" down
    sudo iw dev "$iface" set monitor none
    sudo ip link set "$iface" up
    
    if [ $? -eq 0 ]; then
        echo "[+] $iface is now in monitor mode"
        notify "📡 Mode Changed" "$iface → Monitor Mode"
        return 0
    else
        echo "[-] Failed to set monitor mode"
        notify "⚠️ Mode Change Failed" "$iface monitor mode failed"
        return 1
    fi
}

set_managed() {
    local iface="$1"
    
    echo "[*] Setting $iface to managed mode..."
    sudo ip link set "$iface" down
    sudo iw dev "$iface" set type managed
    sudo ip link set "$iface" up
    
    if [ $? -eq 0 ]; then
        echo "[+] $iface is now in managed mode"
        notify "📶 Mode Changed" "$iface → Managed Mode"
        return 0
    else
        echo "[-] Failed to set managed mode"
        notify "⚠️ Mode Change Failed" "$iface managed mode failed"
        return 1
    fi
}

set_master() {
    local iface="$1"
    
    echo "[*] Setting $iface to AP (master) mode..."
    sudo ip link set "$iface" down
    sudo iw dev "$iface" set type __ap
    sudo ip link set "$iface" up
    
    if [ $? -eq 0 ]; then
        echo "[+] $iface is now in AP mode"
        notify "📡 Mode Changed" "$iface → AP Mode"
        return 0
    else
        echo "[-] Failed to set AP mode"
        notify "⚠️ Mode Change Failed" "$iface AP mode failed"
        return 1
    fi
}

case "$ACTION" in
    status)
        if [ -z "$INTERFACE" ]; then
            show_usage
        fi
        
        mode=$(get_mode "$INTERFACE")
        echo "$mode"
        ;;
        
    set)
        if [ -z "$INTERFACE" ] || [ -z "$TARGET_MODE" ]; then
            show_usage
        fi
        
        case "$TARGET_MODE" in
            monitor)
                set_monitor "$INTERFACE"
                ;;
            managed)
                set_managed "$INTERFACE"
                ;;
            master)
                set_master "$INTERFACE"
                ;;
            *)
                echo "[-] Unknown mode: $TARGET_MODE"
                show_usage
                ;;
        esac
        ;;
        
    ensure)
        if [ -z "$INTERFACE" ] || [ -z "$TARGET_MODE" ]; then
            show_usage
        fi
        
        current=$(get_mode "$INTERFACE")
        
        if [ "$current" == "$TARGET_MODE" ]; then
            echo "[*] $INTERFACE already in $TARGET_MODE mode"
            exit 0
        fi
        
        echo "[*] $INTERFACE is $current, switching to $TARGET_MODE..."
        
        case "$TARGET_MODE" in
            monitor)
                set_monitor "$INTERFACE"
                ;;
            managed)
                set_managed "$INTERFACE"
                ;;
            master)
                set_master "$INTERFACE"
                ;;
            *)
                echo "[-] Unknown mode: $TARGET_MODE"
                exit 1
                ;;
        esac
        ;;
        
    *)
        show_usage
        ;;
esac
