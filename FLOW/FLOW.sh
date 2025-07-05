#!/bin/bash

# --- Color helpers ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

cecho() { echo -e "$1$2${NC}"; }
press_enter() { read -p "Press Enter to continue..." dummy; }

# --- Bash version check ---
if ! declare -A test_assoc 2>/dev/null; then
    cecho "$RED" "This script requires Bash version 4 or higher."
    exit 1
fi

# --- Trap for cleanup on exit ---
cleanup() {
    sudo systemctl stop apache2 2>/dev/null
    > "$LOG_FILE"
}
trap cleanup EXIT

clear
cecho "$YELLOW" "========================================"
cecho "$GREEN"  "        Welcome to FLOW"
cecho "$YELLOW" "========================================"
echo
cecho "$GREEN"  "A streamlined toolkit for automating"
cecho "$GREEN"  "Bettercap network attacks and testing."
cecho "$GREEN"  "An easier way to use Bettercap."
echo
cecho "$YELLOW" "Created by: Karma"
cecho "$YELLOW" "Version: Beta 0.7"
echo
cecho "$RED" "!!!EXPECT BUGS!!!"
echo
cecho "$YELLOW" "Press Enter to continue..."
read -p "" dummy
clear

echo

# --- Set FLOW data directory ---
FLOW_DIR="$HOME/Desktop/FLOWbcapData"
mkdir -p "$FLOW_DIR"
LOG_FILE="$FLOW_DIR/.flowbcap_modules.txt"

# --- List interfaces and detect default ---
cecho "$YELLOW" "Available interfaces:"
interfaces=$(ip -o link show | awk -F': ' '{print $2}')
default_iface=$(ip route | awk '/default/ {print $5; exit}')
for i in $interfaces; do
    [[ "$i" == "$default_iface" ]] && cecho "$GREEN" "  $i (default)" || echo "  $i"
done

read -p "Enter interface (leave blank for default [$default_iface]): " iface
iface="${iface:-$default_iface}"

# --- Initialize variables ---
selected_targets=""
dns_domains=""
dns_ip=""
spoof_all=""
hosts_file=""
modules_on=()
fullduplex=""
internal=""
skip_restore=""
arp_mode_selected=""

while true; do
    # --- Restore modules_on from persistent log if exists ---
    [ ! -f "$LOG_FILE" ] && touch "$LOG_FILE"
    mapfile -t modules_on < "$LOG_FILE"
    : "${modules_on[@]}"

    # --- Gather interface/network info ---
    iface_ip=$(ip -4 addr show "$iface" | awk '/inet / {print $2}' | cut -d/ -f1)
    iface_netmask=$(ip -4 addr show "$iface" | awk '/inet / {print $2}' | cut -d/ -f2)
    iface_mac=$(ip link show "$iface" | awk '/link\/ether/ {print $2}')
    gateway=$(ip route | awk '/default/ {print $3; exit}')

    # --- Query module statuses (real-time) ---
    net_probe_status=$(sudo bettercap -iface "$iface" -eval "get net.probe.status; q" 2>/dev/null | grep -oE 'true|false')
    arp_spoof_status=$(sudo bettercap -iface "$iface" -eval "get arp.spoof.status; q" 2>/dev/null | grep -oE 'true|false')
    dns_spoof_status=$(sudo bettercap -iface "$iface" -eval "get dns.spoof.status; q" 2>/dev/null | grep -oE 'true|false')
    net_sniff_status=$(sudo bettercap -iface "$iface" -eval "get net.sniff.status; q" 2>/dev/null | grep -oE 'true|false')
    apache_status=$(systemctl is-active apache2 2>/dev/null)

    # --- Show "to be ON/OFF" status based on modules_on ---
    show_status() {
        [[ " ${modules_on[*]} " =~ " $1 " ]] && cecho "$GREEN" "ON" || cecho "$RED" "OFF"
    }
    net_probe_status=$(show_status "net.probe")
    arp_spoof_status=$(show_status "arp.spoof")
    dns_spoof_status=$(show_status "dns.spoof")
    net_sniff_status=$(show_status "net.sniff")
    [[ "$apache_status" == "active" ]] && apache_status="${GREEN}active${NC}" || apache_status="${RED}inactive${NC}"

    # --- Build up the bettercap_cmds string (settings first, modules ON at end, no duplicates) ---
    bettercap_cmds=""
    declare -A seen_mods

    # Only add arp.spoof.targets if arp.spoof or arp.ban is enabled
    if [[ " ${modules_on[*]} " =~ " arp.spoof " || " ${modules_on[*]} " =~ " arp.ban " ]]; then
        [ -n "$selected_targets" ] && bettercap_cmds+="set arp.spoof.targets $selected_targets; "
        [[ "$fullduplex" =~ ^[Yy]$ ]] && bettercap_cmds+="set arp.spoof.fullduplex true; "
        [[ "$internal" =~ ^[Yy]$ ]] && bettercap_cmds+="set arp.spoof.internal true; "
        [[ "$skip_restore" =~ ^[Yy]$ ]] && bettercap_cmds+="set arp.spoof.skip_restore true; "
    fi

    # Only add DNS spoof settings if dns.spoof is enabled
    if [[ " ${modules_on[*]} " =~ " dns.spoof " ]]; then
        [ -n "$dns_domains" ] && bettercap_cmds+="set dns.spoof.domains $dns_domains; "
        [ -n "$dns_ip" ] && bettercap_cmds+="set dns.spoof.address $dns_ip; "
        [[ "$spoof_all" =~ ^[Yy]$ ]] && bettercap_cmds+="set dns.spoof.all true; "
        [ -n "$hosts_file" ] && bettercap_cmds+="set dns.spoof.hosts $hosts_file; "
    fi

    # Add module commands (no duplicates)
    for mod in "${modules_on[@]}"; do
        [ -z "$mod" ] && continue
        [[ -z "${seen_mods[$mod]}" ]] && bettercap_cmds+="$mod on; " && seen_mods[$mod]=1
    done

    # Ensure all ON modules are present in the CLI (log file enforcement)
    for mod in "${modules_on[@]}"; do
        [[ "$bettercap_cmds" != *"$mod on;"* ]] && bettercap_cmds+="$mod on; "
    done

    clear
    cecho "$YELLOW" "========== FLOW Info =========="
    cecho "$YELLOW" "Interface:${NC} $iface"
    echo -e "  IP      : ${iface_ip:-N/A}"
    echo -e "  Netmask : ${iface_netmask:-N/A}"
    echo -e "  MAC     : ${iface_mac:-N/A}"
    echo -e "  Gateway : ${gateway:-N/A}"
    echo "-----------------------------------"
    cecho "$YELLOW" "Selected Target(s):${NC} ${selected_targets:-none}"
    cecho "$YELLOW" "DNS Spoof Domains :${NC} ${dns_domains:-none}"
    cecho "$YELLOW" "DNS Spoof Address :${NC} ${dns_ip:-none}"
    cecho "$YELLOW" "Hosts File        :${NC} ${hosts_file:-none}"
    cecho "$YELLOW" "ARP Mode          :${NC} ${arp_mode_selected:-none}"
    echo "-----------------------------------"
    cecho "$YELLOW" "Module Status (current):${NC}"
    printf "  net.probe : %-7b" "$net_probe_status"
    printf "| arp.spoof : %-7b" "$arp_spoof_status"
    printf "| dns.spoof : %-7b" "$dns_spoof_status"
    printf "| net.sniff : %-7b" "$net_sniff_status"
    printf "| apache2 : %-8b\n" "$apache_status"
    echo "-----------------------------------"
    cecho "$YELLOW" "CLI (Command Line):${NC}"
    [ -n "$bettercap_cmds" ] && echo "  $bettercap_cmds" || echo "  (none)"
    echo "==================================="
    echo
    echo "Choose an action:"
    echo "1) Network Probe & Show"
    echo "2) ARP Spoof (setup options)"
    echo "3) DNS Spoof (setup options)"
    echo "4) Apache2 Web Server Control"
    echo "5) Set/Change Target(s)"
    echo "6) Toggle Module On/Off"
    echo "7) Clear CLI/Bettercap command"
    echo "8) Custom Bettercap Command"
    echo "9) Start Bettercap with current settings"
    echo "10) Show current Bettercap log"
    echo "00) Save/Load Commands"
    echo "0) Exit"
    read -p "Select an option [0-10,00]: " opt

    case $opt in
        1)
            read -p "How many seconds should net.probe run before showing results? " wait
            cmds="net.probe on; sleep $wait; net.probe off; net.show; q"
            sudo bettercap -iface "$iface" -eval "$cmds"
            press_enter
            continue
            ;;
        2)
            if [ -z "$selected_targets" ]; then
                cecho "$RED" "No targets selected. Please set targets first (action 5)."
                press_enter
                continue
            fi
            echo "ARP Spoofing Options:"
            echo "1) Normal ARP Spoof"
            echo "2) ARP Ban (disconnect targets)"
            read -p "Choose ARP mode [1-2]: " arp_mode
            read -p "Set fullduplex? (y/N): " fullduplex
            read -p "Set internal? (y/N): " internal
            read -p "Skip ARP cache restore on stop? (y/N): " skip_restore

            [[ "$arp_mode" == "2" ]] && arp_mode_selected="arp.ban" || arp_mode_selected="arp.spoof"

            # Ensure the selected ARP module is in modules_on and log
            if [[ ! " ${modules_on[*]} " =~ " $arp_mode_selected " ]]; then
                modules_on+=("$arp_mode_selected")
                grep -qxF "$arp_mode_selected" "$LOG_FILE" || echo "$arp_mode_selected" >> "$LOG_FILE"
            fi
            continue
            ;;
        3)
            read -p "Enter domain(s) to spoof (comma separated): " dns_domains
            read -p "Enter IP address to map these domains to (leave blank for default): " dns_ip
            read -p "Spoof all DNS requests? (y/N): " spoof_all
            read -p "Use a hosts file? (leave blank to skip): " hosts_file

            # Ensure dns.spoof is in modules_on and log
            if [[ ! " ${modules_on[*]} " =~ " dns.spoof " ]]; then
                modules_on+=("dns.spoof")
                grep -qxF "dns.spoof" "$LOG_FILE" || echo "dns.spoof" >> "$LOG_FILE"
            fi
            continue
            ;;
        4)
            echo "Apache2 Web Server Control"
            apache_status=$(systemctl is-active apache2 2>/dev/null)
            echo "Current status: $apache_status"
            echo "1) Start Apache2"
            echo "2) Stop Apache2"
            echo "0) Back to main menu"
            read -p "Choose an option [0-2]: " apache_opt
            case $apache_opt in
                1) sudo systemctl start apache2 && cecho "$GREEN" "Apache2 started." ;;
                2) sudo systemctl stop apache2 && cecho "$GREEN" "Apache2 stopped." ;;
                0) ;;
                *) cecho "$RED" "Invalid option." ;;
            esac
            press_enter
            continue
            ;;
        5)
            read -p "Enter target IP(s) (comma separated): " selected_targets
            continue
            ;;
        6)
            echo
            echo "Toggle which modules ON/OFF?"
            echo "1) net.recon"
            echo "2) net.probe"
            echo "3) arp.spoof"
            echo "4) dns.spoof"
            echo "5) net.sniff"
            echo "6) arp.ban"
            echo "Type numbers together to toggle (e.g. 135 for net.recon, arp.spoof, net.sniff)"
            echo "0) Back to main menu"
            read -p "Select modules to toggle [0,1-6]: " modseq
            [[ "$modseq" == "0" ]] && continue

            mod_name() {
                case "$1" in
                    1) echo "net.recon" ;;
                    2) echo "net.probe" ;;
                    3) echo "arp.spoof" ;;
                    4) echo "dns.spoof" ;;
                    5) echo "net.sniff" ;;
                    6) echo "arp.ban" ;;
                    *) echo "" ;;
                esac
            }

            toggled_on=()
            toggled_off=()
            for (( idx=0; idx<${#modseq}; idx++ )); do
                mod="${modseq:$idx:1}"
                name=$(mod_name "$mod")
                if [[ -n "$name" ]]; then
                    if [[ " ${modules_on[*]} " =~ " $name " ]]; then
                        # Remove module
                        modules_on=("${modules_on[@]/$name}")
                        toggled_off+=("$name")
                    else
                        modules_on+=("$name")
                        toggled_on+=("$name")
                    fi
                else
                    cecho "$RED" "Invalid module: $mod"
                fi
            done

            # Persistent log file logic
            touch "$LOG_FILE"
            for mod in "${toggled_on[@]}"; do
                grep -qxF "$mod" "$LOG_FILE" || echo "$mod" >> "$LOG_FILE"
            done
            for mod in "${toggled_off[@]}"; do
                tmpfile=$(mktemp)
                grep -vxF "$mod" "$LOG_FILE" > "$tmpfile" && mv "$tmpfile" "$LOG_FILE"
            done

            [ ${#toggled_on[@]} -gt 0 ] && cecho "$GREEN" "Toggled ON: ${toggled_on[*]}"
            [ ${#toggled_off[@]} -gt 0 ] && cecho "$RED" "Toggled OFF: ${toggled_off[*]}"
            [ ${#toggled_on[@]} -eq 0 ] && [ ${#toggled_off[@]} -eq 0 ] && echo "No valid modules toggled."
            press_enter
            continue
            ;;
        7)
            modules_on=()
            bettercap_cmds=""
            > "$LOG_FILE"
            cecho "$GREEN" "CLI and module selections cleared."
            press_enter
            continue
            ;;
        8)
            read -p "Enter your Bettercap commands: " cmds
            cmds="$cmds; q"
            sudo bettercap -iface "$iface" -eval "$cmds"
            press_enter
            continue
            ;;
        9)
            if [ -z "$bettercap_cmds" ]; then
                cecho "$RED" "No commands to run. Set up your actions first."
                press_enter
                continue
            fi
            cecho "$YELLOW" "Running:"
            echo "bettercap -iface $iface -eval \"$bettercap_cmds\""
            sudo bettercap -iface "$iface" -eval "$bettercap_cmds"
            modules_on=()
            bettercap_cmds=""
            press_enter
            continue
            ;;
        10)
            cecho "$YELLOW" "Showing current Bettercap log (last 20 lines):"
            sudo tail -n 20 /var/log/bettercap.log 2>/dev/null || echo "No log found."
            press_enter
            continue
            ;;
        00)
            default_cli_file="$FLOW_DIR/cli_commands.txt"
            echo "Saving and loading CLI commands will use: $default_cli_file"
            echo "1) Save current CLI commands"
            echo "2) Load CLI commands from file"
            echo "3) Delete saved command"
            echo "0) Back to main menu"
            read -p "Choose an option [0-3]: " save_opt
            case $save_opt in
                1)
                    touch "$default_cli_file"
                    echo "$bettercap_cmds" >> "$default_cli_file"
                    cecho "$GREEN" "Command saved to $default_cli_file"
                    ;;
                2)
                    if [ ! -f "$default_cli_file" ]; then
                        touch "$default_cli_file"
                        cecho "$YELLOW" "File $default_cli_file did not exist and was created. It is empty."
                        bettercap_cmds=""
                    else
                        mapfile -t cli_lines < "$default_cli_file"
                        total_lines=${#cli_lines[@]}
                        page_size=9
                        page=0
                        while true; do
                            clear
                            cecho "$YELLOW" "Loaded CLI Commands (Page $((page+1))):"
                            start=$((page * page_size))
                            end=$((start + page_size - 1))
                            for ((i=start; i<=end && i<total_lines; i++)); do
                                printf "%2d) %s\n" $((i+1)) "${cli_lines[$i]}"
                            done
                            echo
                            echo "Use ←/→ arrows to change page, 0 to return to menu."
                            echo "Press a number (1-9) to load that command."
                            IFS= read -rsn1 key
                            if [[ $key == $'\x1b' ]]; then
                                read -rsn2 -t 0.1 rest
                                key+="$rest"
                                if [[ $key == $'\x1b[C' ]]; then
                                    (( (page+1)*page_size < total_lines )) && ((page++))
                                elif [[ $key == $'\x1b[D' ]]; then
                                    (( page > 0 )) && ((page--))
                                fi
                            elif [[ $key == "0" ]]; then
                                break
                            elif [[ $key =~ [1-9] ]]; then
                                idx=$((start + key - 1))
                                if (( idx < total_lines )); then
                                    bettercap_cmds="${cli_lines[$idx]}"
                                    cecho "$GREEN" "Loaded command #$((idx+1)): ${cli_lines[$idx]}"
                                    # Parse and restore variables from the loaded command
                                    selected_targets=$(echo "$bettercap_cmds" | grep -oP 'set arp\.spoof\.targets \K[^;]*')
                                    dns_domains=$(echo "$bettercap_cmds" | grep -oP 'set dns\.spoof\.domains \K[^;]*')
                                    dns_ip=$(echo "$bettercap_cmds" | grep -oP 'set dns\.spoof\.address \K[^;]*')
                                    hosts_file=$(echo "$bettercap_cmds" | grep -oP 'set dns\.spoof\.hosts \K[^;]*')
                                    [[ "$bettercap_cmds" =~ "set arp.spoof.fullduplex true;" ]] && fullduplex="y" || fullduplex=""
                                    [[ "$bettercap_cmds" =~ "set arp.spoof.internal true;" ]] && internal="y" || internal=""
                                    [[ "$bettercap_cmds" =~ "set arp.spoof.skip_restore true;" ]] && skip_restore="y" || skip_restore=""
                                    if [[ "$bettercap_cmds" =~ "arp.ban on;" ]]; then
                                        arp_mode_selected="arp.ban"
                                    elif [[ "$bettercap_cmds" =~ "arp.spoof on;" ]]; then
                                        arp_mode_selected="arp.spoof"
                                    else
                                        arp_mode_selected=""
                                    fi
                                    # Update modules_on from loaded command
                                    > "$LOG_FILE"
                                    for mod in net.recon net.probe arp.spoof dns.spoof net.sniff arp.ban; do
                                        [[ "$bettercap_cmds" == *"$mod on;"* ]] && echo "$mod" >> "$LOG_FILE"
                                    done
                                    mapfile -t modules_on < "$LOG_FILE"
                                    # Show summary
                                    cecho "$YELLOW" "Preset loaded:"
                                    echo "  Targets: ${selected_targets:-none}"
                                    echo "  DNS Domains: ${dns_domains:-none}"
                                    echo "  DNS IP: ${dns_ip:-none}"
                                    echo "  Hosts File: ${hosts_file:-none}"
                                    echo "  ARP Mode: ${arp_mode_selected:-none}"
                                    echo "  Modules: ${modules_on[*]:-none}"
                                    press_enter
                                    break
                                fi
                            fi
                        done
                    fi
                    ;;
                3)
                    if [ ! -f "$default_cli_file" ]; then
                        touch "$default_cli_file"
                        cecho "$YELLOW" "File $default_cli_file did not exist and was created. It is empty."
                    else
                        mapfile -t cli_lines < "$default_cli_file"
                        total_lines=${#cli_lines[@]}
                        page_size=9
                        page=0
                        while true; do
                            clear
                            cecho "$YELLOW" "Delete Saved CLI Commands (Page $((page+1))):"
                            start=$((page * page_size))
                            end=$((start + page_size - 1))
                            for ((i=start; i<=end && i<total_lines; i++)); do
                                printf "%2d) %s\n" $((i+1)) "${cli_lines[$i]}"
                            done
                            echo
                            echo "Use ←/→ arrows to change page, 0 to return to menu."
                            echo "Press a number (1-9) to delete that command."
                            IFS= read -rsn1 key
                            if [[ $key == $'\x1b' ]]; then
                                read -rsn2 -t 0.1 rest
                                key+="$rest"
                                if [[ $key == $'\x1b[C' ]]; then
                                    (( (page+1)*page_size < total_lines )) && ((page++))
                                elif [[ $key == $'\x1b[D' ]]; then
                                    (( page > 0 )) && ((page--))
                                fi
                            elif [[ $key == "0" ]]; then
                                break
                            elif [[ $key =~ [1-9] ]]; then
                                idx=$((start + key - 1))
                                if (( idx < total_lines )); then
                                    unset 'cli_lines[idx]'
                                    printf "%s\n" "${cli_lines[@]}" > "$default_cli_file"
                                    cecho "$GREEN" "Deleted command #$((idx+1))."
                                    press_enter
                                fi
                            fi
                        done
                    fi
                    ;;
                0) ;;
                *) cecho "$RED" "Invalid option." ;;
            esac
            press_enter
            continue
            ;;
        0)
            cecho "$GREEN" "Goodbye!"
            exit 0
            ;;
        *)
            cecho "$RED" "Invalid option."
            continue
            ;;
    esac
done
