#!/usr/bin/env bash
# network.sh — kolektor stanu sieci.
#
# Punkty kontrolne:
#   net_listen        — gniazda nasłuchujące (TCP/UDP) + port/proces
#   net_promisc       — interfejs w trybie promiscuous (podsłuch ruchu)
#   net_established    — nawiązane połączenia do adresów spoza pętli zwrotnej

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "${here}/_lib.sh"

NAME="network"

collect_listen() {
    # ss preferowane; fallback do netstat.
    # Podstawianie procesu zamiast potoku, aby licznik obserwacji przetrwał
    # (potok tworzy podpowłokę i gubi stan zmiennej licznika).
    if have ss; then
        # -H bez nagłówka, -t/-u TCP/UDP, -l nasłuch, -n numerycznie, -p proces
        local proto local_addr port comm
        while IFS= read -r line; do
            proto="$(awk '{print $1}' <<<"$line")"
            local_addr="$(awk '{print $5}' <<<"$line")"
            port="${local_addr##*:}"
            comm="$(sed -n 's/.*users:(("\([^"]*\)".*/\1/p' <<<"$line")"
            [ -n "$port" ] || continue
            emit net_listen "proto=${proto}" "local=${local_addr}" \
                 "port=${port}" "comm=${comm:-unknown}"
        done < <(ss -Htulnp 2>/dev/null)
    elif have netstat; then
        local proto local_addr port
        while IFS= read -r line; do
            proto="$(awk '{print $1}' <<<"$line")"
            local_addr="$(awk '{print $4}' <<<"$line")"
            port="${local_addr##*:}"
            [ -n "$port" ] || continue
            emit net_listen "proto=${proto}" "local=${local_addr}" "port=${port}"
        done < <(netstat -tulnp 2>/dev/null | awk 'NR>2{print}')
    fi
}

collect_promisc() {
    local iface
    have ip || return 0
    while IFS= read -r line; do
        iface="$(awk -F': ' '{print $2}' <<<"$line")"
        if grep -q "PROMISC" <<<"$line"; then
            emit net_promisc "iface=${iface}"
        fi
    done < <(ip -o link show 2>/dev/null)
}

collect_established() {
    have ss || return 0
    local peer paddr pport
    while IFS= read -r line; do
        peer="$(awk '{print $4}' <<<"$line")"   # peer address:port
        paddr="${peer%:*}"
        pport="${peer##*:}"
        # Pomiń pętlę zwrotną — interesują nas połączenia wychodzące na zewnątrz.
        case "$paddr" in
            127.*|::1|"[::1]") continue ;;
        esac
        [ -n "$paddr" ] || continue
        emit net_established "peer=${paddr}" "port=${pport}"
    done < <(ss -Htn state established 2>/dev/null)
}

collect_listen
collect_promisc
collect_established
finish "$NAME"
