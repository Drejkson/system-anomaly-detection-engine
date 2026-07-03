#!/usr/bin/env bash
# system.sh — kolektor konfiguracji jądra i stanu systemu.
#
# Wiele z tych punktów ma bezpośrednie znaczenie dla badań podatności:
# osłabione zabezpieczenia jądra ułatwiają eksploitację.
#
# Punkty kontrolne:
#   sys_aslr           — kernel.randomize_va_space (ASLR)
#   sys_ptrace_scope   — kernel.yama.ptrace_scope
#   sys_dmesg_restrict — kernel.dmesg_restrict
#   sys_kptr_restrict  — kernel.kptr_restrict
#   sys_core_pattern   — kernel.core_pattern (potok do programu = ryzyko)
#   sys_unpriv_bpf     — kernel.unprivileged_bpf_disabled
#   sys_module         — załadowany moduł jądra
#   sys_cron           — wpis crona (systemowy)

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "${here}/_lib.sh"

NAME="system"

read_sysctl() {
    # read_sysctl <checkpoint_id> <ścieżka /proc/sys/...>
    local id="$1" path="$2" val
    if [ -r "$path" ]; then
        val="$(tr -d '\n' < "$path" 2>/dev/null)"
        emit "$id" "value=${val}"
    fi
}

collect_sysctls() {
    read_sysctl sys_aslr           /proc/sys/kernel/randomize_va_space
    read_sysctl sys_ptrace_scope   /proc/sys/kernel/yama/ptrace_scope
    read_sysctl sys_dmesg_restrict /proc/sys/kernel/dmesg_restrict
    read_sysctl sys_kptr_restrict  /proc/sys/kernel/kptr_restrict
    read_sysctl sys_unpriv_bpf     /proc/sys/kernel/unprivileged_bpf_disabled
    if [ -r /proc/sys/kernel/core_pattern ]; then
        emit sys_core_pattern "value=$(tr -d '\n' </proc/sys/kernel/core_pattern)"
    fi
}

collect_modules() {
    [ -r /proc/modules ] || return 0
    # Czytanie z pliku przez przekierowanie (nie potok) zachowuje licznik obserwacji.
    while read -r modname _; do
        [ -n "$modname" ] || continue
        emit sys_module "name=${modname}"
    done < /proc/modules
}

collect_cron() {
    local f line
    for f in /etc/crontab /etc/cron.d/*; do
        [ -r "$f" ] || continue
        # Czytamy plik bezpośrednio (przekierowanie) i filtrujemy komentarze/puste
        # linie za pomocą case — bez potoku, więc licznik obserwacji jest zachowany.
        while IFS= read -r line; do
            case "$line" in
                ''|\#*) continue ;;
            esac
            emit sys_cron "file=${f}" "entry=$(tr -s ' ' <<<"$line")"
        done < "$f"
    done
}

collect_sysctls
collect_modules
collect_cron
finish "$NAME"
