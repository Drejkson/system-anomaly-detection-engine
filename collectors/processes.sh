#!/usr/bin/env bash
# processy.sh — kolektor stanu procesów.
#
# Punkty kontrolne (checkpointy):
#   process_root          — procesy działające z EUID=0 (potencjalna eskalacja)
#   process_deleted_exe   — procesy, których binarka została usunięta z dysku
#                           (klasyczny wskaźnik złośliwego oprogramowania / IOC)
#   process_memfd_exe     — proces wykonywany z pamięci (memfd:) bez pliku
#   process_suspicious_parent — powłoka zrodzona przez demon sieciowy
#                               (typowy wzorzec reverse-shell)

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "${here}/_lib.sh"

NAME="processes"

# Demony, których dziecko będące powłoką jest podejrzane.
NET_DAEMONS="sshd nginx apache2 httpd vsftpd smbd named postfix dovecot"
SHELLS="sh bash dash zsh ksh"

collect_processes() {
    local pid comm state euid ppid exe_link pcomm
    for pid in /proc/[0-9]*; do
        pid="${pid#/proc/}"
        [ -r "/proc/${pid}/status" ] || continue

        comm="$(cat "/proc/${pid}/comm" 2>/dev/null)"
        [ -n "$comm" ] || continue

        # EUID to drugie pole w wierszu "Uid:" w /proc/<pid>/status.
        euid="$(awk '/^Uid:/{print $3}' "/proc/${pid}/status" 2>/dev/null)"
        ppid="$(awk '/^PPid:/{print $2}' "/proc/${pid}/status" 2>/dev/null)"

        # process_root
        if [ "${euid:-x}" = "0" ]; then
            emit process_root "pid=${pid}" "comm=${comm}" "euid=0"
        fi

        # Analiza dowiązania /proc/<pid>/exe (dynamiczna analiza stanu procesu).
        exe_link="$(readlink "/proc/${pid}/exe" 2>/dev/null || true)"
        if [ -n "$exe_link" ]; then
            case "$exe_link" in
                *"(deleted)")
                    emit process_deleted_exe "pid=${pid}" "comm=${comm}" \
                         "exe=${exe_link}"
                    ;;
                /memfd:*|memfd:*)
                    emit process_memfd_exe "pid=${pid}" "comm=${comm}" \
                         "exe=${exe_link}"
                    ;;
            esac
        fi

        # process_suspicious_parent — powłoka, której rodzicem jest demon sieciowy.
        case " $SHELLS " in
            *" $comm "*)
                if [ -n "${ppid:-}" ] && [ -r "/proc/${ppid}/comm" ]; then
                    pcomm="$(cat "/proc/${ppid}/comm" 2>/dev/null)"
                    case " $NET_DAEMONS " in
                        *" $pcomm "*)
                            emit process_suspicious_parent "pid=${pid}" \
                                 "comm=${comm}" "ppid=${ppid}" "parent=${pcomm}"
                            ;;
                    esac
                fi
                ;;
        esac
    done
}

collect_processes
finish "$NAME"
