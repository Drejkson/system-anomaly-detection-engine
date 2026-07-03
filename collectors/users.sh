#!/usr/bin/env bash
# users.sh — kolektor kont i uwierzytelniania.
#
# Punkty kontrolne:
#   user_uid0          — konto o UID=0 inne niż root (ukryty superużytkownik)
#   user_dup_uid       — zduplikowany UID (dwa konta, ten sam identyfikator)
#   user_empty_pass    — konto z pustym hasłem (jeśli /etc/shadow czytelny)
#   user_shell_system  — konto systemowe (UID<1000) z interaktywną powłoką
#   user_sudo_nopasswd — reguła sudoers z NOPASSWD (jeśli czytelna)

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "${here}/_lib.sh"

NAME="users"

REAL_SHELLS="/bin/sh /bin/bash /bin/dash /bin/zsh /bin/ksh /usr/bin/bash /usr/bin/zsh /usr/bin/fish"

collect_passwd() {
    [ -r /etc/passwd ] || return 0
    # Wykrywanie duplikatów UID.
    awk -F: '{print $3}' /etc/passwd | sort | uniq -d > /tmp/.dup_uids.$$ 2>/dev/null

    while IFS=: read -r username _ uid gid _ home shell; do
        [ -n "$username" ] || continue

        # user_uid0 — UID 0 nie będące rootem.
        if [ "$uid" = "0" ] && [ "$username" != "root" ]; then
            emit user_uid0 "user=${username}" "uid=0" "shell=${shell}"
        fi

        # user_dup_uid
        if grep -qx "$uid" /tmp/.dup_uids.$$ 2>/dev/null; then
            emit user_dup_uid "user=${username}" "uid=${uid}"
        fi

        # user_shell_system — konto systemowe z realną powłoką.
        if [ -n "${uid:-}" ] && [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ]; then
            case " $REAL_SHELLS " in
                *" $shell "*)
                    emit user_shell_system "user=${username}" "uid=${uid}" \
                         "shell=${shell}"
                    ;;
            esac
        fi
    done < /etc/passwd

    rm -f /tmp/.dup_uids.$$ 2>/dev/null
}

collect_shadow() {
    # Wymaga uprawnień do odczytu /etc/shadow; jeśli brak — po cichu pomiń.
    [ -r /etc/shadow ] || return 0
    while IFS=: read -r username pass _; do
        [ -n "$username" ] || continue
        # Puste pole hasła = logowanie bez hasła.
        if [ -z "$pass" ]; then
            emit user_empty_pass "user=${username}"
        fi
    done < /etc/shadow
}

collect_sudoers() {
    [ -r /etc/sudoers ] || return 0
    local files=(/etc/sudoers)
    [ -d /etc/sudoers.d ] && for f in /etc/sudoers.d/*; do
        [ -r "$f" ] && files+=("$f")
    done
    local file rule
    while IFS= read -r line; do
        file="${line%%:*}"
        rule="$(sed 's/^[^:]*:[0-9]*://' <<<"$line" | tr -s ' ')"
        emit user_sudo_nopasswd "file=${file}" "rule=${rule}"
    done < <(grep -RHnE 'NOPASSWD' "${files[@]}" 2>/dev/null)
}

collect_passwd
collect_shadow
collect_sudoers
finish "$NAME"
