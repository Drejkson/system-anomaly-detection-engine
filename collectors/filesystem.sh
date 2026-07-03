#!/usr/bin/env bash
# filesystem.sh — kolektor stanu systemu plików.
#
# Punkty kontrolne:
#   fs_suid            — binarki SUID/SGID (potencjalne wektory eskalacji)
#   fs_world_writable  — pliki zapisywalne dla wszystkich w katalogach systemowych
#   fs_ww_dir_nosticky — katalogi zapisywalne dla wszystkich bez bitu sticky
#   fs_orphan          — pliki bez właściciela (nieistniejący UID/GID)
#   fs_path_writable   — katalog z PATH zapisywalny dla wszystkich (hijacking)
#
# Skanowanie ograniczone do katalogów systemowych, aby uniknąć długiego
# przeszukiwania całego dysku i fałszywych trafień z katalogów użytkownika.

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "${here}/_lib.sh"

NAME="filesystem"

# Katalogi systemowe brane pod uwagę (istniejące).
SYS_DIRS=()
for d in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /etc /lib /opt; do
    [ -d "$d" ] && SYS_DIRS+=("$d")
done

# Uwaga projektowa: pętle while czytają z podstawiania procesu (done < <(...)),
# a nie z potoku (cmd | while). Potok uruchamia pętlę w podpowłoce, przez co
# licznik obserwacji z _lib.sh zostałby utracony i sentinel zgłaszałby 0.

collect_suid() {
    [ "${#SYS_DIRS[@]}" -gt 0 ] || return 0
    # -perm -4000 SUID, -perm -2000 SGID.
    while IFS=$'\t' read -r path owner mode; do
        emit fs_suid "path=${path}" "owner=${owner}" "mode=${mode}"
    done < <(find "${SYS_DIRS[@]}" -xdev -type f \( -perm -4000 -o -perm -2000 \) -printf '%p\t%u\t%m\n' 2>/dev/null)
}

collect_world_writable_files() {
    [ "${#SYS_DIRS[@]}" -gt 0 ] || return 0
    while IFS=$'\t' read -r path owner mode; do
        emit fs_world_writable "path=${path}" "owner=${owner}" "mode=${mode}"
    done < <(find "${SYS_DIRS[@]}" -xdev -type f -perm -0002 -printf '%p\t%u\t%m\n' 2>/dev/null)
}

collect_ww_dirs() {
    [ "${#SYS_DIRS[@]}" -gt 0 ] || return 0
    # Katalog zapisywalny dla wszystkich (-0002) ale BEZ sticky bit (-1000).
    while IFS=$'\t' read -r path mode; do
        emit fs_ww_dir_nosticky "path=${path}" "mode=${mode}"
    done < <(find "${SYS_DIRS[@]}" -xdev -type d -perm -0002 ! -perm -1000 -printf '%p\t%m\n' 2>/dev/null)
}

collect_orphans() {
    [ "${#SYS_DIRS[@]}" -gt 0 ] || return 0
    # -nouser lub -nogroup: pliki, których UID/GID nie ma w bazie użytkowników.
    while IFS=$'\t' read -r path uid gid; do
        emit fs_orphan "path=${path}" "uid=${uid}" "gid=${gid}"
    done < <(find "${SYS_DIRS[@]}" -xdev \( -nouser -o -nogroup \) -printf '%p\t%U\t%G\n' 2>/dev/null | head -n 200)
}

collect_path_writable() {
    local dir mode
    IFS=':' read -ra parts <<<"${PATH}"
    for dir in "${parts[@]}"; do
        [ -d "$dir" ] || continue
        # Katalog z PATH zapisywalny dla grupy/innych = możliwość podmiany binarek.
        if [ -w "$dir" ] && find "$dir" -maxdepth 0 -perm -0022 >/dev/null 2>&1; then
            mode="$(stat -c '%a' "$dir" 2>/dev/null)"
            emit fs_path_writable "path=${dir}" "mode=${mode}"
        fi
    done
}

collect_suid
collect_world_writable_files
collect_ww_dirs
collect_orphans
collect_path_writable
finish "$NAME"
