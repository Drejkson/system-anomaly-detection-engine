# _lib.sh — wspólne funkcje pomocnicze dla kolektorów.
# Kolektory NIE mają być uruchamiane bezpośrednio z tego pliku; to biblioteka
# dołączana przez `source`. Definiuje jednolity kontrakt wyjścia, dzięki któremu
# silnik Python może walidować odpowiedź każdego kolektora (walidacja odpowiedzi).
#
# Kontrakt wyjścia (stdout):
#   - zero lub więcej rekordów obserwacji, po jednym w linii:
#       <checkpoint_id>\t<klucz>=<wartość>\t<klucz>=<wartość>...
#   - dokładnie jedna linia-sentinel na końcu:
#       __COLLECTOR_OK__ name=<nazwa> observations=<N> rc=0
#
# Jeśli sentinel jest nieobecny albo kod wyjścia != 0, silnik traktuje kolektor
# jako uszkodzony/zmanipulowany i zgłasza to jako anomalię integralności
# monitoringu (ślepa plama = powierzchnia ataku).

set -u

# Licznik obserwacji wyemitowanych przez bieżący kolektor.
__OBS_COUNT=0

# emit <checkpoint_id> [k=v ...] — wypisuje jeden rekord obserwacji.
emit() {
    local id="$1"; shift
    local line="$id"
    local kv
    for kv in "$@"; do
        # Zamień znaki tabulacji/nowej linii w wartościach na spacje,
        # aby nie rozbić formatu rekordu.
        kv="${kv//$'\t'/ }"
        kv="${kv//$'\n'/ }"
        line="${line}"$'\t'"${kv}"
    done
    printf '%s\n' "$line"
    __OBS_COUNT=$((__OBS_COUNT + 1))
}

# finish <nazwa_kolektora> — wypisuje sentinel poprawnego zakończenia.
finish() {
    local name="$1"
    printf '__COLLECTOR_OK__ name=%s observations=%d rc=0\n' "$name" "$__OBS_COUNT"
}

# have <program> — true, jeśli program jest dostępny w PATH.
have() { command -v "$1" >/dev/null 2>&1; }
