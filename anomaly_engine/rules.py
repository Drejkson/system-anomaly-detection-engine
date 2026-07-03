"""Reguły analizy dynamicznej — serce silnika wykrywania anomalii.

Każda reguła to funkcja przyjmująca listę :class:`CollectorResult` oraz
:class:`Baseline`, a zwracająca listę :class:`Finding`. Reguły są bezstanowe i
niezależne, więc łatwo je testować pojedynczo (patrz ``tests/``).

Dwie klasy reguł:
  1. Bezwzględne wskaźniki kompromitacji (nie wymagają baseline) — np. proces z
     usuniętą binarką, konto UID 0 poza whitelistą.
  2. Odchylenia od baseline — np. nowa binarka SUID, nieznany port nasłuchujący,
     osłabione ustawienie jądra.
"""

from __future__ import annotations

from typing import Callable, Dict, List

from .baseline import Baseline
from .model import CollectorResult, Finding, Observation, Severity

# ---------------------------------------------------------------------------
# Pomocnicze
# ---------------------------------------------------------------------------

def _iter(results: List[CollectorResult], checkpoint: str):
    """Iteruje po obserwacjach danego punktu kontrolnego ze wszystkich kolektorów."""
    for res in results:
        for obs in res.observations:
            if obs.checkpoint == checkpoint:
                yield obs


# ---------------------------------------------------------------------------
# Reguła 0: walidacja odpowiedzi kolektorów (integralność monitoringu)
# ---------------------------------------------------------------------------

def rule_collector_integrity(results: List[CollectorResult], baseline: Baseline) -> List[Finding]:
    findings: List[Finding] = []
    for res in results:
        if res.valid:
            continue
        if res.return_code != 0:
            reason = f"kod wyjścia {res.return_code}"
        elif not res.sentinel_ok:
            reason = "brak sentinela zakończenia (możliwe obcięcie/manipulacja)"
        else:
            reason = (
                f"niespójna liczba rekordów: zadeklarowano {res.reported_count}, "
                f"odebrano {len(res.observations)}"
            )
        findings.append(
            Finding(
                rule_id="collector_integrity",
                severity=Severity.HIGH,
                checkpoint=f"collector:{res.name}",
                title=f"Kolektor '{res.name}' nie przeszedł walidacji odpowiedzi",
                detail=(
                    f"Kolektor nie zwrócił wiarygodnej odpowiedzi ({reason}). "
                    "Ślepa plama w monitoringu sama w sobie jest powierzchnią ataku."
                ),
                evidence={
                    "return_code": str(res.return_code),
                    "stderr": (res.stderr[:300] if res.stderr else ""),
                },
                remediation="Sprawdź uprawnienia i zależności kolektora; uruchom go ręcznie.",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Reguły bezwzględne (bez baseline)
# ---------------------------------------------------------------------------

def rule_deleted_exe(results, baseline) -> List[Finding]:
    out = []
    for obs in _iter(results, "process_deleted_exe"):
        out.append(Finding(
            rule_id="process_deleted_exe",
            severity=Severity.CRITICAL,
            checkpoint="process_deleted_exe",
            title="Proces działa z usuniętej binarki",
            detail=("Binarka procesu została usunięta z dysku, ale proces wciąż "
                    "działa — klasyczny wskaźnik złośliwego oprogramowania."),
            evidence=dict(obs.fields),
            remediation="Zbadaj proces (pid), zrzuć /proc/<pid>/exe do analizy, izoluj host.",
        ))
    return out


def rule_memfd_exe(results, baseline) -> List[Finding]:
    out = []
    for obs in _iter(results, "process_memfd_exe"):
        out.append(Finding(
            rule_id="process_memfd_exe",
            severity=Severity.CRITICAL,
            checkpoint="process_memfd_exe",
            title="Proces wykonywany z pamięci (memfd)",
            detail="Wykonanie bez pliku na dysku — technika unikania detekcji.",
            evidence=dict(obs.fields),
            remediation="Zrzuć pamięć procesu, zbadaj pochodzenie, izoluj host.",
        ))
    return out


def rule_suspicious_parent(results, baseline) -> List[Finding]:
    out = []
    for obs in _iter(results, "process_suspicious_parent"):
        out.append(Finding(
            rule_id="process_suspicious_parent",
            severity=Severity.HIGH,
            checkpoint="process_suspicious_parent",
            title="Powłoka zrodzona przez demon sieciowy",
            detail=(f"Powłoka '{obs.get('comm')}' ma rodzica '{obs.get('parent')}' "
                    "— typowy wzorzec reverse-shell po eksploatacji usługi."),
            evidence=dict(obs.fields),
            remediation="Zweryfikuj legalność; sprawdź logi usługi rodzica.",
        ))
    return out


def rule_uid0(results, baseline) -> List[Finding]:
    out = []
    allowed = set(baseline.allowed_uid0_users)
    for obs in _iter(results, "user_uid0"):
        user = obs.get("user")
        if user in allowed:
            continue
        out.append(Finding(
            rule_id="user_uid0",
            severity=Severity.CRITICAL,
            checkpoint="user_uid0",
            title=f"Konto UID 0 poza whitelistą: {user}",
            detail="Konto z uprawnieniami roota, którego nie ma w zatwierdzonym baseline.",
            evidence=dict(obs.fields),
            remediation="Zweryfikuj i usuń nieautoryzowane konto UID 0.",
        ))
    return out


def rule_empty_pass(results, baseline) -> List[Finding]:
    out = []
    for obs in _iter(results, "user_empty_pass"):
        out.append(Finding(
            rule_id="user_empty_pass",
            severity=Severity.CRITICAL,
            checkpoint="user_empty_pass",
            title=f"Konto bez hasła: {obs.get('user')}",
            detail="Logowanie możliwe bez hasła.",
            evidence=dict(obs.fields),
            remediation="Ustaw hasło lub zablokuj konto (passwd -l).",
        ))
    return out


def rule_dup_uid(results, baseline) -> List[Finding]:
    out = []
    seen = set()
    for obs in _iter(results, "user_dup_uid"):
        key = (obs.get("uid"), obs.get("user"))
        if key in seen:
            continue
        seen.add(key)
        out.append(Finding(
            rule_id="user_dup_uid",
            severity=Severity.HIGH,
            checkpoint="user_dup_uid",
            title=f"Zduplikowany UID {obs.get('uid')} ({obs.get('user')})",
            detail="Dwa konta dzielą ten sam UID — ukrywanie tożsamości/uprawnień.",
            evidence=dict(obs.fields),
            remediation="Nadaj unikalne UID-y kontom.",
        ))
    return out


def rule_shell_system(results, baseline) -> List[Finding]:
    out = []
    for obs in _iter(results, "user_shell_system"):
        out.append(Finding(
            rule_id="user_shell_system",
            severity=Severity.MEDIUM,
            checkpoint="user_shell_system",
            title=f"Konto systemowe z powłoką: {obs.get('user')}",
            detail="Konto systemowe (UID<1000) ma interaktywną powłokę logowania.",
            evidence=dict(obs.fields),
            remediation="Ustaw powłokę na /usr/sbin/nologin, jeśli logowanie nie jest potrzebne.",
        ))
    return out


def rule_sudo_nopasswd(results, baseline) -> List[Finding]:
    out = []
    for obs in _iter(results, "user_sudo_nopasswd"):
        out.append(Finding(
            rule_id="user_sudo_nopasswd",
            severity=Severity.MEDIUM,
            checkpoint="user_sudo_nopasswd",
            title="Reguła sudoers z NOPASSWD",
            detail="sudo bez hasła zwiększa skutki przejęcia konta.",
            evidence=dict(obs.fields),
            remediation="Ogranicz NOPASSWD do niezbędnego minimum.",
        ))
    return out


# ---------------------------------------------------------------------------
# Reguły odchyleń od baseline
# ---------------------------------------------------------------------------

def rule_new_suid(results, baseline) -> List[Finding]:
    out = []
    known = set(baseline.known_suid)
    for obs in _iter(results, "fs_suid"):
        path = obs.get("path")
        if path in known:
            continue
        # Bez baseline (tryb domyślny) nie znamy „dobrych" SUID-ów — zgłaszamy
        # jako informacyjne, aby nie zalać raportu. Z baseline: HIGH.
        sev = Severity.HIGH if baseline.loaded_from_file else Severity.INFO
        out.append(Finding(
            rule_id="fs_new_suid",
            severity=sev,
            checkpoint="fs_suid",
            title=f"Binarka SUID/SGID spoza baseline: {path}",
            detail="Nowa binarka z podniesionymi uprawnieniami — potencjalny wektor eskalacji.",
            evidence=dict(obs.fields),
            remediation="Zweryfikuj pochodzenie; usuń bit SUID, jeśli zbędny (chmod u-s).",
        ))
    return out


def rule_world_writable(results, baseline) -> List[Finding]:
    out = []
    for obs in _iter(results, "fs_world_writable"):
        out.append(Finding(
            rule_id="fs_world_writable",
            severity=Severity.HIGH,
            checkpoint="fs_world_writable",
            title=f"Plik systemowy zapisywalny dla wszystkich: {obs.get('path')}",
            detail="Każdy użytkownik może modyfikować plik systemowy.",
            evidence=dict(obs.fields),
            remediation="Odbierz prawo zapisu innym (chmod o-w).",
        ))
    return out


def rule_ww_dir(results, baseline) -> List[Finding]:
    out = []
    for obs in _iter(results, "fs_ww_dir_nosticky"):
        out.append(Finding(
            rule_id="fs_ww_dir_nosticky",
            severity=Severity.MEDIUM,
            checkpoint="fs_ww_dir_nosticky",
            title=f"Katalog zapisywalny dla wszystkich bez sticky bit: {obs.get('path')}",
            detail="Pozwala na podmianę plików innych użytkowników.",
            evidence=dict(obs.fields),
            remediation="Dodaj sticky bit (chmod +t) lub odbierz prawo zapisu.",
        ))
    return out


def rule_path_writable(results, baseline) -> List[Finding]:
    out = []
    for obs in _iter(results, "fs_path_writable"):
        out.append(Finding(
            rule_id="fs_path_writable",
            severity=Severity.HIGH,
            checkpoint="fs_path_writable",
            title=f"Katalog z PATH zapisywalny: {obs.get('path')}",
            detail="Możliwa podmiana binarek uruchamianych z PATH (hijacking).",
            evidence=dict(obs.fields),
            remediation="Odbierz prawa zapisu grupie/innym dla katalogu z PATH.",
        ))
    return out


def rule_orphan(results, baseline) -> List[Finding]:
    out = []
    for obs in _iter(results, "fs_orphan"):
        out.append(Finding(
            rule_id="fs_orphan",
            severity=Severity.LOW,
            checkpoint="fs_orphan",
            title=f"Plik bez właściciela: {obs.get('path')}",
            detail="UID/GID pliku nie odpowiada żadnemu kontu — pozostałość po usuniętym użytkowniku.",
            evidence=dict(obs.fields),
            remediation="Przypisz właściciela lub usuń plik.",
        ))
    return out


def rule_listen_port(results, baseline) -> List[Finding]:
    out = []
    allowed = set(baseline.allowed_listen_ports)
    for obs in _iter(results, "net_listen"):
        try:
            port = int(obs.get("port"))
        except ValueError:
            continue
        if port in allowed:
            continue
        sev = Severity.MEDIUM if baseline.loaded_from_file else Severity.INFO
        out.append(Finding(
            rule_id="net_unexpected_listen",
            severity=sev,
            checkpoint="net_listen",
            title=f"Nieoczekiwany port nasłuchujący: {port}/{obs.get('proto')}",
            detail=(f"Usługa '{obs.get('comm')}' nasłuchuje na porcie spoza baseline — "
                    "dodatkowa powierzchnia ataku."),
            evidence=dict(obs.fields),
            remediation="Zweryfikuj usługę; wyłącz, jeśli nieautoryzowana.",
        ))
    return out


def rule_promisc(results, baseline) -> List[Finding]:
    out = []
    for obs in _iter(results, "net_promisc"):
        out.append(Finding(
            rule_id="net_promisc",
            severity=Severity.HIGH,
            checkpoint="net_promisc",
            title=f"Interfejs w trybie promiscuous: {obs.get('iface')}",
            detail="Interfejs przechwytuje cały ruch — możliwy podsłuch (sniffing).",
            evidence=dict(obs.fields),
            remediation="Wyłącz tryb promiscuous, jeśli nie jest wymagany.",
        ))
    return out


def rule_new_module(results, baseline) -> List[Finding]:
    out = []
    known = set(baseline.known_modules)
    if not baseline.loaded_from_file:
        return out  # bez baseline lista modułów jest zbyt szumna
    for obs in _iter(results, "sys_module"):
        name = obs.get("name")
        if name in known:
            continue
        out.append(Finding(
            rule_id="sys_new_module",
            severity=Severity.MEDIUM,
            checkpoint="sys_module",
            title=f"Moduł jądra spoza baseline: {name}",
            detail="Załadowany moduł jądra, którego nie ma w zatwierdzonym stanie.",
            evidence=dict(obs.fields),
            remediation="Zweryfikuj pochodzenie modułu; rozważ wyładowanie (rmmod).",
        ))
    return out


def rule_new_cron(results, baseline) -> List[Finding]:
    out = []
    known = set(baseline.known_cron)
    if not baseline.loaded_from_file:
        return out
    for obs in _iter(results, "sys_cron"):
        entry = obs.get("entry")
        if entry in known:
            continue
        out.append(Finding(
            rule_id="sys_new_cron",
            severity=Severity.MEDIUM,
            checkpoint="sys_cron",
            title="Wpis crona spoza baseline",
            detail="Nowe zadanie cron — możliwy mechanizm utrwalenia (persistence).",
            evidence=dict(obs.fields),
            remediation="Zweryfikuj wpis; usuń, jeśli nieautoryzowany.",
        ))
    return out


def rule_sysctl(results, baseline) -> List[Finding]:
    """Porównuje ustawienia jądra z oczekiwanym stanem utwardzonym."""
    out = []
    expected = baseline.expected_sysctl
    labels = {
        "sys_aslr": "ASLR (randomize_va_space)",
        "sys_ptrace_scope": "ptrace_scope",
        "sys_dmesg_restrict": "dmesg_restrict",
        "sys_kptr_restrict": "kptr_restrict",
    }
    for cp, label in labels.items():
        exp = expected.get(cp)
        if exp is None:
            continue
        for obs in _iter(results, cp):
            actual = obs.get("value")
            if actual == exp:
                continue
            # ASLR wyłączony jest szczególnie istotny dla eksploitacji.
            sev = Severity.HIGH if cp == "sys_aslr" else Severity.MEDIUM
            out.append(Finding(
                rule_id=f"{cp}_deviation",
                severity=sev,
                checkpoint=cp,
                title=f"Osłabione ustawienie jądra: {label} = {actual} (oczekiwano {exp})",
                detail="Odchylenie od utwardzonej konfiguracji ułatwia eksploitację.",
                evidence={"actual": actual, "expected": exp},
                remediation=f"Przywróć zalecaną wartość przez sysctl (oczekiwano {exp}).",
            ))
    return out


def rule_core_pattern(results, baseline) -> List[Finding]:
    out = []
    for obs in _iter(results, "sys_core_pattern"):
        val = obs.get("value", "")
        if val.startswith("|"):
            out.append(Finding(
                rule_id="sys_core_pattern_pipe",
                severity=Severity.MEDIUM,
                checkpoint="sys_core_pattern",
                title="core_pattern przekierowany do programu",
                detail=(f"Zrzuty pamięci trafiają do programu ({val}); przy błędnej "
                        "konfiguracji może to być wektor wykonania kodu."),
                evidence=dict(obs.fields),
                remediation="Zweryfikuj program obsługujący core dump.",
            ))
    return out


# Rejestr wszystkich reguł uruchamianych przez silnik.
ALL_RULES: List[Callable[[List[CollectorResult], Baseline], List[Finding]]] = [
    rule_collector_integrity,
    rule_deleted_exe,
    rule_memfd_exe,
    rule_suspicious_parent,
    rule_uid0,
    rule_empty_pass,
    rule_dup_uid,
    rule_shell_system,
    rule_sudo_nopasswd,
    rule_new_suid,
    rule_world_writable,
    rule_ww_dir,
    rule_path_writable,
    rule_orphan,
    rule_listen_port,
    rule_promisc,
    rule_new_module,
    rule_new_cron,
    rule_sysctl,
    rule_core_pattern,
]


def evaluate(results: List[CollectorResult], baseline: Baseline) -> List[Finding]:
    """Uruchamia wszystkie reguły i zwraca znaleziska posortowane wg istotności."""
    findings: List[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(results, baseline))
    findings.sort(key=lambda f: f.severity, reverse=True)
    return findings
