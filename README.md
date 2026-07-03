# Silnik wykrywania anomalii i błędów stanu systemu

Zautomatyzowany pakiet monitorujący, który zbiera stan systemu Linux w **20+
punktach kontrolnych**, **waliduje odpowiedzi** każdego kolektora i stosuje
**reguły analizy dynamicznej**, aby wykryć niespójności stanu stanowiące
potencjalną powierzchnię ataku — skracając średni czas wykrycia (MTTD) o
ok. **70%** względem audytu ręcznego.

Projekt powstał w kontekście badań podatności (vulnerability research):
większość checkpointów odpowiada typowym wektorom eskalacji uprawnień, utrwalenia
(persistence) i osłabienia zabezpieczeń jądra ułatwiającego eksploitację.

---

## Kluczowe cechy

- **Kolektory w Bash, silnik w Pythonie** — rozdział zbierania danych (szybkie,
  natywne narzędzia systemowe) od logiki decyzyjnej (testowalne reguły w Pythonie).
- **Walidacja odpowiedzi** — każdy kolektor przestrzega ścisłego kontraktu
  wyjścia (rekordy + sentinel + zgodność liczby rekordów). Kolektor, który padł,
  został obcięty lub zmanipulowany, jest sam w sobie zgłaszany jako anomalia
  (ślepa plama w monitoringu = powierzchnia ataku).
- **Analiza dynamiczna względem baseline** — porównanie stanu bieżącego z
  zatwierdzonym „dobrym stanem"; odchylenie to kandydat na anomalię. Bez baseline
  silnik działa na bezpiecznych wartościach domyślnych.
- **Pomiar MTTD** — raport podaje czas skanu i wyliczoną redukcję względem
  konfigurowalnego czasu audytu ręcznego.
- **Raport JSON i tekstowy** — nadaje się do integracji z CI/monitoringiem
  (kod wyjścia zależny od progu istotności).
- **Zero zależności runtime** — wyłącznie biblioteka standardowa Pythona 3.8+.

---

## Punkty kontrolne (checkpointy)

| Kolektor      | Punkt kontrolny            | Co wykrywa |
|---------------|----------------------------|------------|
| `processes`   | `process_root`             | procesy z EUID=0 |
|               | `process_deleted_exe`      | proces z usuniętej binarki (IOC) |
|               | `process_memfd_exe`        | wykonanie z pamięci (memfd) |
|               | `process_suspicious_parent`| powłoka zrodzona przez demon sieciowy |
| `network`     | `net_listen`               | porty nasłuchujące |
|               | `net_promisc`              | interfejs w trybie promiscuous |
|               | `net_established`          | połączenia wychodzące na zewnątrz |
| `filesystem`  | `fs_suid`                  | binarki SUID/SGID |
|               | `fs_world_writable`        | pliki systemowe zapisywalne dla wszystkich |
|               | `fs_ww_dir_nosticky`       | katalogi zapisywalne bez sticky bit |
|               | `fs_orphan`                | pliki bez właściciela |
|               | `fs_path_writable`         | zapisywalny katalog z `$PATH` |
| `users`       | `user_uid0`                | konto UID 0 poza whitelistą |
|               | `user_dup_uid`             | zduplikowany UID |
|               | `user_empty_pass`          | konto bez hasła |
|               | `user_shell_system`        | konto systemowe z powłoką |
|               | `user_sudo_nopasswd`       | reguła sudoers NOPASSWD |
| `system`      | `sys_aslr`                 | ASLR (randomize_va_space) |
|               | `sys_ptrace_scope`         | ograniczenie ptrace |
|               | `sys_dmesg_restrict`       | dostęp do dmesg |
|               | `sys_kptr_restrict`        | ukrywanie adresów jądra |
|               | `sys_core_pattern`         | przekierowanie core dump do programu |
|               | `sys_module`               | załadowane moduły jądra |
|               | `sys_cron`                 | zadania cron |

Łącznie **26 punktów kontrolnych** w 5 kolektorach.

---

## Architektura

```
                 ┌──────────────────────────────────────────────┐
                 │                 silnik (Python)               │
  ┌───────────┐  │  ┌────────────┐   ┌────────┐   ┌───────────┐  │
  │ kolektory │─────▶│ walidacja  │──▶│ reguły │──▶│  raport   │  │
  │  (Bash)   │  │  │ odpowiedzi │   │        │   │ JSON/tekst│  │
  └───────────┘  │  └────────────┘   └───┬────┘   └───────────┘  │
                 │                       │                        │
                 │                  ┌────▼────┐                   │
                 │                  │ baseline│                   │
                 │                  └─────────┘                   │
                 └──────────────────────────────────────────────┘
```

Moduły:

- `collectors/*.sh` — kolektory Bash (jeden plik = jedna domena stanu).
- `anomaly_engine/collectors.py` — uruchamianie + parsowanie + walidacja odpowiedzi.
- `anomaly_engine/baseline.py` — wczytywanie/tworzenie stanu odniesienia.
- `anomaly_engine/rules.py` — reguły analizy dynamicznej (bezstanowe, testowalne).
- `anomaly_engine/report.py` — metryki (w tym redukcja MTTD) i formatowanie.
- `anomaly_engine/engine.py` — orkiestracja całego cyklu.
- `anomaly_engine/cli.py` — interfejs wiersza poleceń.

---

## Instalacja

Nie wymaga instalacji ani zależności runtime. Wystarczy Python 3.8+ i Bash.

```bash
git clone https://github.com/<twoj-uzytkownik>/silnik-wykrywania-anomalii.git
cd silnik-wykrywania-anomalii
```

---

## Użycie

Skan z bezpiecznymi wartościami domyślnymi:

```bash
python3 -m anomaly_engine scan
```

Zapisz bieżący (czysty) stan jako baseline, a potem skanuj względem niego:

```bash
python3 -m anomaly_engine capture -o baseline.json
python3 -m anomaly_engine scan -b baseline.json
```

Raport w JSON do pliku (np. do dalszej obróbki / CI):

```bash
python3 -m anomaly_engine scan --json -o raport.json
```

Kod wyjścia `1`, gdy znaleziono coś o istotności ≥ HIGH (przydatne w CI):

```bash
python3 -m anomaly_engine scan --fail-on HIGH
```

Demonstracja na symulowanym skompromitowanym hoście (bez dotykania systemu):

```bash
python3 examples/demo.py
```

### Ważne o uprawnieniach

Część checkpointów (np. `/etc/shadow`, pełna lista SUID) wymaga uprawnień roota.
Silnik działa też bez nich — po prostu zbierze mniej danych. Kolektor, który nie
może odczytać zasobu, pomija go po cichu, ale nadal poprawnie kończy się
sentinelem, więc walidacja odpowiedzi przechodzi.

---

## Baseline

Baseline to plik JSON opisujący „stan znany jako dobry". Przykład w
`config/baseline.example.json`. Pola:

- `allowed_listen_ports` — dozwolone porty nasłuchujące,
- `known_suid` — zatwierdzone binarki SUID/SGID,
- `known_modules`, `known_cron` — zatwierdzone moduły jądra i zadania cron,
- `allowed_uid0_users` — konta, które mogą mieć UID 0,
- `expected_sysctl` — oczekiwane, utwardzone wartości ustawień jądra,
- `manual_mttd_seconds` — czas ręcznego audytu (baza do wyliczenia redukcji MTTD).

Bez baseline reguły odchyleń (nowy SUID, nieznany port, nowy moduł/cron) działają
w trybie łagodniejszym (INFO / pominięcie), aby nie zalać raportu.

---

## Metryka MTTD

Silnik mierzy czas zautomatyzowanego cyklu (zbieranie + analiza) i porównuje go z
konfigurowalnym czasem audytu ręcznego (`manual_mttd_seconds`). Raport podaje
procentową redukcję:

```
redukcja = (czas_ręczny − czas_automatyczny) / czas_ręczny
```

Dla przykładowego audytu ręcznego ~15 min i skanu rzędu kilku sekund redukcja
przekracza 70%.

---

## Testy

```bash
pip install -r requirements-dev.txt
pytest
```

Testy jednostkowe pokrywają: reguły wykrywania (progi istotności, whitelisty,
odchylenia od baseline), parsowanie i walidację odpowiedzi kolektorów oraz
metryki raportu (w tym wyliczenie redukcji MTTD).

---

## Ograniczenia i uczciwe zastrzeżenia

- Narzędzie robi migawkę stanu (point-in-time), nie monitoruje ciągłego strumienia
  zdarzeń — do wykrywania w czasie rzeczywistym łączy się je zwykle z harmonogramem
  (cron/systemd timer) lub auditd/eBPF.
- Heurystyki (np. „powłoka zrodzona przez demon") mogą dawać fałszywe trafienia —
  baseline i przegląd przez człowieka pozostają konieczne.
- Metryka redukcji MTTD jest ilustracyjna i zależy od przyjętego czasu audytu
  ręcznego.

## Licencja

MIT — zobacz plik [LICENSE](LICENSE).
