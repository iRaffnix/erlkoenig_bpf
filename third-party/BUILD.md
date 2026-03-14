# Third-Party Dependencies — Build-Anleitung

**Stand**: 2026-03-11

---

## Verzeichnisstruktur

```
third-party/
├── src/                          ← Quellcode (git clones)
│   └── ubpf/                     ← iovisor/ubpf (Userspace BPF VM)
│       └── external/
│           └── ebpf-verifier/    ← vbpf/prevail (Formaler BPF-Verifier)
├── bld/                          ← CMake Build-Artefakte
└── lib/                          ← Installierte Libraries + Headers
    ├── include/
    │   ├── ubpf.h
    │   └── ubpf_config.h
    └── lib/
        ├── libubpf.a             ← Static Library (~150 KB)
        └── cmake/ubpf/
```

## Voraussetzungen

```bash
sudo apt install build-essential cmake libelf-dev
```

## uBPF bauen

```bash
cd /path/to/erlkoenig_bpf

# 1. Klonen
git clone https://github.com/iovisor/ubpf.git third-party/src/ubpf

# 2. Submodules (enthaelt bpf_conformance, ebpf-verifier/PREVAIL, elfio)
cd third-party/src/ubpf
git submodule update --init --recursive
cd ../../..

# 3. CMake konfigurieren
cmake -B third-party/bld \
      -S third-party/src/ubpf \
      -DCMAKE_INSTALL_PREFIX=$(pwd)/third-party/lib \
      -DUBPF_ENABLE_TESTS=OFF \
      -DUBPF_ENABLE_INSTALL=ON

# 4. Bauen
make -C third-party/bld -j$(nproc)

# 5. Installieren (nach third-party/lib/)
make -C third-party/bld install
```

## Verifizieren

```bash
# Static Library vorhanden?
ls -la third-party/lib/lib/libubpf.a
# → ~150 KB

# Header vorhanden?
ls third-party/lib/include/ubpf.h
```

## Gegen uBPF linken (fuer ubpf_port.c)

```bash
gcc -O2 -Wall -o priv/ubpf_port c_src/ubpf_port.c \
    -Ithird-party/lib/include \
    -Lthird-party/lib/lib \
    -lubpf -lm
```

## PREVAIL (Bonus-Fund)

PREVAIL (formaler eBPF-Verifier via Abstract Interpretation) wurde als
Submodule von uBPF mitgezogen:

```
third-party/src/ubpf/external/ebpf-verifier/
```

PREVAIL kann als CLI-Tool gebaut werden um BPF-Programme statisch zu
verifizieren — ohne Kernel, ohne Root. Wird fuer WP-017/WP-018 relevant.

PREVAIL separat bauen (optional, spaeter):
```bash
cmake -B third-party/bld-prevail \
      -S third-party/src/ubpf/external/ebpf-verifier \
      -DCMAKE_INSTALL_PREFIX=$(pwd)/third-party/lib
make -C third-party/bld-prevail -j$(nproc)
```

## Aufraumen

```bash
# Nur Build-Artefakte loeschen (Source + installierte Libs bleiben):
rm -rf third-party/bld/*

# Alles loeschen und neu bauen:
rm -rf third-party/bld/* third-party/lib/*
# Dann Schritte 3-5 wiederholen
```
