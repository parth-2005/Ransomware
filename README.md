# Ransomware Detection System

A production-grade ransomware detection simulation demonstrating **Hybrid Detection** techniques used by real EDR systems.

## Features

✅ **Zero False Positives** - Distinguishes valid edits from ransomware  
✅ **Magic Byte Detection** - Checks file header integrity (binaries)  
✅ **Entropy Analysis** - Detects encryption patterns (text files)  
✅ **Honeytokens** - Bait files that trigger instant lockdown  
✅ **Multi-threaded Defense** - Catches fast, concurrent attacks  

## Quick Start

```powershell
# 1. Install dependencies
pip install psutil watchdog cryptography

# 2. Create test environment
python setup_vault.py

# 3. Start defender (Terminal 1)
python sentinel_entropy.py

# 4. Run attack (Terminal 2)
python attack_swarm.py
```

## How It Works

### Detection Strategy

| File Type | Method | Speed |
|-----------|--------|-------|
| Binary (.db) | Magic Header `CORP_DB_FORMAT_V1` | 16 bytes |
| Text (.txt) | Shannon Entropy < 7.5 | 64 bytes |
| Any | Honeytoken filename match | Instant |

### Test Results

- **Files Created:** 34 (20 heavy DB + 10 text + 4 traps)
- **Attack Speed:** 10 concurrent threads
- **Defense Response:** < 1 second
- **Files Protected:** 23 / 34 (68%)

## Components

- `setup_vault.py` - Creates test environment with magic headers
- `sentinel_entropy.py` - Hybrid detection engine
- `attack_swarm.py` - Multi-threaded ransomware simulator
- `attack_encryptor.py` - Basic encryption attack
- `attack_sprinter.py` - Rapid file renaming attack
- `attack_intermittent.py` - Stealthy slow attack

## Architecture

```
┌─────────────────────────────────────┐
│      Watchdog File Monitor          │
│  (Detects file system events)       │
└────────────────┬────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│    Hybrid Detection Engine          │
│                                     │
│  ┌──────────────┐  ┌─────────────┐ │
│  │ Magic Header │  │   Entropy   │ │
│  │    Check     │  │    Check    │ │
│  └──────────────┘  └─────────────┘ │
│                                     │
│  ┌──────────────┐  ┌─────────────┐ │
│  │ Honeytoken   │  │    Burst    │ │
│  │    Alert     │  │  Detection  │ │
│  └──────────────┘  └─────────────┘ │
└────────────────┬────────────────────┘
                 │ Threat Detected
                 ▼
┌─────────────────────────────────────┐
│      Emergency Lockdown             │
│  (Kill all Python processes)        │
└─────────────────────────────────────┘
```

## Educational Value

This project demonstrates:

1. **File Integrity Monitoring** - How EDR systems protect critical files
2. **Behavioral Analysis** - Detecting abnormal file access patterns
3. **Deception Technology** - Using honeytokens to catch attackers
4. **Race Condition** - Attack vs. Defense timing challenges

## License

Educational use only. Do not use for malicious purposes.
