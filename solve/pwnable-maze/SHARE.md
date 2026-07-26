# pwnable-maze — IN PROGRESS / STUCK ⏸

> 팀 공유용 handoff. **풀이과정(어떻게 도달했나) 포함.**

## 풀이과정 (진행 순서 — 시도·배제·핵심착상)
1. **[🔎 정찰/맥락]** pwnable.kr maze selected: Grotesque no local attempt; target ssh maze@pwnable.kr -p2222 pw guest / nc pwnable.kr 10038; no auto-submit
2. **[? 가설]** At level 20, gets(local_38[48]) permits saved-RIP control at offset 56; ret-to-hidden FUN_004017b4 (system /bin/sh) should yield a local shell after deterministic maze completion.
3. **[→ 다음]** Implement local visual-state maze driver, concrete-verify all 20 levels, then measure gets RIP offset with a minimal cyclic payload.
4. **[📏 측정]** `gets_saved_rip = 56`  (static frame: local_38[48] + saved RBP(8); must still concrete-verify after game completion)
5. **[📏 측정]** `hidden_shell = 0x4007b4`  (decomp FUN_004017b4: system("/bin/sh"))
6. **[✗ 배제]** naive visual shortest-path maze driver — locally clears levels 1-3, then level 4 has a guard-blocked route and player is caught; this is not a completed-game or RIP-control verification
7. **[🔎 정찰/맥락]** measurement checkpoint: pwnable-maze elapsed=325s tokens=36090; solve.py added as local game-state driver, no remote attempt and no automatic submission.
8. **[→ 다음]** Model the deterministic guard PRNG/time-expanded maze state or derive the intended OPENSESAMI skip; only after local level-20 completion perform a minimal RIP-control probe.
9. **[🔎 정찰/맥락]** final handoff measurement: pwnable-maze elapsed=424s tokens=41499; incomplete, no remote attempt.

## Gate Status
- Primitive: BLOCKED — hypothesis exists but no `primitive ... pass` evidence is recorded.
- Exploit chaining / remote attempt: BLOCKED until a primitive PASS is recorded.
- Active hypotheses:
  - At level 20, gets(local_38[48]) permits saved-RIP control at offset 56; ret-to-hidden FUN_004017b4 (system /bin/sh) should yield a local shell after deterministic maze completion.

## 검증된 오프셋/상수 (live 측정)
| key | value | src |
|---|---|---|
| `gets_saved_rip` | `56` | static frame: local_38[48] + saved RBP(8); must still concrete-verify after game completion |
| `hidden_shell` | `0x4007b4` | decomp FUN_004017b4: system("/bin/sh") |

## 배제된 것 (재시도 금지)
- ❌ naive visual shortest-path maze driver — locally clears levels 1-3, then level 4 has a guard-blocked route and player is caught; this is not a completed-game or RIP-control verification

## 막힌 지점 / 다음 단계
- Implement local visual-state maze driver, concrete-verify all 20 levels, then measure gets RIP offset with a minimal cyclic payload.
- Model the deterministic guard PRNG/time-expanded maze state or derive the intended OPENSESAMI skip; only after local level-20 completion perform a minimal RIP-control probe.

## 재현
- 스크립트: `solve.py`
- 실행: `cd pwnable-maze && python3 solve.py`
