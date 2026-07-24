# P0 verification record

검증일: 2026-07-22 (Asia/Seoul)

## 기준 문서

- 파일: `CTF-Rat_bin_architecture_upgrade_report_ko_corrected.pdf`
- SHA-256: `41244dff6a95bfb6269249b180497dfe745f21bb3b6c4bcadb2b7d250e0f9b95`
- P0 근거: 인쇄 페이지 27의 §15.1, 인쇄 페이지 28~29의 B001~B007 표

## 백로그 대조

| ID | PDF 완료 조건 | 구현 및 검증 근거 |
|---|---|---|
| B001 | traversal/link/device/bomb 차단 | `ratlib.safe_archive`, malicious ZIP/TAR·bomb·nested·weird-name fixture |
| B002 | timeout/exit/stdout/stderr/tool version 기록 | `ratlib.runner`, process-group kill, resource/output/env/network fixture; Python `/bin` 호출을 공통 runner로 통합 |
| B003 | failure fixture에서 CI non-zero | `PKSELFTEST_FORCE_FAIL=1` unit fixture와 strict-optional exit 검증 |
| B004 | solve dir 단일 manifest | `newchal --run`, slug/root/symlink 검증, run ID 보존, `manifest_owner=solve`, invalid/different manifest fail-closed |
| B005 | binary/tool/script 변경 시 invalidate | binary SHA, Ghidra version, 두 Ghidra script hash 변경 fixture; partial cache miss |
| B006 | instruction/block schema test | revmap schema 2의 `nblocks`/`ninstr`/`count_quality`와 renderer label selftest |
| B007 | timeout 뒤 Qiling 실행 없음 | instruction hook + `emu_stop()`, fake backend wall timeout 뒤 PID 소멸, missing dependency result |

보고서 §15.1의 추가 항목인 duplicate wrapper는 `pwnclean`을 `pwnkit` compatibility wrapper로 축소해 한 구현만
유지한다. `recon`, `revq`, `state`, `pwnkit`, `teamstate`, `k_dump_heap`, `ctfpull`의 Python subprocess 경로는
`ratlib.runner`로 통합했으며 `shell=True`/`os.system` 사용이 남아 있지 않음을 정적 검색했다.

## 실행 결과

```text
python3 -m unittest -v tests.test_stability
  Ran 39 tests ... OK

python3 bin/ctfpull selftest                       GREEN
python3 bin/revq selftest                          GREEN
python3 solve/_template/rev/symsolve.py selftest   GREEN
python3 solve/_template/rev/vmlift.py selftest     GREEN
bin/pkselftest --format json
  pass=11 fail=0 skip=2 exit=0
python3 tests/e2e_mock.py                          GREEN
bash tests/e2e_rev.sh                              GREEN (real binary + angr)
python3 -m json.tool schemas/rat.run.v1.json        GREEN
bash -n bin/newchal bin/decomp bin/pkselftest      GREEN
git diff --check                                   GREEN
```

`bin/pkselftest --strict-optional --format json`은 이 호스트에서 Qiling package와 선택적 GDB fixture가 없으므로
의도대로 exit 1이다. 일반 matrix에서는 명시적 SKIP이고, Qiling hook/stop은 deterministic fake backend fixture로
검증했다. Ghidra missing/timeout/partial 및 Qiling missing/timeout 결과도 unit fixture로 검증했다.

## 작업 경계

작업 시작 전부터 저장소에는 challenge 산출물과 다른 수정이 존재했다. 이를 삭제·reset·stage하지 않았고, P0 검증은
도구·schema·문서·테스트 경로로 한정했다. 사용자가 커밋을 요청하지 않았으므로 commit/push는 만들지 않았다. 이 문서는
uncommitted P0 구현의 검증 checkpoint이며, 커밋 시에는 `P0_STABILITY.md`의 권장 분할을 사용해 기존 변경과 대조해야 한다.
