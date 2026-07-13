# Clockwork_Vault — exploit working memory
> context 압축돼도 여기서 재-orient. 주소/offset은 반드시 확인 후 기록.

- **binary**: clockwork_vault   **remote**: '-'
- **arch/prot**: (recon 결과 붙여넣기)
- **libc**: (버전 / 경로)
- **vuln class**: (stack overflow / fmt / heap-UAF / …)
- **stage**: recon

## offsets
| 이름 | 값 | 확인방법 |
|---|---|---|
| buf→ret | ? | cyclic |

## leaks / gadgets
- libc base: ?
- pop rdi: ?   ret: ?   one_gadget: ?

## plan (체크리스트)
- [ ] recon + triage
- [ ] vuln 함수 확정 (decomp)
- [ ] primitive 확보
- [ ] leak
- [ ] 최종 exploit → flag

## notes
(막힌 지점 / 시도한 것 / 다음 아이디어)

---
### recon
[!] ELF 파싱 실패: [Errno 2] No such file or directory: './clockwork_vault'
./clockwork_vault: cannot open `./clockwork_vault' (No such file or directory)
