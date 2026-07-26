# BroncoCTF Results Check

## Official CTFd Result

- Checked via `https://broncoctf.ctfd.io/api/v1` on 2026-07-13.
- Account: `ssttff` (`user_id=1750`)
- Team: `ssttff` (`team_id=969`)
- Team place: `726th`
- Team score: `10`

Official solves returned by CTFd:

| ID | Challenge | Category | Points | Date |
|---:|---|---|---:|---|
| 1 | Welcome to BroncoCTF | Welcome | 10 | 2026-07-12T09:10:50.057417+00:00 |

CTFd reports `solved_by_me=false` for every Pwn/Reversing challenge checked below.

## CTF-Rat Local Work

Local CTF-Rat artifacts contain completed writeups/solvers for these Pwn/Reversing
challenges:

| ID | Challenge | Category | Points | Local status | Artifact |
|---:|---|---|---:|---|---|
| 17 | Proper Pwning | Pwn | 10 | flag recovered locally | `solve/broncoctf/Proper_Pwning/WRITEUP.md` |
| 18 | C++ Unplugged | Reversing | 10 | flag recovered locally | `solve/broncoctf/C_Unplugged/WRITEUP.md` |
| 27 | Cat Simulator | Reversing | 10 | flag recovered locally | `solve/broncoctf/Cat_Simulator/WRITEUP.md` |
| 29 | Mirror Mirror | Reversing | 10 | flag recovered locally | `solve/broncoctf/Mirror_Mirror/WRITEUP.md` |
| 42 | Crab Trap | Pwn | 10 | flag recovered locally | `solve/broncoctf/Crab_Trap/WRITEUP.md` |
| 46 | Dog Simulator | Reversing | 191 | flag recovered locally | `solve/broncoctf/Dog_Simulator/WRITEUP.md` |
| 23 | World's Hardestest Flag | Pwn | 360 | exploit path recovered; live Roblox flag read still required | `solve/broncoctf/Worlds_Hardestest_Flag/WRITEUP.md` |

Confirmed local flag score, excluding the live-read challenge: `241`.
Potential score including World's Hardestest Flag after live flag read/submission: `601`.

## Manual Submission Queue

Flag submission is intentionally manual. Submit these in the CTFd UI:

```text
Proper Pwning: bronco{1m_th3_b35t_PWN3r_1n_th3_wh0l3_w1d3_w0r1d}
C++ Unplugged: bronco{i_c@m3_1n_lik3_@_s3gfAult}
Cat Simulator: bronco{fluffy_baby}
Mirror Mirror: bronco{wh0_1s_th3_f@ir3st_r3v3rs3r}
Crab Trap: bronco{h0w_c4n_mr_kr4b5_c0de}
Dog Simulator: bronco{mans_best_friend}
```

For World's Hardestest Flag, run this in the live Roblox terminal first, then
submit the printed `bronco{...}` value:

```lua
write(0x6767,{["Type".."Tag"]=4});print(read(0x6767))
```

## Conclusion

The provided CTFd token/session does not show official submissions for the Pwn/Reversing
work present in this repo. Officially, that team only solved the welcome challenge.
The local CTF-Rat output shows six Pwn/Reversing flags recovered, but they were not
submitted under this CTFd account/team, or the token belongs to a different account
than the one used for those submissions.
