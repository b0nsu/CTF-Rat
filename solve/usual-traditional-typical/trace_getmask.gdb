set debuginfod enabled off
set disable-randomization on
set pagination off
set confirm off
set print thread-events off
set logging file trace_getmask.log
set logging overwrite on
set logging enabled on

b *0x555555554000+0x161474
commands
 silent
 set $obj=$rbp-0x90
 printf "OBJ obj=%#lx\n", $obj
 continue
end

b *0x555555554000+0x172190
commands
 silent
 printf "GET ret=%#lx rdi=%#lx off=%ld idx=%lu val=%u\n", *(void**)$rsp-0x555555554000, $rdi, (long)$rdi-(long)$obj, $rsi, *(unsigned char*)($rdi+$rsi)
 continue
end

b *0x555555554000+0x222af3
commands
 silent
 printf "MASK bit=0 pc=0x222af6 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x14b89c
commands
 silent
 printf "MASK bit=1 pc=0x14b89f rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0xad48a
commands
 silent
 printf "MASK bit=2 pc=0xad48d rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x185036
commands
 silent
 printf "MASK bit=3 pc=0x185039 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x247987
commands
 silent
 printf "MASK bit=4 pc=0x24798a rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x11e977
commands
 silent
 printf "MASK bit=5 pc=0x11e97a rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x1965dc
commands
 silent
 printf "MASK bit=6 pc=0x1965df rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x1ec748
commands
 silent
 printf "MASK bit=7 pc=0x1ec74b rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x203cc5
commands
 silent
 printf "MASK bit=8 pc=0x203cc8 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0xfc46f
commands
 silent
 printf "MASK bit=9 pc=0xfc472 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x1d0a6a
commands
 silent
 printf "MASK bit=10 pc=0x1d0a6d rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x25329e
commands
 silent
 printf "MASK bit=11 pc=0x2532a1 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x1a76f6
commands
 silent
 printf "MASK bit=12 pc=0x1a76f9 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x18ed3a
commands
 silent
 printf "MASK bit=13 pc=0x18ed3d rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x18e486
commands
 silent
 printf "MASK bit=14 pc=0x18e489 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x131c36
commands
 silent
 printf "MASK bit=15 pc=0x131c39 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x2441fc
commands
 silent
 printf "MASK bit=16 pc=0x2441ff rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0xd11bf
commands
 silent
 printf "MASK bit=17 pc=0xd11c2 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x17e3af
commands
 silent
 printf "MASK bit=18 pc=0x17e3b2 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x208afb
commands
 silent
 printf "MASK bit=19 pc=0x208afe rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0xf4464
commands
 silent
 printf "MASK bit=20 pc=0xf4467 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x15bf4d
commands
 silent
 printf "MASK bit=21 pc=0x15bf50 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0xf849e
commands
 silent
 printf "MASK bit=22 pc=0xf84a1 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x172de2
commands
 silent
 printf "MASK bit=23 pc=0x172de5 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x18777a
commands
 silent
 printf "MASK bit=24 pc=0x18777d rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0xe5e3e
commands
 silent
 printf "MASK bit=25 pc=0xe5e41 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0xea70c
commands
 silent
 printf "MASK bit=26 pc=0xea70f rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x216e72
commands
 silent
 printf "MASK bit=27 pc=0x216e75 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x145301
commands
 silent
 printf "MASK bit=28 pc=0x145304 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x111c16
commands
 silent
 printf "MASK bit=29 pc=0x111c19 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x168718
commands
 silent
 printf "MASK bit=30 pc=0x16871b rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0xf13f8
commands
 silent
 printf "MASK bit=31 pc=0xf13fb rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x234e50
commands
 silent
 printf "MASK bit=32 pc=0x234e53 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0xe4e80
commands
 silent
 printf "MASK bit=33 pc=0xe4e83 rdx=%#lx eax=%#x rcx_old=%#lx\n", $rdx, $eax, *(long*)$rax
 continue
end

b *0x555555554000+0x25b4bb
commands
 silent
 printf "PRED mask80=%#lx\n", *(long*)($obj+0x80)
 quit
end
run DH{eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee}
