set debuginfod enabled off
set disable-randomization on
set pagination off
set confirm off
set print thread-events off
set logging file hashmix.log
set logging overwrite on
set logging enabled on

b *0x555555554000+0x110d60
commands
 silent
 printf "MIX pc=%#lx ret=%#lx rdi=%#lx\n", $pc-0x555555554000, *(void**)$rsp-0x555555554000, $rdi
 continue
end
disable 1

b *0x555555554000+0x25b4bb
commands
 silent
 printf "HASHCALL obj=%#lx mask80=%#lx\n", *(void**)($rbp-0x18), *(long*)(*(void**)($rbp-0x18)+0x80)
 enable 1
 continue
end

b *0x555555554000+0x25b4c4
commands
 silent
 printf "HASHRET rax=%#lx\n", $rax
 quit
end

run DH{eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee}
