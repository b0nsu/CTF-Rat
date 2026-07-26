set debuginfod enabled off
set disable-randomization on
set pagination off
set confirm off
set print thread-events off

b *0x555555554000+0x25b4bb
commands
 silent
 set $obj=*(void**)($rbp-0x18)
 dump binary memory pred_pre.bin $obj $obj+0x90
 printf "DUMPED obj=%#lx mask80=%#lx\n", $obj, *(long*)($obj+0x80)
 quit
end

run DH{eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee}
