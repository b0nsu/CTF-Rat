set debuginfod enabled off
set disable-randomization on
set pagination off
set logging file watch.log
set logging overwrite on
set logging enabled on
b *0x555555554000+0xca280
commands
 silent
 set $obj=*(void**)($rbp-0x30)
 watch *(long*)($obj+0x30)
 commands
  silent
  printf "WATCH pc=%#lx val=%#lx\n", $pc-0x555555554000, *(long*)($obj+0x30)
  continue
 end
 continue
end
b *0x555555554000+0x18f925
commands
 silent
 printf "WRONG pc=%#lx\n", $pc-0x555555554000
 quit
end
run DH{eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee}
