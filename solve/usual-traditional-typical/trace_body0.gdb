set debuginfod enabled off
set disable-randomization on
set pagination off
set logging file body0.log
set logging overwrite on
set logging enabled on
b *0x555555554000+0xca280
commands
 silent
 set $obj=*(void**)($rbp-0x30)
 rwatch *(char*)($obj+0)
 commands
  silent
  printf "READ0 pc=%#lx val=%#x\n", $pc-0x555555554000, *(unsigned char*)($obj+0)
  x/10i $pc-16
  continue
 end
 continue
end
b *0x555555554000+0x18f925
commands
 silent
 printf "WRONG\n"
 quit
end
run DH{eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee}
