set debuginfod enabled off
set disable-randomization on
set pagination off
set confirm off
set print thread-events off
set logging file watch80.log
set logging overwrite on
set logging enabled on

b *0x555555554000+0x161474
commands
 silent
 set $obj=$rbp-0x90
 printf "OBJ pc=%#lx obj=%#lx watch=%#lx init=%#lx\n", $pc-0x555555554000, $obj, $obj+0x80, *(long*)($obj+0x80)
 watch -l *(long*)($obj+0x80)
 commands
  silent
  printf "WRITE80 pc=%#lx val=%#lx obj=%#lx\n", $pc-0x555555554000, *(long*)($obj+0x80), $obj
  x/6i $pc-8
  bt 6
  continue
 end
 continue
end

b *0x555555554000+0x25b4bb
commands
 silent
 printf "PRED pc=%#lx obj=%#lx mask80=%#lx\n", $pc-0x555555554000, *(void**)($rbp-0x18), *(long*)(*(void**)($rbp-0x18)+0x80)
 continue
end

b *0x555555554000+0x18f925
commands
 silent
 printf "WRONG pc=%#lx\n", $pc-0x555555554000
 quit
end

run DH{eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee}
