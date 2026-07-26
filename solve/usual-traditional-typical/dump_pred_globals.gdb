set debuginfod enabled off
set disable-randomization on
set pagination off
set confirm off
set print thread-events off

b *0x555555554000+0x161487
commands
  silent
  set $obj = $rbp - 0x90
  dump binary memory check_mid_globals.bin 0x555555554000+0x267780 0x555555554000+0x2a4000
  dump binary memory check_mid_stack.bin $rbp-0x23000 $rbp+0x100
  dump binary memory check_mid_object.bin $obj $obj+0x90
  printf "captured rbp=%#lx rsp=%#lx obj=%#lx mask=%#lx\n", $rbp, $rsp, $obj, *(long*)($obj+0x80)
  quit
end

run DH{eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee}
