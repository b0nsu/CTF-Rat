set debuginfod enabled off
set disable-randomization on
set pagination off
set confirm off
set print thread-events off

b *0x555555554000+0x21af60
commands
  silent
  printf "CALLBACK rdi=%#lx rsp=%#lx rbp=%#lx ret=%#lx\n", $rdi, $rsp, $rbp, *(void**)$rsp
  x/12gx $rdi
  dump binary memory callback_arg.bin $rdi $rdi+0x100
  dump binary memory callback_globals.bin 0x555555554000+0x267780 0x555555554000+0x2a4000
  quit
end

run DH{eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee}
