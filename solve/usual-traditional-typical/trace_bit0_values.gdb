set debuginfod enabled off
set disable-randomization on
set pagination off
set confirm off
set print thread-events off

b *0x555555554000+0x21c1b0
commands
  silent
  set $obj = *(void**)($rbp-8)
  printf "BIT0 rax_source=%#lx index=%u state0_7=%#lx state8_15=%#lx\n", *(unsigned long*)($rbp-0x438), *(unsigned char*)($rbp-0x39), *(unsigned long*)($obj+0x30), *(unsigned long*)($obj+0x38)
  quit
end

run DH{eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee}
