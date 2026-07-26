set debuginfod enabled off
set disable-randomization on
set pagination off
set confirm off
set print thread-events off
set logging file bit0_producer.log
set logging overwrite on
set logging enabled on

b *0x555555554000+0x2076cb
commands
  silent
  set $check_rbp = $rbp
  printf "CHECK rbp=%#lx obj=%#lx\n", $check_rbp, *(void**)($rbp-8)
  set *(unsigned int*)($check_rbp-0xdfa4) = 0xdeadbeef
  watch -l *(unsigned int*)($check_rbp-0xdfa4)
  commands
    silent
    printf "SOURCE_WRITE pc=%#lx value=%#x\n", $pc-0x555555554000, *(unsigned int*)($check_rbp-0xdfa4)
    x/8i $pc-16
    continue
  end
  continue
end

b *0x555555554000+0x222ac3
commands
  silent
  printf "BIT0 source=%#x\n", *(unsigned int*)($rbp-0xdfa4)
  quit
end

run DH{eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee}
