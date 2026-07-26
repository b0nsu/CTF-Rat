set debuginfod enabled off
set disable-randomization on
set pagination off
set confirm off
set print thread-events off
set logging file bit0_condition.log
set logging overwrite on
set logging enabled on

b *0x555555554000+0x2076cb
commands
  silent
  set $check_rbp = $rbp
  set *(unsigned int*)($check_rbp-0xdfa0) = 0xdeadbeef
  watch -l *(unsigned int*)($check_rbp-0xdfa0)
  commands
    silent
    printf "COND_WRITE pc=%#lx value=%#x\n", $pc-0x555555554000, *(unsigned int*)($check_rbp-0xdfa0)
    x/10i $pc-20
    continue
  end
  continue
end

b *0x555555554000+0x1671ad
commands
  silent
  printf "COND_FINAL value=%#x\n", *(unsigned int*)($rbp-0xdfa0)
  quit
end

run DH{eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee}
