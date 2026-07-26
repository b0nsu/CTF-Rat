set debuginfod enabled off
set disable-randomization on
set pagination off
b *0x5555556e3925
run AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
dump memory snap_A44.bin $rbp-0x23000 $rbp
printf "RBP %p\n", $rbp
quit
