# t801x(iPhone 8(+)/iPhone 7(+)) fakerootfs + homebutton with palera1n  

## How to use?
- iboot patch  

```
./img4 -i iBoot.im4p -o iBoot -k <ivkey>
./iBoot64Patcher iBoot iBoot_p1 -b "serial=3"
./iBootpatch2 [--t8015/--t8010] iBoot_p1 iBoot_p2
./img4 -i iBoot_p2 -o iBoot.img4 -M IM4M -A -T ibss
```

- boot  
```
./gaster pwn
./irecovery -f iBoot.img4

./irecovery -s
> dorwx
> /upload [payload.bin/payload_t8010.bin]
> go
> go boot
```

## credits
[exploit3dguy](https://gist.github.com/exploit3dguy) for [internationalhackingsolutionsfbi.s](https://gist.github.com/exploit3dguy/a600c1df8b4abd242c9314d20e2961c5)
