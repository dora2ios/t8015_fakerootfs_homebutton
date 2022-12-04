# t8015(iPhone 8(+)) fakerootfs + homebutton with palera1n  

## How to use?
- iboot patch  

```
./img4 -i iBoot.im4p -o iBoot -k <ivkey>
./iBoot64Patcher iBoot iBoot_p1 -b "serial=3"
./iBootpatch2 iBoot_p1 iBoot_p2
./img4 -i iBoot_p2 -o iBoot.img4 -M IM4M -A -T ibss
```

- boot  
```
./gaster pwn
./irecovery -f iBoot.img4

./irecovery -s
> dorwx
> /upload payload.bin
> go
> go boot
```

