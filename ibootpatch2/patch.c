#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "offsetfinder.h"
#include "payload.h"

#define INSN_MOV_X0_0           0xd2800000
#define INSN_MOV_X0_1           0xd2800020
#define INSN_RET                0xd65f03c0
#define INSN_NOP                0xd503201f

int open_file(char *file, size_t *sz, unsigned char **buf)
{
    FILE *fd = fopen(file, "r");
    if (!fd) {
        printf("error opening %s\n", file);
        return -1;
    }
    
    fseek(fd, 0, SEEK_END);
    *sz = ftell(fd);
    fseek(fd, 0, SEEK_SET);
    
    *buf = malloc(*sz);
    if (!*buf) {
        printf("error allocating file buffer\n");
        fclose(fd);
        return -1;
    }
    
    fread(*buf, *sz, 1, fd);
    fclose(fd);
    
    return 0;
}

int main(int argc, char **argv)
{
    
    if(argc != 3){
        printf("%s <in> <out>\n", argv[0]);
        return 0;
    }
    
    char *infile = argv[1];
    char *outfile = argv[2];
    
    
    unsigned char* idata;
    size_t isize;
    if(open_file(infile, &isize, &idata))
        return -1;
    assert(isize && idata);
    
    
    {
        //uint64_t iboot_base = 0x18001c000;
        uint64_t iboot_base = *(uint64_t*)(idata + 0x300);
        if(!iboot_base)
            goto end;
        printf("%016llx[%016llx]: iboot_base\n", iboot_base, (uint64_t)0x300);
        
        uint64_t check_bootmode = find_check_bootmode(iboot_base, idata, isize);
        if(!check_bootmode)
            goto end;
        printf("%016llx[%016llx]: check_bootmode\n", check_bootmode + iboot_base, check_bootmode);
        
        uint64_t bootx_str = find_bootx_str(iboot_base, idata, isize);
        if(!bootx_str)
            goto end;
        printf("%016llx[%016llx]: bootx_str\n", bootx_str + iboot_base, bootx_str);
        
        uint64_t bootx_cmd_handler = find_bootx_cmd_handler(iboot_base, idata, isize);
        if(!bootx_cmd_handler)
            goto end;
        printf("%016llx[%016llx]: bootx_cmd_handler\n", bootx_cmd_handler + iboot_base, bootx_cmd_handler);
        
        uint64_t go_cmd_handler = find_go_cmd_handler(iboot_base, idata, isize);
        if(!go_cmd_handler)
            goto end;
        printf("%016llx[%016llx]: go_cmd_handler\n", go_cmd_handler + iboot_base, go_cmd_handler);
        
        uint64_t zeroBuf = find_zero(iboot_base, idata, isize);
        if(!zeroBuf)
            goto end;
        printf("%016llx[%016llx]: zeroBuf\n", zeroBuf + iboot_base, zeroBuf);
        
        uint64_t jumpto_bl = find_jumpto_bl(iboot_base, idata, isize);
        if(!jumpto_bl)
            goto end;
        printf("%016llx[%016llx]: jumpto_bl\n", jumpto_bl + iboot_base, jumpto_bl);
        
        uint64_t kc_str = find_kc(iboot_base, idata, isize);
        if(!kc_str)
            goto end;
        printf("%016llx[%016llx]: kc_str\n", kc_str + iboot_base, kc_str);
        
        /*---- patch part ----*/
        {
            uint32_t* patch_check_bootmode = (uint32_t*)(idata + check_bootmode);
            patch_check_bootmode[0] = INSN_MOV_X0_1; // 1: REMOTE_BOOT
            patch_check_bootmode[1] = INSN_RET;
            printf("set bootmode: REMOTE_BOOT(1)\n");
        }
        
        {
            uint32_t* patch_bootx_str = (uint32_t*)(idata + bootx_str);
            patch_bootx_str[0] = 0x77726F64; // 'bootx' -> 'dorwx'
            printf("bootx -> dorwx\n");
        }
        
        {
            uint64_t* patch_bootx_cmd_handler = (uint64_t*)(idata + bootx_cmd_handler);
            uint64_t* patch_go_cmd_handler = (uint64_t*)(idata + go_cmd_handler);
            
            patch_bootx_cmd_handler[0] = iboot_base + zeroBuf;
            printf("change dorwx_cmd_handler -> %016llx\n", iboot_base + zeroBuf);
            patch_go_cmd_handler[0] = iboot_base + zeroBuf + a11rxw_len;
            printf("change go_cmd_handler -> %016llx\n", iboot_base + zeroBuf + a11rxw_len);
            
            printf("copying payload...\n");
            memcpy((void*)(idata + zeroBuf), a11rxw, a11rxw_len);
            memcpy((void*)(idata + zeroBuf + a11rxw_len), go_cmd_hook, go_cmd_hook_len);
            memcpy((void*)(idata + zeroBuf + a11rxw_len + go_cmd_hook_len), tram, tram_len);
            printf("done\n");
            
            uint64_t jumpto_hook_addr = zeroBuf + a11rxw_len + go_cmd_hook_len;
            uint32_t opcode = make_branch(jumpto_bl, jumpto_hook_addr);
            printf("jumpto_bl_opcode: %08x\n", opcode);
            uint32_t* patch_jumpto_bl = (uint32_t*)(idata + jumpto_bl);
            patch_jumpto_bl[0] = opcode;
        }
        
        {
            uint8_t* patch_kc_str = (uint8_t*)(idata + kc_str);
            patch_kc_str[0] = 'd';
            printf("kernelcache -> kernelcachd\n");
        }
    }
    
    
    
    FILE *out = fopen(outfile, "w");
    if (!out) {
        printf("error opening %s\n", outfile);
        return -1;
    }
    
    printf("writing %s...\n", outfile);
    fwrite(idata, isize, 1, out);
    fflush(out);
    fclose(out);
    
    
end:
    if(idata)
        free(idata);
    
    return 0;
}
