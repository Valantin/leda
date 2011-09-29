#include <pspsdk.h>
#include <pspctrl.h>
#include <pspsysmem.h>
#include <pspmodulemgr.h>
#include <pspmodulemgr_kernel.h>
#include <psploadcore.h>
#include <psploadexec_kernel.h>
#include <pspdisplay_kernel.h>
#include <pspiofilemgr.h>
#include <pspsyscon.h>
#include <pspinit.h>
#include <pspthreadman.h>
#include <psputils.h>
#include <pspkdebug.h>
//#include <pspintrman.h>
//#include <pspintrman_kernel.h>
#include <systemctrl.h>
#include <kubridge.h>
#include <string.h>
#include "leda.h"

PSP_MODULE_INFO("Legacy_Software_Loader", PSP_MODULE_KERNEL, 1, 0);

#define ELF_MAGIC 0x464C457F

SceOff g0x00003DCC;
SceOff g0x00003DD0;//64bit 0x00003DD0 | 0x00003DD4
SceModule2 *g0x00003DD8;//module header
SceUID g0x00003DE4;//module UID
void *g0x00003E10;//module address

/*
 * Imports from library: InterruptManagerForKernel
 */
extern int InterruptManagerForKernel_8B61808B (int arg1);//missing in header


#define MAKE_JUMP(a, f) _sw(0x08000000 | (((u32)(f) & 0x0ffffffc) >> 2), a); 
#define MAKE_CALL(a, f) _sw(0x0C000000 | (((u32)(f) >> 2)  & 0x03ffffff), a); 
#define MAKE_SYSCALL(a, n) _sw(0x0000000C | (n << 6), a);
#define JUMP_TARGET(x) (0x80000000 | ((x & 0x03FFFFFF) << 2))

#define REDIRECT_FUNCTION(a, f) _sw(0x08000000 | (((u32)(f) >> 2)  & 0x03ffffff), a);  _sw(0x00000000, a+4);
#define MAKE_DUMMY_FUNCTION0(a) _sw(0x03e00008, a); _sw(0x00001021, a+4);
#define MAKE_DUMMY_FUNCTION1(a) _sw(0x03e00008, a); _sw(0x24020001, a+4);

/**
 * Subroutine at address 0x00000000
 */
int IsStaticElf(void *buf) {
    Elf32_Ehdr *hdr = buf;
    return ((hdr->e_magic == ELF_MAGIC) && (hdr->e_type) == 2);
}

/**
 * Subroutine at address 0x00000040
 */
char * __attribute__ ((noinline)) GetStrTab(void *buf) {
    Elf32_Ehdr *hdr = (Elf32_Ehdr *) buf;
    int i;
    u8 *p;
    if (hdr->e_magic != ELF_MAGIC) return NULL;

    p = buf + hdr->e_shoff;
    for (i = 0; i < hdr->e_shnum; i++) {
        if (hdr->e_shstrndx == i) {
            Elf32_Shdr *section = (Elf32_Shdr *) p;

            if (section->sh_type == 3) return (char *) buf + section->sh_offset;
        }
        p += hdr->e_shentsize;
    }

    return NULL;
}


/**
 * Subroutine at address 0x000000DC
 */
int sceKernelDevkitVersionPatched() {
  return 0x01050003;//(0x105 << 16) | 0x3;
}

/**
 * Subroutine at address 0x000000E8
 */
int sceKernelGetUserLevelPatched() {
  return 8;
}

/**
 * Subroutine at address 0x000000F0
 */
int sub_000F0 (void *arg1) {
    ret = 1;
    if ((u32 *)arg1[0] == 0x03E00008) {
        ret = 0;
        if ((u32 *)arg1[1] != 0) {
            ret = (0 < ((u32 *)arg1[1] ^ 0x000003CC));
        }
    }
    return ret;
}

/**
 * Subroutine at address 0x00000128
 */
int module_stop(SceSize args, void *argp) {
	return 0;
}

/**
 * Subroutine at address 0x00000130
 */
int module_start(SceSize args, void *argp) {
    if(sceKernelInitApitype() == PSP_INIT_APITYPE_MS2) {
//        Kprintf("LEDA - Legacy Software Loader, version 0.1, by Dark_AleX\n");
        SystemCtrlForKernel_07232EA5(sceKernelLoadModuleMs2Patched);
    }
  return 0;
}

/**
 * Subroutine at address 0x000001FC
 */
SceOff sceIoLseekPatched(SceUID fd, SceOff offset, int whence)
{
    g0x00003DD0 = sceIoLseek(fd, offset, whence);
    if(g0x00003DCC != 0) {
        if(offset != 0 && whence == 2) return g0x00003DCC;
    }
    return g0x00003DD0;
}

/**
 * Subroutine at address 0x00000280
 */
int destructor(SceSize args, void *argp) {
    int sysstatus = 0;
    int status = 0;
    do {
        sysstatus = sceKernelGetSystemStatus();
		sceKernelDelayThread(1000);
    } while(sysstatus != 0x20000);
    sceKernelStopUnloadSelfModule(0, NULL, &status, NULL);
    return sceKernelExitDeleteThread(0);
}

/**
 * Subroutine at address 0x000002D4
 */
char *sub_002D4 (void *data, int arg2, char *offset)
{
    char *ptr = (char *)data;
    var4 = (Elf32_Ehdr *)data->e_shnum;
    if((Elf32_Ehdr *)data->e_shnum > 0){
        var6 = 0;
        while(1) {
            if(strcmp(data+offset, ".rodata.sceModuleInfo") != 0) {
                ptr += var4->e_shentsize;
            }
        }
    }
  sp = sp + 0xFFFFFFE0;
  ((int *) sp)[4] = s4;
  ((int *) sp)[3] = s3;
  ((int *) sp)[2] = s2;
  ((int *) sp)[0] = s0;
  ((int *) sp)[6] = ra;
  ((int *) sp)[5] = s5;
  ((int *) sp)[1] = s1;
  var1 = ((unsigned char *) arg1)[49];
  var2 = ((unsigned char *) arg1)[48];
  var3 = arg1;
  var4 = (var1 << 0x00000008) | var2;
  var5 = arg2;
  if (var4 <= 0)
  {

  label9:
    ra = ((int *) sp)[6];
    var18 = ((int *) sp)[5];
    var20 = ((int *) sp)[4];
    var21 = ((int *) sp)[3];
    var23 = ((int *) sp)[2];
    var22 = ((int *) sp)[1];
    var24 = ((int *) sp)[0];
    var25 = 0x000035D8;
    sp = sp + 0x00000020;
  }
  else
  {
    var6 = 0x00000000;
    while (1) {
      var7 = LWL (var5, arg1, 0x00000003);
      var6 = var6 + 0x00000001;
      var8 = LWR (var5, var7, 0x00000000);
      var11 var12 = strcmp((var8 + arg3), ".rodata.sceModuleInfo");
      if (var11 != 0x00000000)
      {
        var26 = ((unsigned char *) var3)[47];
        var27 = ((unsigned char *) var3)[46];
        var5 = var5 + ((var26 << 0x00000008) | var27);
        if (var6 == var4)
          break;
        continue;
      }
      else
      {
        var13 = LWL (var5, var11, 0x00000013);
        var14 = LWR (var5, var13, 0x00000010);
        var15 = var3 + var14;
        var16 = ((unsigned short *) var15)[0];
        if (var16 != 0x00000000)
        {
          ((short *) var15)[0] = 0x00000000;
        }
        else
        {
          var15 = 0x00000000;
          *((int *) 0x00003DC8) = 0x00000001;
        }
        var17 = LWL (var5, var15, 0x00000013);
        ra = ((int *) sp)[6];
        var18 = ((int *) sp)[5];
        var19 = LWR (var5, var17, 0x00000010);
        var20 = ((int *) sp)[4];
        var21 = ((int *) sp)[3];
        var22 = ((int *) sp)[1];
        var23 = ((int *) sp)[2];
        var24 = ((int *) sp)[0];
        var25 = (var3 + var19) + 0x00000004;
        sp = sp + 0x00000020;
      }
      goto label14;
    }
    goto label9;
  }

label14:
  return var25;
}

/**
 * Subroutine at address 0x000003D8
 */
int sceKernelCreateThreadPatched2(const char *name, SceKernelThreadEntry entry, int initPriority, int stackSize, SceUInt attr, SceKernelThreadOptParam *option) {
    int k1 = pspSdkSetK1(0);
    if(sceKernelGetModuleIdByAddress(entry) == g0x00003DE4) {
        entry |= 0x80000000;
    }
    pspSdkSetK1(k1);
    return sceKernelCreateThread(name, entry, initPriority, stackSize, attr, option);
}

/**
 * Subroutine at address 0x000004DC
 */
char *sub_004DC (const char *libname)
{
    char *modname = NULL;
    SceModule *mod = sceKernelFindModuleByName("sceSystemMemoryManager");
    if(mod != 0) {
        int ent_size = mod->ent_size;
        while(1) {
            int *ent_top = mod->ent_top;
            if(ent_size > 0) {
                int i = 0;
                while(i <= ent_size) {
                    SceLibraryEntryTable *entry = ent_top + i;
                    if(strcmp(entry->libname, libname) == 0) break;
                    i += (entry->len <<2);
                }
            }
            mod = mod->next;
            if(mod == 0) break;
            ent_size = mod->ent_size;
            modname = mod->modname;
        }
    }
    return modname;
}

/**
 * Subroutine at address 0x0000059C
 */
int sub_0059C(char *modname, char *libname, u32 nid)
{
  sp = sp + 0xFFFFFFE0;
  ((int *) sp)[3] = s3;
  ((int *) sp)[1] = s1;
  ((int *) sp)[0] = s0;
  ((int *) sp)[6] = ra;
  ((int *) sp)[5] = s5;
  ((int *) sp)[4] = s4;
  ((int *) sp)[2] = s2;
  var1 = arg2;
  var4 = sctrlHENFindFunction(modname, libname, nid);
  var5 = var4;
  if (var4 != 0x00000000)
  {
    var15 = sceKernelFindModuleByName(modname);
    var16 = ((int *) var15)[17];//ent_size
    var17 = ((int *) var15)[16];//ent_top
    if (var16 <= 0)
    {

    label30:
      ra = ((int *) sp)[6];
      var6 = ((int *) sp)[5];

    label31:
      var7 = ((int *) sp)[4];
      var8 = ((int *) sp)[3];
      var9 = ((int *) sp)[2];
      var10 = ((int *) sp)[1];
      var11 = ((int *) sp)[0];
      var12 = 0x00000000;
      sp = sp + 0x00000020;
    }
    else
    {
      var18 = 0x00000000;
      while (1) {
        var19 = var17 + var18;
        if (var1 == 0x00000000)
        {

        label16:
          var25 = ((unsigned short *) var19)[5];
          var26 = ((unsigned char *) var19)[9];
          var27 = ((int *) var19)[3];
          if (var25 == 0x00000000)
          {

          label27:
            var33 = ((unsigned char *) var19)[8];

          label28:
            var18 = var18 + (var33 << 0x00000002);
            ra = ((int *) sp)[6];
            if (((var18 < var16)) != 0x00000000)
              continue;
            var6 = ((int *) sp)[5];
            goto label31;
          }
          else
          {
            var28 = var25 + var26;
            if (var28 <= 0)
              goto label27;
            var29 = (var28 << 0x00000002) + var27;
            var30 = ((int *) var29)[0];
            if (var5 == var30)
              break;
            var31 = var29;
            var32 = 0x00000000;
            var32 = var32 + 0x00000001;
            if (!(var28 != var32))
              goto label27;
            var34 = ((int *) var31)[1];
            var31 = var31 + 0x00000004;
            if (!(var5 == var34))
              continue;
            var12 = ((int *) ((var32 << 0x00000002) + var27))[0];
            goto label26;
          }
        }
        else
        {
          var20 = ((int *) var19)[0];
          if (var20 == 0x00000000)
          {
            var33 = ((unsigned char *) var19)[8];
            goto label28;
          }
          else
          {
            var23 var24 = strcmp (var20, var1);
            if (!(var23 != 0x00000000))
              goto label16;
            var33 = ((unsigned char *) var19)[8];
            goto label28;
          }
        }
        goto label32;
      }
      var12 = ((int *) (0x00000000 + var27))[0];

    label26:
      ra = ((int *) sp)[6];
      var6 = ((int *) sp)[5];
      var7 = ((int *) sp)[4];
      var8 = ((int *) sp)[3];
      var9 = ((int *) sp)[2];
      var10 = ((int *) sp)[1];
      var11 = ((int *) sp)[0];
      sp = sp + 0x00000020;
    }
  }
  else
  goto label30;

label32:
  return var12;
}

/**
 * Subroutine at address 0x000006DC
 */
void *sub_006DC (const char *modname){
    int k1 = pspSdkSetK1 (0);
    SceModule2 *mod = sceKernelFindModuleByName(modname);
    if(mod != 0) {
        if(g0x00003dd8 == 0) {
            SceUID id = sceKernelAllocPartitionMemory(2, "FindModuleByNameUser", 1, sizeof(SceModule2), NULL);
            if(var25 >= 0) {
                g0x00003DD8 = sceKernelGetBlockHeadAddr(id);
                if(g0x00003DD8 != 0){
                    memcpy(g0x00003DD8, mod, sizeof(SceModule2));
                    return g0x00003DD8;
                }
            }
        }
    }
    pspSdkSetK1(k1);
    return NULL;
}

/**
 * Subroutine at address 0x000007CC
 */
SceUID sceKernelLoadModuleBufferPatched(SceSize bufsize, void *buf, int flags, SceKernelLMOption *option)
{
  return sceKernelLoadModuleBuffer(buf, bufsize, flags, option);
}

/**
 * Subroutine at address 0x000007DC
 */
SceUID sceKernelLoadModulePatched(const char *path, int flags, SceKernelLMOption *option) {
    SceUID ret;
    int k1 = pspSdkSetK1(0);
    char audio[] = "flash0:/kd/audiocodec_260.prx";
    char video[] = "flash0:/kd/videocodec_260.prx";
    if(strcmp(arg1,"flash0:/kd/semawm.prx") == 0) {
        ret = sceKernelLoadModule("flash0:/kd/chkreg.prx", 0, NULL);
        if (ret < 0) goto out;
        ret = sceKernelStartModule(ret, 0, NULL, NULL, NULL);
        ret = sceKernelLoadModule("flash0:/kd/npdrm.prx", 0, NULL);
        if (ret < 0) goto out
        ret = sceKernelStartModule(ret, 0, NULL, NULL, NULL);
    } else if(strcmp(path, "flash0:/kd/audiocodec.prx") == 0) {
        path = audio;
    } else if(strcmp(path, "flash0:/kd/videocodec.prx") == 0) {
        path = video;
    }
out:
    ret = sceKernelLoadModule(path, flags, option);
    pspSdkSetK1(k1);
    return ret;
}

/**
 * Subroutine at address 0x0000090C
 */
int sceCtrlReadBufferPositivePatched(SceCtrlData *pad_data, int count) {
    int k1 = pspSdkSetK1(0);
    int ret = sceCtrlReadBufferPositive(pad_data, count);
    pspSdkSetK1(k1);
    return ret;
}

/**
 * Subroutine at address 0x00000968
 */
void sceCtrlPeekBufferPositivePatched(SceCtrlData *pad_data, int count) {
    int k1 = pspSdkSetK1(0);
    int ret = sceCtrlPeekBufferPositive(pad_data, count);
    pspSdkSetK1(k1);
    return ret;
}

/**
 * Subroutine at address 0x000009C4
 */
void sceKernelIcacheInvalidateAllPatched() {
    int k1 = pspSdkSetK1(0);
    sceKernelIcacheInvalidateAll();
    pspSdkSetK1(k1);
}

/**
 * Subroutine at address 0x000009FC
 */
void sceDisplaySetBrightnessPatched(int level,int unk1) {
    int k1 = pspSdkSetK1(0);
    sceDisplaySetBrightness(level, unk);
    pspSdkSetK1(k1);
}

/**
 * Subroutine at address 0x00000A54
 */
void sceSysconCtrlLEDPatched(int SceLED, int state) {
  int k1 = pspSdkSetK1 (0);
  int res = sceSysconCtrlLED(SceLED, state);
  pspSdkSetK1(k1);
  return res;
}

/**
 * Subroutine at address 0x00000AB0
 */
void sceKernelExitVSHKernelPatched(struct SceKernelLoadExecVSHParam *param)
{
  return sceKernelExitVSHKernel(NULL);
}

/**
 * Subroutine at address 0x00000AB8
 */
int sub_00AB8 ()
{
    int ret = 0;
    u32 *nid = sctrlHENFindFunction(arg1, arg2, arg3);
    if (nid != 0)
    {
        int res = sceKernelQuerySystemCall(nid);
        ret = (res > 0) ? res : 0;
    }
    return ret;
}

/**
 * Subroutine at address 0x00000B04
 */
int findFunction(char *modname, char *libname, u32 nid) {
    SceModule2 *mod = sceKernelFindModuleByName(modname);
    if(mod != 0) {
        SceModule2 *mod2 = sceKernelFindModuleByUID(mod->modid);
        if(mod2->stub_size > 0) {
            SceLibraryStubTable *stub = mod->stub_top;
            int stubsize = mod->stub_size;
            if(stubsize < 0) {
                while(1) {
                    stub->len;
                    if(stub->stubcount == 0) {
                        stub += stub->len << 2;
                        continue;
                    }
                }
            }
        }
    }
    return 0;
}
int sub_00B04 (int arg1, int arg2, int arg3)//findFunction
{
  var3 = sceKernelFindModuleByName(arg1);
  ra = ((int *) sp)[9];
  if (var3 == 0x00000000)
  {

  label35:
  }
  else
  {
    var4 = ((int *) var3)[11];
    var7 = sceKernelFindModuleByUID(var4);
    ra = ((int *) sp)[9];
    if (var7 == 0x00000000)
      goto label35;
    var8 = ((int *) var7)[19];
    var9 = ((int *) var7)[18];
    if (var8 <= 0)
      goto label35;
    var10 = 0x00000000;
    var11 = var9 + 0x00000000;
    while (1) {
      var12 = ((unsigned char *) var11)[11];
      var13 = ((unsigned char *) var11)[10];
      var14 = LWL (var11, s0, 3);
      var15 = (var12 << 8) | var13;
      s0 = LWR (var11, var14, 0);
      if (var15 == 0) {

      label32:
        var24 = ((unsigned char *) var11)[8];

      label33:
        var10 = var10 + (var24 << 2);
        var11 = var9 + var10;
        if (((var10 < var8)) != 0)
          continue;
        ra = ((int *) sp)[9];
        goto label35;
      } else {
        if (var15 <= 0) {
          var24 = ((unsigned char *) var11)[8];
          goto label33;
        }
        else
        {
          var16 = 0x00000000;
          while (1) {
            if (s0 == 0x00000000)
            {

            label31:
              var16 = var16 + 0x00000001;
              if (var15 != var16)
                continue;
              break;
            }
            else
            {
              var19 var20 = strcmp(s0, arg2);
              if (var19 != 0x00000000)
                goto label31;
              var21 = LWL (var11, var19, 0x0000000F);
              var22 = LWR (var11, var21, 0x0000000C);
              var23 = ((int *) ((var16 << 0x00000002) + var22))[0];
              if (var23 == arg3)
                break;
              goto label31;
            }
            goto label36;
          }
          goto label32;
        }
      }
      goto label36;
    }
    var37 = sctrlHENFindFunction("sceSystemMemoryManager", "SysMemUserForUser", 0x3FC9AE6A);
    var40 var41 = (*var37) (0x00000000, 0x00000000);
    var42 = (((var40 + 0xFE000000) >> 0x00000008) < 0x00030001);
    if (var42 == 0x00000000)
    {
      var47 = sctrlHENFindFunction("SystemControl", "SystemCtrlForKernel", 0x764A319B);
      var50 var51 = (*var47) (0x00000000, 0xFFFFFFFF);
      var43 = LWL (var11, var50, 0x00000013);
    }
    else
    {
      var43 = LWL (var11, var42, 0x00000013);
    }
    ra = ((int *) sp)[9];
    var44 = LWR (var11, var43, 0x00000010);
    var25 = ((int *) sp)[8];
    var26 = ((int *) sp)[7];
    var27 = ((int *) sp)[6];
    var28 = ((int *) sp)[5];
    var29 = ((int *) sp)[4];
    var30 = ((int *) sp)[3];
    var31 = ((int *) sp)[2];
    var32 = ((int *) sp)[1];
    var33 = ((int *) sp)[0];
    var34 = var44 + (var16 << 0x00000003);
    sp = sp + 0x00000028;
  }

label36:
  return var34;
}

/**
 * Subroutine at address 0x00000CCC
 */
void clearcache()
{
  sceKernelDcacheWritebackAll();
  sceKernelIcacheClearAll();
}

/**
 * Subroutine at address 0x00000CE8
 */
int sceKernelLoadModuleMs2Patched(const char *path, int flags, SceKernelLMOption *option)
{
    SceUID var3 = sceKernelLoadModuleForLoadExecVSHMs2(const char *path, int flags, SceKernelLMOption *option);
    if(var3 == 0x80020148) {
        var21 = sub_00B04 ("sceModuleManager", "IoFileMgrForKernel", 0x6A638D83);//sceIoRead
	    MAKE_JUMP(var21, sceIoReadPatched);
        var25 = sub_00B04 ("sceModuleManager", "IoFileMgrForKernel", 0x27EB27B8);//sceIoLseek
	    MAKE_JUMP(var25, sceIoLseekPatched);
        clearcache();
        var3 = sceKernelLoadModuleForLoadExecVSHMs2(path, flags, option);
        MAKE_JUMP(var21, sceIoRead);
        MAKE_JUMP(var25, sceIoLseek);
        clearcache();
        if(var3 > 0) {
            if (g0x00003DC8 == 0){
                var37 = sub_0059C ("sceLoaderCore", "LoadCoreForKernel", 0xC0913394);//sceKernelLinkLibraryEntriesWithModule
                var40 = sub_00B04 ("sceModuleManager", "LoadCoreForKernel", var37);
                MAKE_JUMP(var40, sceKernelLinkLibraryEntriesWithModulePatched);
                var43 = sub_0059C ("sceLoaderCore", "LoadCoreForKernel", 0x0E760DBA);//sceKernelLinkLibraryEntries
                var46 = sub_00B04 ("sceModuleManager", "LoadCoreForKernel", var43);
                MAKE_JUMP(var46, sceKernelLinkLibraryEntriesPatched);
                var49 = sub_00B04 ("SystemControl", "ThreadManForKernel", 0x446D8DE6);//sceKernelCreateThread
                MAKE_JUMP(var49, sceKernelCreateThreadPatched);
                clearcache();
            }
        }
    } else {
        SceUID thid = sceKernelCreateThread("Destruction of Leda", destructor, 0x10, 0x1000, 0, NULL);
        if (thid < 0) return -1;
        sceKernelStartThread(thid, 0, NULL)
    }
  return 0;
}

/**
 * Subroutine at address 0x00000F40
 */
int sceKernelCreateThreadPatched(const char *name, SceKernelThreadEntry entry, int initPriority, int stackSize, SceUInt attr, SceKernelThreadOptParam *option) {
    if(strcmp(name, "SceModmgrStart") == 0) {
        if(g0x00003D70 != 0) {
            var42 = sctrlHENFindFunction("sceModuleManager", "ModuleMgrForUser", 0x50F0C1EC);
            sctrlHENPatchSyscall(var42, sceKernelStartModulePatched);
            if(strcmp(g0x00003DF4, WlanScanner) == 0) {
                var67 = sctrlHENFindFunction("sceController_Service", "sceCtrl", 0x1F803938);
                sctrlHENPatchSyscall(var67, sceCtrlReadBufferPositivePatched);
                var72 = sctrlHENFindFunction("sceController_Service", "sceCtrl", 0x3A622550);
                sctrlHENPatchSyscall(var72, sceCtrlPeekBufferPositivePatched);
            }
            var52 = sub_00B04 ("sceIOFileManager", "ThreadManForKernel", 0xF6427665);
            MAKE_JUMP(var52, sceKernelGetUserLevelPathced);
            var55 = sub_00B04 ("sceLFatFs_Driver", "ThreadManForKernel", 0xF6427665);
            MAKE_JUMP(var55, sceKernelGetUserLevelPathced);
            if(strcmp(g0x00003DF4, "\"WEBNAB\"") == 0) {
                var62 = sctrlHENFindFunction("sceSystemMemoryManager", "SysMemUserForUser", 0x3FC9AE6A);
                sctrlHENPatchSyscall(var62, sceKernelDevkitVersionPatched);
            }
        } else {
            var12 = pspSdkSetK1 (0);
            option[1] = 1;
            entry = entry | 0x80000000;
            var15 = sub_00B04("SystemControl", "ThreadManForKernel", 0x446D8DE6);
            MAKE_JUMP(var15, sceKernelCreateThreadPatched);
            attr = 0;
            var18 = sctrlHENFindFunction("sceThreadManager", "ThreadManForUser", 0x446D8DE6);
            sctrlHENPatchSyscall(var18, sceKernelCreateThreadPatched2);
        }
        var23 = sctrlHENFindFunction("sceModuleManager", "ModuleMgrForUser", 0x977DE386);
        sctrlHENPatchSyscall(var23, sceKernelLoadModulePatched);
        clearcache();
    }
    return sceKernelCreateThread(name, entry, initPriority, stackSize, attr, option);
}

/**
 * Subroutine at address 0x000011E8
 */
void sceIoReadPatched(SceUID fd, void *data, SceSize size)
{
    int read = sceIoRead(fd, data, size);
    if(g0x00003DC0 == 0) {
        if((u32 *)data[0] == ELF_MAGIC) {
            if(g0x00003DD0 != 0) {
                if((u32 *)data[0] == ELF_MAGIC) {
                    if(size != 0) {
                        int iself = IsStaticElf(data);
                        if(iself == 1){
                            char *strtab = GetStrTab(data);
                            if(strtab == NULL) return -1;
                            e_version
                        }
                    }
                }
            }
        }
    }
  sp = sp + 0xFFFFFFB0;
  ((int *) sp)[14] = s4;
  ((int *) sp)[13] = s3;
  ((int *) sp)[12] = s2;
  ((int *) sp)[11] = s1;
  ((int *) sp)[10] = s0;
  ((int *) sp)[19] = ra;
  ((int *) sp)[18] = fp;
  ((int *) sp)[17] = s7;
  ((int *) sp)[16] = s6;
  ((int *) sp)[15] = s5;
  var1 = arg1;
  var2 = arg2;
  var3 = arg3;
  var6 = sceIoRead(fd, data, size);
  var7 = var6;
  var8 = *((int *) 0x00003DC0);
  if (var8 != 0x00000000)
  {
  }
  else
  {
    var9 = ((int *) var2)[0];
    if (var9 == 0x464C457F)
    {
      var158 = *((int *) 0x00003DD4);
      var159 = *((int *) 0x00003DD0);
      if ((var159 | var158) != 0x00000000)
      {

      label24:
        if (var9 == 0x464C457F)
        {
          if (var3 == 0x00000200)
          {

          label315:
          }
          else
          {
            *((int *) 0x00003DC0) = 0x00000001;
            var29 = IsStaticElf(var2);
            if (var29 == 0x00000000)
            {
            }
            else
            {
              var32 = sub_00040 (var2);
              var33 = var32;
              if (var32 == 0x00000000)
                goto label315;
              var34 = LWL (var2, var32, 0x00000023);
              var35 = LWR (var2, var34, 0x00000020);
              var36 = var2 + var35;
              char *var39 = sub_002D4(var2, var36, var33);
              strcpy(0x00003DF4, var39);
              var42 = *((int *) 0x00003DC8);
              if (var42 != 0x00000000)
              {
              }
              else
              {
                var43 = sp;
                var46 = sceCtrl_driver_1F803938 (var43, 0x00000001);
                var47 = ((int *) sp)[1];
                if ((var47 & 0x00000200) == 0x00000000)
                {
                  var157 = strstr(0x00003DF4, "Resurssiklunssi");
                  if (!(var157 == 0x00000000))
                  {
                    *((int *) 0x00003D70) = 0x00000000;
                  }
                }
                else
                {
                  *((int *) 0x00003D70) = 0x00000000;
                }
                var48 = ((unsigned char *) var2)[49];
                var49 = ((unsigned char *) var2)[48];
                if (!(((var48 << 0x00000008) | var49) <= 0))
                {
                  ((int *) sp)[8] = (0x00002BA4 >> 0x00000002);
                  ((int *) sp)[9] = (0x00002BB4 >> 0x00000002);
                  var50 = 0x00000000;
                  while (1) {
                    var51 = LWL (var36);
                    var52 = LWR (var36, var51, 0x00000000);
                    var55 var56 = strcmp((var33 + var52), ".text");
                    if (var55 != 0x00000000)
                    {
                      var77 = ((unsigned char *) var2)[47];
                    }
                    else
                    {
                      var57 = LWL (var36, var55, 0x00000017);
                      var58 = LWL (var36, var56, 0x00000013);
                      var59 = LWR (var36, var57, 0x00000014);
                      var60 = LWR (var36, var58, 0x00000010);
                      var61 = var2 + var60;
                      if (!((var59 >> 0x00000002) == 0x00000000))
                      {
                        var62 = *((int *) 0x00003714);
                        ((int *) sp)[7] = (((0x00002B54 >> 0x00000002) & var62) | 0x0C000000);
                        ((int *) sp)[4] = (((0x00002B84 >> 0x00000002) & var62) | 0x0C000000);
                        var63 = *((int *) 0x00003718);
                        ((int *) sp)[6] = (((0x00002B64 >> 0x00000002) & var62) | 0x0C000000);
                        ra = 0x00000000;
                        var64 = 0x00000000;
                        ((int *) sp)[5] = (((0x00002B74 >> 0x00000002) & var62) | 0x0C000000);
                        while (1) {
                          var65 = *((int *) 0x00003D70);
                          if (var65 == 0x00000000)
                          {
                            var118 = var61 + (var64 << 0x00000002);
                            var119 = ((int *) var118)[0];
                            if (var119 == 0x0160F809)
                            {
                              ((int *) var118)[0] = (((0x00002BF4 >> 0x00000002) & var62) | 0x0C000000);
                              var75 = LWL (var36, 0x0160F809, 0x00000017);
                            }
                            else
                            {
                              if (((0x0160F809 < var119)) != 0x00000000)
                              {
                                if (var119 == 0x0220F809)
                                {
                                  var154 = ((0x00002C74 >> 0x00000002) & var62) | 0x0C000000;
                                  ((int *) var118)[0] = var154;
                                  var75 = LWL (var36, var154, 0x00000017);
                                }
                                else
                                {
                                  if (((0x0220F809 < var119)) != 0x00000000)
                                  {
                                    if (var119 == 0x02C0F809)
                                    {
                                      var153 = ((0x00002CC4 >> 0x00000002) & var62) | 0x0C000000;
                                      ((int *) var118)[0] = var153;
                                      var75 = LWL (var36, var153, 0x00000017);
                                    }
                                    else
                                    {
                                      if (((0x02C0F809 < var119)) != 0x00000000)
                                      {
                                        if (var119 == 0x0300F809)
                                        {
                                          var152 = ((0x00002C44 >> 0x00000002) & var62) | 0x0C000000;
                                          ((int *) var118)[0] = var152;
                                          var75 = LWL (var36, var152, 0x00000017);
                                        }
                                        else
                                        {
                                          if (((0x0300F809 < var119)) != 0x00000000)
                                          {
                                            if (var119 == 0x03200008)
                                            {
                                              var151 = ((var63 & 0x00002DD4) >> 0x00000002) | 0x08000000;
                                              ((int *) var118)[0] = var151;
                                              var75 = LWL (var36, var151, 0x00000017);
                                            }
                                            else
                                            {
                                              if (var119 != 0x0320F809)
                                              {
                                                var75 = LWL (var36, 0x0320F809, 0x00000017);
                                              }
                                              else
                                              {
                                                var150 = ((0x00002C54 >> 0x00000002) & var62) | 0x0C000000;
                                                ((int *) var118)[0] = var150;
                                                var75 = LWL (var36, var150, 0x00000017);
                                              }
                                            }
                                          }
                                          else
                                          {
                                            if (var119 == 0x02E0F809)
                                            {
                                              var149 = ((0x00002CD4 >> 0x00000002) & var62) | 0x0C000000;
                                              ((int *) var118)[0] = var149;
                                              var75 = LWL (var36, var149, 0x00000017);
                                            }
                                            else
                                            {
                                              if (var119 != 0x03000008)
                                              {
                                                var75 = LWL (var36, 0x03000008, 0x00000017);
                                              }
                                              else
                                              {
                                                var148 = ((var63 & 0x00002DC4) >> 0x00000002) | 0x08000000;
                                                ((int *) var118)[0] = var148;
                                                var75 = LWL (var36, var148, 0x00000017);
                                              }
                                            }
                                          }
                                        }
                                      }
                                      else
                                      {
                                        if (var119 == 0x0260F809)
                                        {
                                          var147 = ((0x00002C94 >> 0x00000002) & var62) | 0x0C000000;
                                          ((int *) var118)[0] = var147;
                                          var75 = LWL (var36, var147, 0x00000017);
                                        }
                                        else
                                        {
                                          if (((0x0260F809 < var119)) != 0x00000000)
                                          {
                                            if (var119 == 0x0280F809)
                                            {
                                              var146 = ((0x00002CA4 >> 0x00000002) & var62) | 0x0C000000;
                                              ((int *) var118)[0] = var146;
                                              var75 = LWL (var36, var146, 0x00000017);
                                            }
                                            else
                                            {
                                              if (var119 != 0x02A0F809)
                                              {
                                                var75 = LWL (var36, 0x02A0F809, 0x00000017);
                                              }
                                              else
                                              {
                                                var145 = ((0x00002CB4 >> 0x00000002) & var62) | 0x0C000000;
                                                ((int *) var118)[0] = var145;
                                                var75 = LWL (var36, var145, 0x00000017);
                                              }
                                            }
                                          }
                                          else
                                          {
                                            if (var119 != 0x0240F809)
                                            {
                                              var75 = LWL (var36, 0x0240F809, 0x00000017);
                                            }
                                            else
                                            {
                                              var144 = ((0x00002C84 >> 0x00000002) & var62) | 0x0C000000;
                                              ((int *) var118)[0] = var144;
                                              var75 = LWL (var36, var144, 0x00000017);
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                  else
                                  {
                                    if (var119 == 0x01C00008)
                                    {
                                      var143 = ((var63 & 0x00002DA4) >> 0x00000002) | 0x08000000;
                                      ((int *) var118)[0] = var143;
                                      var75 = LWL (var36, var143, 0x00000017);
                                    }
                                    else
                                    {
                                      if (((0x01C00008 < var119)) != 0x00000000)
                                      {
                                        if (var119 == 0x01E00008)
                                        {
                                          var142 = ((var63 & 0x00002DB4) >> 0x00000002) | 0x08000000;
                                          ((int *) var118)[0] = var142;
                                          var75 = LWL (var36, var142, 0x00000017);
                                        }
                                        else
                                        {
                                          if (((0x01E00008 < var119)) != 0x00000000)
                                          {
                                            if (var119 == 0x01E0F809)
                                            {
                                              var141 = ((0x00002C34 >> 0x00000002) & var62) | 0x0C000000;
                                              ((int *) var118)[0] = var141;
                                              var75 = LWL (var36, var141, 0x00000017);
                                            }
                                            else
                                            {
                                              if (var119 != 0x0200F809)
                                              {
                                                var75 = LWL (var36, 0x0200F809, 0x00000017);
                                              }
                                              else
                                              {
                                                var140 = ((0x00002C64 >> 0x00000002) & var62) | 0x0C000000;
                                                ((int *) var118)[0] = var140;
                                                var75 = LWL (var36, var140, 0x00000017);
                                              }
                                            }
                                          }
                                          else
                                          {
                                            var117 = 0x01C0F809;
                                            if (var119 == 0x01C0F809)
                                            {
                                              ((int *) var118)[0] = (((0x00002C24 >> 0x00000002) & var62) | 0x0C000000);

                                            label230:
                                              var75 = LWL (var36, var117, 0x00000017);
                                            }
                                            else
                                            {
                                              var75 = LWL (var36, 0x01C0F809, 0x00000017);
                                            }
                                          }
                                        }
                                      }
                                      else
                                      {
                                        if (var119 == 0x0180F809)
                                        {
                                          ((int *) var118)[0] = (((0x00002C04 >> 0x00000002) & var62) | 0x0C000000);
                                          var75 = LWL (var36, 0x0180F809, 0x00000017);
                                        }
                                        else
                                        {
                                          if (((0x0180F809 < var119)) != 0x00000000)
                                          {
                                            if (var119 == 0x01A00008)
                                            {
                                              var139 = ((var63 & 0x00002D94) >> 0x00000002) | 0x08000000;
                                              ((int *) var118)[0] = var139;
                                              var75 = LWL (var36, var139, 0x00000017);
                                            }
                                            else
                                            {
                                              var117 = 0x01A0F809;
                                              if (var119 == 0x01A0F809)
                                              {
                                                ((int *) var118)[0] = (((0x00002C14 >> 0x00000002) & var62) | 0x0C000000);
                                                goto label230;
                                              }
                                              else
                                              {
                                                var75 = LWL (var36, 0x01A0F809, 0x00000017);
                                              }
                                            }
                                          }
                                          else
                                          {
                                            if (var119 != 0x01800008)
                                            {
                                              var75 = LWL (var36, 0x01800008, 0x00000017);
                                            }
                                            else
                                            {
                                              var138 = ((var63 & 0x00002D84) >> 0x00000002) | 0x08000000;
                                              ((int *) var118)[0] = var138;
                                              var75 = LWL (var36, var138, 0x00000017);
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                              else
                              {
                                if (var119 == 0x00C00008)
                                {
                                  var137 = ((var63 & 0x00002D24) >> 0x00000002) | 0x08000000;
                                  ((int *) var118)[0] = var137;
                                  var75 = LWL (var36, var137, 0x00000017);
                                }
                                else
                                {
                                  if (((0x00C00008 < var119)) != 0x00000000)
                                  {
                                    if (var119 == 0x0100F809)
                                    {
                                      ((int *) var118)[0] = (((0x00002BC4 >> 0x00000002) & var62) | 0x0C000000);
                                      var75 = LWL (var36, 0x0100F809, 0x00000017);
                                    }
                                    else
                                    {
                                      if (((0x0100F809 < var119)) != 0x00000000)
                                      {
                                        if (var119 == 0x01400008)
                                        {
                                          var136 = ((var63 & 0x00002D64) >> 0x00000002) | 0x08000000;
                                          ((int *) var118)[0] = var136;
                                          var75 = LWL (var36, var136, 0x00000017);
                                        }
                                        else
                                        {
                                          if (((0x01400008 < var119)) != 0x00000000)
                                          {
                                            if (var119 == 0x0140F809)
                                            {
                                              ((int *) var118)[0] = (((0x00002BE4 >> 0x00000002) & var62) | 0x0C000000);
                                              var75 = LWL (var36, 0x0140F809, 0x00000017);
                                            }
                                            else
                                            {
                                              if (var119 != 0x01600008)
                                              {
                                                var75 = LWL (var36, 0x01600008, 0x00000017);
                                              }
                                              else
                                              {
                                                var135 = ((var63 & 0x00002D74) >> 0x00000002) | 0x08000000;
                                                ((int *) var118)[0] = var135;
                                                var75 = LWL (var36, var135, 0x00000017);
                                              }
                                            }
                                          }
                                          else
                                          {
                                            if (var119 == 0x01200008)
                                            {
                                              var134 = ((var63 & 0x00002D54) >> 0x00000002) | 0x08000000;
                                              ((int *) var118)[0] = var134;
                                              var75 = LWL (var36, var134, 0x00000017);
                                            }
                                            else
                                            {
                                              var117 = 0x0120F809;
                                              if (var119 == 0x0120F809)
                                              {
                                                ((int *) var118)[0] = (((0x00002BD4 >> 0x00000002) & var62) | 0x0C000000);
                                                goto label230;
                                              }
                                              else
                                              {
                                                var75 = LWL (var36, 0x0120F809, 0x00000017);
                                              }
                                            }
                                          }
                                        }
                                      }
                                      else
                                      {
                                        if (var119 == 0x00E00008)
                                        {
                                          var133 = ((var63 & 0x00002D34) >> 0x00000002) | 0x08000000;
                                          ((int *) var118)[0] = var133;
                                          var75 = LWL (var36, var133, 0x00000017);
                                        }
                                        else
                                        {
                                          if (((0x00E00008 < var119)) != 0x00000000)
                                          {
                                            var130 = ((int *) sp)[9];
                                            if (var119 == 0x00E0F809)
                                            {
                                              var132 = (var130 & var62) | 0x0C000000;
                                              ((int *) var118)[0] = var132;
                                              var75 = LWL (var36, var132, 0x00000017);
                                            }
                                            else
                                            {
                                              if (var119 != 0x01000008)
                                              {
                                                var75 = LWL (var36, 0x01000008, 0x00000017);
                                              }
                                              else
                                              {
                                                var131 = ((var63 & 0x00002D44) >> 0x00000002) | 0x08000000;
                                                ((int *) var118)[0] = var131;
                                                var75 = LWL (var36, var131, 0x00000017);
                                              }
                                            }
                                          }
                                          else
                                          {
                                            if (var119 != 0x00C0F809)
                                            {
                                              var75 = LWL (var36, 0x00C0F809, 0x00000017);
                                            }
                                            else
                                            {
                                              var128 = ((int *) sp)[8];
                                              var129 = (var128 & var62) | 0x0C000000;
                                              ((int *) var118)[0] = var129;
                                              var75 = LWL (var36, var129, 0x00000017);
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                  else
                                  {
                                    var120 = ((int *) sp)[5];
                                    if (var119 == 0x0060F809)
                                    {
                                      ((int *) var118)[0] = var120;
                                      var75 = LWL (var36, 0x0060F809, 0x00000017);
                                    }
                                    else
                                    {
                                      if (((0x0060F809 < var119)) != 0x00000000)
                                      {
                                        if (var119 == 0x0080F809)
                                        {
                                          var127 = ((int *) sp)[4];
                                          ((int *) var118)[0] = var127;
                                          var75 = LWL (var36, var127, 0x00000017);
                                        }
                                        else
                                        {
                                          if (((0x0080F809 < var119)) != 0x00000000)
                                          {
                                            if (var119 == 0x00A00008)
                                            {
                                              var126 = ((var63 & 0x00002D14) >> 0x00000002) | 0x08000000;
                                              ((int *) var118)[0] = var126;
                                              var75 = LWL (var36, var126, 0x00000017);
                                            }
                                            else
                                            {
                                              var117 = 0x00A0F809;
                                              if (var119 == 0x00A0F809)
                                              {
                                                ((int *) var118)[0] = (((0x00002B94 >> 0x00000002) & var62) | 0x0C000000);
                                                goto label230;
                                              }
                                              else
                                              {
                                                var75 = LWL (var36, 0x00A0F809, 0x00000017);
                                              }
                                            }
                                          }
                                          else
                                          {
                                            if (var119 != 0x00800008)
                                            {
                                              var75 = LWL (var36, 0x00800008, 0x00000017);
                                            }
                                            else
                                            {
                                              var125 = ((var63 & 0x00002D04) >> 0x00000002) | 0x08000000;
                                              ((int *) var118)[0] = var125;
                                              var75 = LWL (var36, var125, 0x00000017);
                                            }
                                          }
                                        }
                                      }
                                      else
                                      {
                                        if (var119 == 0x00400008)
                                        {
                                          var124 = ((var63 & 0x00002CE4) >> 0x00000002) | 0x08000000;
                                          ((int *) var118)[0] = var124;
                                          var75 = LWL (var36, var124, 0x00000017);
                                        }
                                        else
                                        {
                                          if (((0x00400008 < var119)) != 0x00000000)
                                          {
                                            if (var119 == 0x0040F809)
                                            {
                                              var123 = ((int *) sp)[6];
                                              ((int *) var118)[0] = var123;
                                              var75 = LWL (var36, 0x0040F809, 0x00000017);
                                            }
                                            else
                                            {
                                              if (var119 != 0x00600008)
                                              {
                                                var75 = LWL (var36, 0x00600008, 0x00000017);
                                              }
                                              else
                                              {
                                                var122 = ((var63 & 0x00002CF4) >> 0x00000002) | 0x08000000;
                                                ((int *) var118)[0] = var122;
                                                var75 = LWL (var36, var122, 0x00000017);
                                              }
                                            }
                                          }
                                          else
                                          {
                                            if (var119 == 0x0020F809)
                                            {
                                              var121 = ((int *) sp)[7];
                                              ((int *) var118)[0] = var121;
                                              var75 = LWL (var36, var121, 0x00000017);
                                            }
                                            else
                                            {
                                              var117 = ((int *) sp)[7];
                                              goto label230;
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                          else
                          {
                            var66 = var61 + (var64 << 0x00000002);
                            var67 = ((int *) var66)[0];
                            if ((var67 >> 0x0000001A) == 0x0000000F)
                            {
                              var68 = var67 >> 0x0000001A;
                              if ((var67 & 0x0000FFFF) != 0x00008000)
                              {

                              label232:
                                if (var68 == 0x0000000F)
                                {
                                  if ((var67 & 0x0000FFFF) != 0x000003FF)
                                  {
                                    var69 = var67 >> 0x0000001A;

                                  label265:
                                    if (var69 == 0x0000000D)
                                    {
                                      var70 = var67 >> 0x0000001A;
                                      if ((var67 & 0x0000FFFF) != 0x0000DC02)
                                      {

                                      label282:
                                        if (var70 != 0x0000000F)
                                        {
                                          var75 = LWL (var36, 0x0000000F, 0x00000017);
                                        }
                                        else
                                        {
                                          if ((var67 & 0x0000FFFF) != 0x0000BE50)
                                          {
                                            var75 = LWL (var36, 0x0000BE50, 0x00000017);
                                          }
                                          else
                                          {
                                            var71 = ((int *) var66)[1073741819];
                                            if ((var71 >> 0x0000001A) == var70)
                                            {
                                              if ((var71 & 0x0000FFFF) != 0x000005B8)
                                              {
                                                var72 = ((int *) var66)[1];

                                              label295:
                                                if ((var72 >> 0x0000001A) != 0x0000000D)
                                                {
                                                  var75 = LWL (var36, 0x0000000D, 0x00000017);
                                                }
                                                else
                                                {
                                                  if ((var72 & 0x0000FFFF) != 0x00000018)
                                                  {
                                                    var75 = LWL (var36, 0x00000018, 0x00000017);
                                                  }
                                                  else
                                                  {
                                                    var73 = ((int *) var66)[3];
                                                    if ((var73 >> 0x0000001A) != 0x0000000C)
                                                    {
                                                      var75 = LWL (var36, 0x0000000C, 0x00000017);
                                                    }
                                                    else
                                                    {
                                                      var74 = var73 & 0x0000FFFF;
                                                      if (var74 == 0x00000020)
                                                      {

                                                      label305:
                                                        ((int *) var66)[0] = 0x03E00008;
                                                        ((int *) var66)[1] = 0x00001021;
                                                        var75 = LWL (var36, 0x00001021, 0x00000017);
                                                      }
                                                      else
                                                      {
                                                        if (var74 != 0x00000010)
                                                        {
                                                          var75 = LWL (var36, 0x00000010, 0x00000017);
                                                        }
                                                        else
                                                        {
                                                          goto label305;
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                              else
                                              {
                                                var80 = ((int *) var66)[1073741820];
                                                if ((var80 >> 0x0000001A) != 0x0000000D)
                                                {
                                                  var75 = LWL (var36, 0x0000000D, 0x00000017);
                                                }
                                                else
                                                {
                                                  if ((var80 & 0x0000FFFF) != 0x0000D800)
                                                  {
                                                    var75 = LWL (var36, 0x0000D800, 0x00000017);
                                                  }
                                                  else
                                                  {
                                                    ((int *) var66)[1073741819] = 0x03E00008;
                                                    ((int *) var66)[1073741820] = 0x00001021;
                                                    var75 = LWL (var36, 0x00001021, 0x00000017);
                                                  }
                                                }
                                              }
                                            }
                                            else
                                            {
                                              var72 = ((int *) var66)[1];
                                              goto label295;
                                            }
                                          }
                                        }
                                      }
                                      else
                                      {
                                        var81 = ((int *) var66)[1073741822];
                                        var82 = var81 >> 0x0000001A;
                                        if (var82 != 0x0000000F)
                                        {
                                          var75 = LWL (var36, 0x0000000F, 0x00000017);
                                        }
                                        else
                                        {
                                          if ((var81 & 0x0000FFFF) != 0x0000001B)
                                          {
                                            var75 = LWL (var36, 0x0000001B, 0x00000017);
                                          }
                                          else
                                          {
                                            var83 = ((int *) var66)[1073741821];
                                            var84 = var83 >> 0x0000001A;
                                            if (var84 != var82)
                                            {
                                              var75 = LWL (var36, 0x0000001B, 0x00000017);
                                            }
                                            else
                                            {
                                              if ((var83 & 0x0000FFFF) != 0x00008000)
                                              {
                                                var75 = LWL (var36, 0x00008000, 0x00000017);
                                              }
                                              else
                                              {
                                                var85 = ((int *) var66)[1073741817];
                                                var86 = var85 >> 0x0000001A;
                                                if (var86 != var84)
                                                {
                                                  var75 = LWL (var36, var86, 0x00000017);
                                                }
                                                else
                                                {
                                                  if ((var85 & 0x0000FFFF) != 0x000003FF)
                                                  {
                                                    var75 = LWL (var36, 0x000003FF, 0x00000017);
                                                  }
                                                  else
                                                  {
                                                    ((int *) var66)[1073741813] = 0x03E00008;
                                                    ((int *) var66)[1073741814] = 0x00001021;
                                                    var75 = LWL (var36, 0x00001021, 0x00000017);
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                    else
                                    {
                                      var70 = var67 >> 0x0000001A;
                                      goto label282;
                                    }
                                  }
                                  else
                                  {
                                    var87 = ((int *) var66)[1];
                                    var88 = var87 >> 0x0000001A;
                                    if (var88 != 0x0000000D)
                                    {
                                      var75 = LWL (var36, 0x0000000D, 0x00000017);
                                    }
                                    else
                                    {
                                      if ((var87 & 0x0000FFFF) != 0x0000FFFF)
                                      {
                                        var75 = LWL (var36, 0x0000FFFF, 0x00000017);
                                      }
                                      else
                                      {
                                        var89 = (var67 >> 16) & 0x0000001F;
                                        var90 = (var87 >> 16) & 0x0000001F;
                                        if (var89 != var90)
                                        {
                                          var75 = LWL (var36, var90, 0x00000017);
                                        }
                                        else
                                        {
                                          var91 = (var87 >> 21) & 0x0000001F;
                                          if (var89 != var91)
                                          {
                                            var75 = LWL (var36, var91, 0x00000017);
                                          }
                                          else
                                          {
                                            var92 = ((int *) var66)[3];
                                            var93 = var92 >> 0x0000001A;
                                            if (var93 != var68)
                                            {
                                              var75 = LWL (var36, var91, 0x00000017);
                                            }
                                            else
                                            {
                                              if ((var92 & 0x0000FFFF) != 0x0000FFE0)
                                              {
                                                var75 = LWL (var36, 0x0000FFE0, 0x00000017);
                                              }
                                              else
                                              {
                                                var94 = ((int *) var66)[4];
                                                var95 = var94 >> 0x0000001A;
                                                if (var95 != var93)
                                                {
                                                  var75 = LWL (var36, 0x0000FFE0, 0x00000017);
                                                }
                                                else
                                                {
                                                  if ((var94 & 0x0000FFFF) != 0x00008000)
                                                  {
                                                    var75 = LWL (var36, 0x00008000, 0x00000017);
                                                  }
                                                  else
                                                  {
                                                    var96 = ((int *) var66)[8];
                                                    var97 = var96 >> 0x0000001A;
                                                    if (var97 != var95)
                                                    {
                                                      var75 = LWL (var36, 0x00008000, 0x00000017);
                                                    }
                                                    else
                                                    {
                                                      if ((var96 & 0x0000FFFF) != 0x00004000)
                                                      {
                                                        var75 = LWL (var36, 0x00004000, 0x00000017);
                                                      }
                                                      else
                                                      {
                                                        var98 = ((int *) var66)[9];
                                                        var99 = var98 >> 0x0000001A;
                                                        if (var99 != var97)
                                                        {
                                                          var75 = LWL (var36, var99, 0x00000017);
                                                        }
                                                        else
                                                        {
                                                          if ((var98 & 0x0000FFFF) != 0x00003400)
                                                          {
                                                            var75 = LWL (var36, 0x00003400, 0x00000017);
                                                          }
                                                          else
                                                          {
                                                            var100 = ((int *) var66)[10];
                                                            var101 = var100 >> 0x0000001A;
                                                            if (var101 != var88)
                                                            {
                                                              var75 = LWL (var36, var101, 0x00000017);
                                                            }
                                                            else
                                                            {
                                                              if ((var100 & 0x0000FFFF) != 0x0000B000)
                                                              {
                                                                var75 = LWL (var36, 0x0000B000, 0x00000017);
                                                              }
                                                              else
                                                              {
                                                                ((int *) var66)[1073741820] = 0x03E00008;
                                                                ((int *) var66)[1073741821] = 0x00001021;
                                                                var75 = LWL (var36, 0x00001021, 0x00000017);
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                                else
                                {
                                  var69 = var67 >> 0x0000001A;
                                  goto label265;
                                }
                              }
                              else
                              {
                                var102 = ((int *) var66)[1];
                                var103 = var102 >> 0x0000001A;
                                if (var103 != 0x00000000)
                                {
                                  var75 = LWL (var36, var103, 0x00000017);
                                }
                                else
                                {
                                  if ((var102 & 0x0000003F) != 0x00000025)
                                  {
                                    var75 = LWL (var36, 0x00000025, 0x00000017);
                                  }
                                  else
                                  {
                                    var104 = (var102 >> 16) & 0x0000001F;
                                    if (((var67 >> 16) & 0x0000001F) != var104)
                                    {
                                      var75 = LWL (var36, var104, 0x00000017);
                                    }
                                    else
                                    {
                                      var105 = ((int *) var66)[2];
                                      var106 = var105 >> 0x0000001A;
                                      if (var106 != 0x00000000)
                                      {
                                        var75 = LWL (var36, var106, 0x00000017);
                                      }
                                      else
                                      {
                                        if ((var105 & 0x0000003F) != 0x00000008)
                                        {
                                          var75 = LWL (var36, 0x00000008, 0x00000017);
                                        }
                                        else
                                        {
                                          var107 = (var105 >> 21) & 0x0000001F;
                                          if (((var102 >> 11) & 0x0000001F) != var107)
                                          {
                                            var75 = LWL (var36, var107, 0x00000017);
                                          }
                                          else
                                          {
                                            var108 = ((int *) var66)[1073741823];
                                            var109 = var108 >> 0x0000001A;
                                            if (var109 == 0x00000009)
                                            {

                                            label223:
                                              var110 = LWL (var36, 0x0000000D, 0x0000000F);
                                              var111 = ra << 0x00000002;
                                              var112 = var108 & 0x0000FFFF;
                                              var113 = LWR (var36, var110, 0x0000000C);
                                              var114 = (var111 + (var113 + 0x00000010)) & 0x0000FFFF;
                                              if (var112 == var114)
                                              {

                                              label229:
                                                var117 = 0xFFFF0000;
                                                ((int *) var66)[0] = (var67 & 0xFFFF0000);
                                                goto label230;
                                              }
                                              else
                                              {
                                                var115 = var114 + 0x00000004;
                                                if (var112 != var115)
                                                {
                                                  var75 = LWL (var36, var115, 0x00000017);
                                                }
                                                else
                                                {
                                                  var116 = ((int *) var66)[4];
                                                  if (!(var116 != 0x00000000))
                                                    goto label229;
                                                  var75 = LWL (var36, var116, 0x00000017);
                                                }
                                              }
                                            }
                                            else
                                            {
                                              if (!(var109 != 0x0000000D))
                                                goto label223;
                                              var75 = LWL (var36, 0x0000000D, 0x00000017);
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                            else
                            {
                              var68 = var67 >> 0x0000001A;
                              goto label232;
                            }
                          }
                          var64 = ra + 0x00000001;
                          var76 = LWR (var36, var75, 0x00000014);
                          ra = var64;
                          if (((var64 < (var76 >> 0x00000002))) == 0x00000000)
                            break;
                          continue;
                        }
                        var49 = ((unsigned char *) var2)[48];
                        var48 = ((unsigned char *) var2)[49];
                      }
                      var77 = ((unsigned char *) var2)[47];
                    }
                    a0/* Invalid block 309 3 */ = ((unsigned char *) var2)[46];
                    var50 = var50 + 0x00000001;
                    if (((var50 < ((var48 << 0x00000008) | var49))) == 0x00000000)
                      break;
                    var36 = var36 + ((var77 << 0x00000008) | a0/* Invalid block 309 3 */);
                    continue;
                  }
                }
                clearcache();
              }
            }
          }
        }
        else
        {
          goto label315;
        }
      }
      else
      {
        var162 var163 = sceIoLseek(var1, var9, 0x00000000, 0x00000000, 0x00000002);
        var164 = 0x00003D74;
        var165 = var162 + 0x000001C0;
        var166 = 0x00000000;
        *((int *) 0x00003DCC) = var165;
        var167 = 0x00003D74;
        *((int *) 0x00003D98) = var165;
        var168 = var2;
        while (1) {
          var169 = LWL (var167, var165, 0x00000003);
          var170 = LWL (var167, var166, 0x00000007);
          var171 = LWL (var167, var164, 0x0000000B);
          var172 = LWL (var167);
          var165 = LWR (var167, var169, 0x00000000);
          var166 = LWR (var167, var170, 0x00000004);
          var164 = LWR (var167, var171, 0x00000008);
          a1/* Invalid block 12 3 */ = LWR (var167, var172, 0x0000000C);
          SWL (var168, var165, 0x00000003);
          SWR (var168, var165, 0x00000000);
          SWL (var168, var166, 0x00000007);
          SWR (var168, var166, 0x00000004);
          SWL (var168, var164, 0x0000000B);
          SWR (var168, var164, 0x00000008);
          var167 = var167 + 0x00000010;
          SWL (var168);
          SWR (var168);
          var168 = var168 + 0x00000010;
          if (var167 != 0x00003D94)
            continue;
          break;
        }
        var173 = LWL (var167, var165, 0x00000003);
        var174 = LWL (var167, var166, 0x00000007);
        var175 = LWR (var167, var173, 0x00000000);
        var176 = LWR (var167, var174, 0x00000004);
        SWL (var168, var175, 0x00000003);
        SWR (var168, var175, 0x00000000);
        SWL (var168, var176, 0x00000007);
        SWR (var168, var176, 0x00000004);

      label20:
        var17 = *((int *) 0x00003DC0);
        if (var17 != 0x00000000)
        {
        }
        else
        {
          var9 = ((int *) var2)[0];

        label23:
          goto label24;
        }
      }
    }
    else
    {
      if (var9 == 0x50425000)
        goto label23;
      var12 var13 = sceIoLseek(fd, var9, 0x00000000, 0x00000000, 0x00000000);
      var16 = sceIoRead(fd, data, size);
      var7 = var16;
      goto label20;
    }
  }
  ra = ((int *) sp)[19];
  var18 = ((int *) sp)[18];
  var19 = ((int *) sp)[17];
  var20 = ((int *) sp)[16];
  var21 = ((int *) sp)[15];
  var22 = ((int *) sp)[14];
  var23 = ((int *) sp)[13];
  var24 = ((int *) sp)[12];
  var25 = ((int *) sp)[11];
  var26 = ((int *) sp)[10];
  sp = sp + 0x00000050;
  return;
}

/**
 * Subroutine at address 0x00002068
 */
void sceKernelStartModulePatched(SceUID modid, SceSize argsize, void *argp, int *status, SceKernelSMOption *option)
{
    var3 = sceKernelStartModule(modid, argsize, argp, status, option);
  var4 = var3;
  var5 = *((int *) 0x00003DF0);
  if (var5 != 0x00000000)
  {
    var56 = pspSdkSetK1 (0x00000000);
    var10 = var56;
    var57 = *((int *) 0x00003DC4);
    if (var57 != 0x00000000)
    {

    label21:
      var12 = *((int *) 0x00003DF0);
      if (var12 != 0x00000000)
      {

      label22:
        var40 = sctrlHENFindFunction("Circulo Rectangular", "HappyWorld", 0x12345678);
        if (var40 != 0x00000000)
        {
          var42 = *((int *) 0x00003DF0);
          ((int *) var42)[0] = (((var40 >> 0x00000002) & 0x03FFFFFF) | 0x08000000);
          var43 = *((int *) 0x00003DF0);
          ((int *) var43)[1] = 0x00000000;
          clearcache();
          *((int *) 0x00003DF0) = 0x00000000;
        }
        else
        {
          *((int *) 0x00003DF0) = 0x00000000;
        }
        var41 = *((int *) 0x00003E14);
        if (var41 == 0x00000000)
        {

        label39:
          var14 = *((int *) 0x00003DEC);
          if (var14 != 0x00000000)
          {

          label40:
            var25 = sctrlHENFindFunction("Circulo Rectangular", "HappyWorld", 0x01234567);
            if (var25 != 0x00000000)
            {
              var26 = *((int *) 0x00003DEC);
              ((int *) var26)[0] = (((var25 >> 0x00000002) & 0x03FFFFFF) | 0x08000000);
              var27 = *((int *) 0x00003DEC);
              ((int *) var27)[1] = 0x00000000;
              clearcache();
              *((int *) 0x00003DEC) = 0x00000000;
            }
            else
            {
              *((int *) 0x00003DEC) = 0x00000000;
            }
          }
        }
        else
        {

        label31:
          var32 = sctrlHENFindFunction("Circulo Rectangular", "HappyWorld", 0x87654321);
          if (var32 != 0x00000000)
          {
            var34 = *((int *) 0x00003E14);
            ((int *) var34)[0] = (((var32 >> 0x00000002) & 0x03FFFFFF) | 0x08000000);
            var35 = *((int *) 0x00003E14);
            ((int *) var35)[1] = 0x00000000;
            clearcache();
            *((int *) 0x00003E14) = 0x00000000;
          }
          else
          {
            *((int *) 0x00003E14) = 0x00000000;
          }
          var33 = *((int *) 0x00003DEC);
          if (!(var33 == 0x00000000))
            goto label40;
        }
      }
      else
      {

      label30:
        var13 = *((int *) 0x00003E14);
        if (var13 != 0x00000000)
          goto label31;
        goto label39;
      }
    }
    else
    {

    label16:
      *((int *) 0x00003DC4) = 0x00000001;
      var48 = sceKernelLoadModuleBuffer(0x0000052C, (char *)0x00003840, 0x00000000, NULL);
      var51 = sceKernelStartModule(var48, NULL, NULL, NULL, NULL);
      var52 = *((int *) 0x00003DF0);
      if (var52 == 0x00000000)
        goto label30;
      goto label22;
    }
    var17 = pspSdkSetK1 (var10);
    ra = ((int *) sp)[5];
    var18 = ((int *) sp)[4];
    var19 = ((int *) sp)[3];
    var20 = ((int *) sp)[2];
    var21 = ((int *) sp)[1];
    var22 = ((int *) sp)[0];
    sp = sp + 0x00000018;
  }
  else
  {
    var6 = *((int *) 0x00003E14);
    if (var6 == 0x00000000)
    {
      var53 = *((int *) 0x00003DEC);
      if (var53 != 0x00000000)
      {

      label13:
        var9 = pspSdkSetK1 (0x00000000);
        var10 = var9;
        var11 = *((int *) 0x00003DC4);
        if (var11 == 0x00000000)
          goto label16;
        goto label21;
      }
      else
      {
        ra = ((int *) sp)[5];
        var18 = ((int *) sp)[4];
        var19 = ((int *) sp)[3];
        var20 = ((int *) sp)[2];
        var21 = ((int *) sp)[1];
        var22 = ((int *) sp)[0];
        sp = sp + 0x00000018;
      }
    }
    else
    goto label13;
  }
  return;
}

/**
 * Subroutine at address 0x000022D4
 */
void sub_022D4 ()
{
  sp = sp + 0xFFFFFFD0;
  ((int *) sp)[11] = ra;
  ((int *) sp)[10] = fp;
  ((int *) sp)[9] = s7;
  ((int *) sp)[8] = s6;
  ((int *) sp)[7] = s5;
  ((int *) sp)[6] = s4;
  ((int *) sp)[5] = s3;
  ((int *) sp)[4] = s2;
  ((int *) sp)[3] = s1;
  ((int *) sp)[2] = s0;
  var1 = *((int *) 0x00003DE8);
  var2 = *((int *) 0x00003E10);
  ((int *) sp)[0] = var2;
  if (!(var1 <= 0))
  {
    ((int *) sp)[1] = 0x00000000;
    while (1) {
      var3 = ((int *) sp)[1];
      var4 = ((int *) sp)[0];
      var5 = var4 + var3;
      var6 = LWL (var5, var3, 0x00000003);
      var7 = LWR (var5, var6, 0x00000000);
      if (var7 == 0x00000000)
      {
        var23 = ((unsigned char *) var5)[8];
      }
      else
      {
        var10 = sub_004DC (var7);
        var11 = ((unsigned char *) var5)[11];
        var12 = ((unsigned char *) var5)[10];
        var13 = var10;
        var14 = (var11 << 0x00000008) | var12;
        if (var14 <= 0)
        {
          var23 = ((unsigned char *) var5)[8];
        }
        else
        {
          var15 = 0x00000000;
          var16 = 0x00000000;
          while (1) {
            var17 = LWL (var5, var14, 0x00000013);
            var18 = LWR (var5, var17, 0x00000010);
            var19 = var18 + (var15 << 0x00000003);
            var22 = sub_000F0 (var19);
            if (var13 != 0x00000000)
            {
              if (var22 != 0x00000000)
              {
                var38 = var11 << 0x00000008;

              label176:
                var15 = var15 + 0x00000001;
                var14 = (var15 < (var38 | var12));
                var16 = var16 + 0x00000004;
                if (var14 == 0x00000000)
                  break;
                continue;
              }
              else
              {
                var39 = ((unsigned char *) var5)[7];
                if (((var39 << 0x00000008) & 0x00004000) == 0x00000000)
                {
                  var66 = LWL (var5, 0x00000000, 0x0000000F);
                  var67 = LWL (var5);
                  var68 = LWR (var5, var66, 0x0000000C);
                  var69 = LWR (var5, var67, 0x00000000);
                  var70 = ((int *) (var16 + var68))[0];
                  var73 = sctrlHENFindFunction(var13, var69, var70);
                  var74 = LWL (var5, var11, 0x00000003);
                  var75 = LWR (var5, var74, 0x00000000);
                  var65 = var73;
                  var78 var79 = strcmp (var75, "ThreadManForKernel");
                  if (var78 != 0x00000000)
                  {

                  label25:
                    var85 var86 = strcmp (var75, "ModuleMgrForKernel");
                    if (var85 != 0x00000000)
                    {

                    label30:
                      var92 var93 = strcmp (var75, "sceNet");
                      if (var92 != 0x00000000)
                      {
                        var219 var220 = strcmp (var75, "sceNet_lib");
                        if (var219 != 0x00000000)
                        {

                        label41:

                        label42:
                          var99 var100 = strcmp (var75, "sceNetApctl");
                          if (var99 != 0x00000000)
                          {

                          label47:
                            var106 var107 = strcmp (0x00003DF4, ""LUAPLAYER"");
                            if (var106 != 0x00000000)
                            {

                            label54:
                              var108 = *((int *) 0x00003D70);

                            label55:
                              if (var108 != 0x00000000)
                              {
                                var114 var115 = strcmp (0x00003DF4, "callisto");
                                if (var114 == 0x00000000)
                                {
                                  var204 var205 = strcmp (var75, "LoadCoreForKernel");
                                  if (var204 != 0x00000000)
                                  {

                                  label72:

                                  label73:
                                    var118 var119 = strcmp (var75, "StdioForKernel");
                                    if (var118 != 0x00000000)
                                    {
                                      var122 var123 = strcmp (var75, "IoFileMgrForKernel");
                                      if (var122 == 0x00000000)
                                      {

                                      label150:

                                      label151:
                                        ((int *) var19)[0] = 0x03E00008;
                                        ((int *) var19)[1] = 0x00001021;
                                        var12 = ((unsigned char *) var5)[10];
                                        var11 = ((unsigned char *) var5)[11];

                                      label173:
                                        var38 = var11 << 0x00000008;
                                        goto label176;
                                      }
                                      else
                                      {
                                        var126 var127 = strcmp (var75, "ExceptionManagerForKernel");
                                        if (var126 == 0x00000000)
                                          goto label150;
                                        var130 var131 = strcmp (var75, "KDebugForKernel");
                                        if (var130 == 0x00000000)
                                          goto label150;
                                        var134 var135 = strcmp (var75, "LoadCoreForKernel");
                                        if (var134 != 0x00000000)
                                        {

                                        label94:
                                          var141 var142 = strcmp (var75, "UtilsForKernel");
                                          if (var141 != 0x00000000)
                                          {

                                          label107:
                                            var148 var149 = strcmp (var75, "sceSyscon_driver");
                                            if (var148 != 0x00000000)
                                            {
                                              var163 var164 = strcmp (var75, "sceSysreg_driver");
                                              if (var163 != 0x00000000)
                                              {
                                                var170 var171 = strcmp (var75, "sceHprm_driver");
                                                if (var170 != 0x00000000)
                                                {
                                                  var180 var181 = strcmp (var75, "sceDisplay_driver");
                                                  if (var180 != 0x00000000)
                                                  {

                                                  label152:
                                                    if (var65 == 0x00000000)
                                                    {

                                                    label179:
                                                      ((int *) var19)[1] = 0x00000000;
                                                      ((int *) var19)[0] = 0x03E00008;
                                                      var11 = ((unsigned char *) var5)[11];
                                                      var12 = ((unsigned char *) var5)[10];
                                                      var15 = var15 + 0x00000001;
                                                      var14 = (var15 < ((var11 << 0x00000008) | var12));
                                                      var16 = var16 + 0x00000004;
                                                      if (var14 != 0x00000000)
                                                        continue;
                                                      break;
                                                    }
                                                    else
                                                    {

                                                    label160:
                                                      ((int *) var19)[0] = (((var65 >> 0x00000002) & 0x03FFFFFF) | 0x08000000);
                                                      ((int *) var19)[1] = 0x00000000;
                                                      var12 = ((unsigned char *) var5)[10];
                                                      var11 = ((unsigned char *) var5)[11];
                                                      goto label173;
                                                    }
                                                  }
                                                  else
                                                  {
                                                    var182 = LWL (var5, var180, 0x0000000F);
                                                    var183 = LWR (var5, var182, 0x0000000C);
                                                    var184 = var16 + var183;
                                                    var185 = ((int *) var184)[0];
                                                    if (var185 != 0x9E3C6DC6)
                                                    {
                                                      var55 = LWL (var5, var184, 0x0000000F);

                                                    label168:
                                                      var56 = LWL (var5);
                                                      var57 = LWR (var5, var55, 0x0000000C);
                                                      var58 = LWR (var5, var56, 0x00000000);
                                                      var59 = ((int *) (var16 + var57))[0];
                                                      var62 = sub_00AB8 ();
                                                      var63 = var62;
                                                      if (var62 == 0x00000000)
                                                      {

                                                      label178:
                                                        goto label179;
                                                      }
                                                      else
                                                      {

                                                      label171:
                                                        var64 = var63 << 0x00000006;

                                                      label172:
                                                        ((int *) var19)[1] = (var64 | 0x0000000C);
                                                        ((int *) var19)[0] = 0x03E00008;
                                                        var12 = ((unsigned char *) var5)[10];
                                                        var11 = ((unsigned char *) var5)[11];
                                                        goto label173;
                                                      }
                                                    }
                                                    else
                                                    {
                                                      var188 = sub_00AB8 ();
                                                      if (var188 == 0x00000000)
                                                      {

                                                      label149:
                                                        goto label150;
                                                      }
                                                      else
                                                      {
                                                        var191 = sctrlHENFindFunction("SystemControl", "KUBridge", 0x1E9F0498);//kuKernelLoadModuleWithApitype2
                                                        sctrlHENPatchSyscall(var191, 0x000009FC);
                                                        var64 = var188 << 0x00000006;
                                                        goto label172;
                                                      }
                                                      goto label173;
                                                    }
                                                  }
                                                }
                                                else
                                                {
                                                  var172 = LWL (var5, var170, 0x0000000F);
                                                  var173 = LWR (var5, var172, 0x0000000C);
                                                  var174 = ((int *) (var16 + var173))[0];
                                                  var177 = sub_00AB8 ();
                                                  var63 = var177;
                                                  if (var177 != 0x00000000)
                                                    goto label171;

                                                label140:

                                                label166:
                                                  ((int *) var19)[0] = 0x03E00008;
                                                  ((int *) var19)[1] = 0x00001021;
                                                  var12 = ((unsigned char *) var5)[10];
                                                  var11 = ((unsigned char *) var5)[11];
                                                  goto label173;
                                                }
                                              }
                                              else
                                              {
                                                var165 = LWL (var5, var163, 0x0000000F);
                                                var166 = LWR (var5, var165, 0x0000000C);
                                                var167 = ((int *) (var16 + var166))[0];
                                                if (var167 != 0x7FD7A631)
                                                {
                                                  goto label152;
                                                }
                                                else
                                                {

                                                label135:
                                                  ((int *) var19)[0] = 0x03E00008;
                                                  ((int *) var19)[1] = 0x00001021;
                                                  var12 = ((unsigned char *) var5)[10];
                                                  var11 = ((unsigned char *) var5)[11];
                                                  goto label173;
                                                }
                                              }
                                            }
                                            else
                                            {
                                              var150 = LWL (var5, var148, 0x0000000F);
                                              var151 = LWR (var5, var150, 0x0000000C);
                                              var152 = ((int *) (var16 + var151))[0];
                                              if (var152 == 0x18BFBE65)
                                              {
                                                var155 = sub_00AB8 ();
                                                if (var155 == 0x00000000)
                                                  goto label140;
                                                var158 = sctrlHENFindFunction("SystemControl", "KUBridge", 0x4C25EA72);//kuKernelLoadModule
                                                sctrlHENPatchSyscall(var158, 0x00000A54);
                                                var64 = var155 << 0x00000006;
                                                goto label172;
                                              }
                                              else
                                              {
                                                if (var152 != 0x44439604)
                                                {
                                                  goto label152;
                                                }
                                                else
                                                {
                                                  goto label151;
                                                }
                                              }
                                            }
                                          }
                                          else
                                          {
                                            var143 = LWL (var5, var141, 0x0000000F);
                                            var144 = LWR (var5, var143, 0x0000000C);
                                            var145 = ((int *) (var16 + var144))[0];
                                            if (!(var145 == 0x920F104A))
                                              goto label107;
                                            var196 = sub_00AB8 ();
                                            if (var196 != 0x00000000)
                                            {
                                              var199 = sctrlHENFindFunction("SystemControl", "KUBridge", 0x8E5A4057);//kuKernelInitApitype
                                              sctrlHENPatchSyscall(var199, 0x000009C4);
                                              var64 = var196 << 0x00000006;
                                              goto label172;
                                            }
                                            else
                                            {
                                              goto label135;
                                            }
                                            goto label173;
                                          }
                                        }
                                        else
                                        {
                                          var136 = LWL (var5, var134, 0x0000000F);
                                          var137 = LWR (var5, var136, 0x0000000C);
                                          var138 = ((int *) (var16 + var137))[0];
                                          if (var138 == 0xD8779AC6)
                                          {
                                            goto label149;
                                          }
                                          else
                                          {
                                            if (var138 == 0xCF8A41B1)
                                              goto label149;
                                            if (var138 == 0xCCE4A157)
                                            {
                                              goto label150;
                                            }
                                            else
                                            {
                                              goto label94;
                                            }
                                          }
                                        }
                                      }
                                    }
                                    else
                                    goto label149;
                                  }
                                  else
                                  {
                                    var206 = LWL (var5, var204, 0x0000000F);
                                    var207 = LWR (var5, var206, 0x0000000C);
                                    var208 = ((int *) (var16 + var207))[0];
                                    if (var208 != 0xCF8A41B1)
                                      goto label73;
                                    var211 = sub_00AB8 ();
                                    if (var211 == 0x00000000)
                                      goto label152;
                                    var214 = sctrlHENFindFunction("SystemControl", "KUBridge", 0x1742445F);//kuKernelInitFileName
                                    sctrlHENPatchSyscall(var214, 0x000006DC);
                                    var64 = var211 << 0x00000006;
                                    goto label172;
                                  }
                                }
                                else
                                {
                                  goto label72;
                                }
                              }
                              else
                              goto label152;
                            }
                            else
                            {
                              var108 = *((int *) 0x00003D70);
                              if (var99 != 0x00000000)
                                goto label55;
                              var109 = LWL (var5, 0x00000000, 0x0000000F);
                              var110 = LWR (var5, var109, 0x0000000C);
                              var111 = ((int *) (var16 + var110))[0];
                              if (!(var111 == 0xCFB957C6))
                                goto label54;
                              *((int *) 0x00003DEC) = var19;
                              goto label152;
                            }
                          }
                          else
                          {
                            var101 = LWL (var5, var99, 0x0000000F);
                            var102 = LWR (var5, var101, 0x0000000C);
                            var103 = ((int *) (var16 + var102))[0];
                            if (!(var103 == 0xE2F91F9B))
                              goto label47;
                            *((int *) 0x00003E14) = var19;
                            goto label152;
                          }
                        }
                        else
                        {
                          var221 = LWL (var5, var219, 0x0000000F);
                          var222 = LWR (var5, var221, 0x0000000C);
                          var223 = ((int *) (var16 + var222))[0];
                          if (var223 != 0x7BA3ED91)
                            goto label42;

                        label39:
                          *((int *) 0x00003DF0) = var19;
                          goto label152;
                        }
                      }
                      else
                      {
                        var94 = LWL (var5, var92, 0x0000000F);
                        var95 = LWR (var5, var94, 0x0000000C);
                        var96 = ((int *) (var16 + var95))[0];
                        if (var96 == 0x7BA3ED91)
                          goto label39;
                        goto label41;
                      }
                    }
                    else
                    {
                      var87 = LWL (var5, var85, 0x0000000F);
                      var88 = LWR (var5, var87, 0x0000000C);
                      var89 = ((int *) (var16 + var88))[0];
                      if (!(var89 == 0xBA889C07))
                        goto label30;
                      var65 = sceKernelLoadModuleBufferPatched;
                      goto label160;
                    }
                  }
                  else
                  {
                    var80 = LWL (var5, var78, 0x0000000F);
                    var81 = LWR (var5, var80, 0x0000000C);
                    var82 = ((int *) (var16 + var81))[0];
                    if (!(var82 == 0x446D8DE6))
                      goto label25;
                    var65 = sceKernelCreateThreadPatched2;
                    goto label160;
                  }
                }
                else
                {
                  var40 = *((int *) 0x00003D70);
                  var41 = LWL (var5);
                  if (var40 != 0x00000000)
                  {

                  label162:
                    var50 = LWR (var5, var41, 0x00000000);
                    var53 var54 = strcmp (var50, "KUBridge");
                    if (var53 == 0x00000000)
                    {
                      goto label166;
                    }
                    else
                    {
                      var55 = LWL (var5, 0x03E00000, 0x0000000F);
                      goto label168;
                    }
                  }
                  else
                  {
                    var42 = LWR (var5, var41, 0x00000000);
                    var45 var46 = strcmp (var42, "LoadExecForUser");
                    if (var45 != 0x00000000)
                    {
                      var41 = LWL (var5);
                      goto label162;
                    }
                    else
                    {
                      var47 = LWL (var5, var45, 0x0000000F);
                      var48 = LWR (var5, var47, 0x0000000C);
                      var49 = ((int *) (var16 + var48))[0];
                      if (var49 == 0x05572A5F)
                      {
                        var65 = sceKernelExitVSHKernelPatched;
                        goto label160;
                      }
                      else
                      {
                        var41 = LWL (var5, var49, 0x00000003);
                        goto label162;
                      }
                    }
                  }
                }
              }
            }
            else
            {
              if (var22 != 0x00000000)
              {
                var38 = var11 << 0x00000008;
                goto label176;
              }
              else
              {
                goto label178;
              }
            }
          }
          var23 = ((unsigned char *) var5)[8];
        }
      }
      var24 = *((int *) 0x00003DE8);
      var25 = ((int *) sp)[1];
      var26 = var25 + (var23 << 0x00000002);
      ((int *) sp)[1] = var26;
      if (((var26 < var24)) != 0x00000000)
        continue;
      break;
    }
  }
  ra = ((int *) sp)[11];
  var27 = ((int *) sp)[10];
  var28 = ((int *) sp)[9];
  var29 = ((int *) sp)[8];
  var30 = ((int *) sp)[7];
  var31 = ((int *) sp)[6];
  var32 = ((int *) sp)[5];
  var33 = ((int *) sp)[4];
  var34 = ((int *) sp)[3];
  var35 = ((int *) sp)[2];
  sp = sp + 0x00000030;
  clearcache();
  return;
}

/**
 * Subroutine at address 0x00002A88
 */
void sceKernelLinkLibraryEntriesPatched(void *arg0, u32 arg1) {
    var3 = sceKernelLinkLibraryEntries(arg0, arg1);
    if (g0x00003E10 != 0) {
        sub_022D4 ();
    }
    return var3;
}

/**
 * Subroutine at address 0x00002ACC
 */
int sceKernelLinkLibraryEntriesWithModulePatched(int arg1, void *address, int arg3) {
    var4 = sceKernelLinkLibraryEntriesWithModule();
    if(g0x00003E10 == 0) {
        if(var4 < 0) {
            g0x00003DE4 = sceKernelGetModuleIdByAddress(address);
            g0x00003E10 = address;
            g0x00003DE8 = arg3;
        }
    }
    sub_022D4();
    return var4;
}

/**
 * Subroutine at address 0x00002B54
 */
void sub_02B54 ()
{
    asm( "lui $2, 0x8000",
	     "or  $1, $1, $2",
		 "jr $1",
		 "nop");
}

/**
 * Subroutine at address 0x00002B64
 */
void sub_02B64 ()
{
    asm( "lui $3, 0x8000",
	     "or  $2, $2, $3",
		 "jr $2",
		 "nop");
}

/**
 * Subroutine at address 0x00002B74
 */
void sub_02B74 ()
{
    asm( "lui $2, 0x8000",
	     "or  $3, $3, $2",
		 "jr $3",
		 "nop");
}

/**
 * Subroutine at address 0x00002B84
 */
void sub_02B84 ()
{
    asm( "lui $2, 0x8000",
	     "or  $4, $4, $2",
		 "jr $4",
		 "nop");
}

/**
 * Subroutine at address 0x00002B94
 */
void sub_02B94 ()
{
    asm( "lui $2, 0x8000",
	     "or  $5, $5, $2",
		 "jr $5",
		 "nop");
}

/**
 * Subroutine at address 0x00002BA4
 */
void sub_02BA4 ()
{
    asm( "lui $2, 0x8000",
	     "or  $6, $6, $2",
		 "jr $6",
		 "nop");
}

/**
 * Subroutine at address 0x00002BB4
 */
void sub_02BB4 ()
{
    asm( "lui $2, 0x8000",
	     "or  $7, $7, $2",
		 "jr $7",
		 "nop");
}

/**
 * Subroutine at address 0x00002BC4
 */
void sub_02BC4 ()
{
    asm( "lui $2, 0x8000",
	     "or  $8, $8, $2",
		 "jr $8",
		 "nop");
}

/**
 * Subroutine at address 0x00002BD4
 */
void sub_02BD4 ()
{
    asm( "lui $2, 0x8000",
	     "or  $9, $9, $2",
		 "jr $9",
		 "nop");
}

/**
 * Subroutine at address 0x00002BE4
 */
void sub_02BE4 ()
{
    asm( "lui $2, 0x8000",
	     "or  $10, $10, $2",
		 "jr  $10",
		 "nop");
}

/**
 * Subroutine at address 0x00002BF4
 */
void sub_02BF4 ()
{
    asm( "lui $2, 0x8000",
	     "or  $11, $11, $2",
		 "jr $11",
		 "nop");
}

/**
 * Subroutine at address 0x00002C04
 */
void sub_02C04 ()
{
    asm( "lui $2, 0x8000",
	     "or  $12, $12, $2",
		 "jr $12",
		 "nop");
}

/**
 * Subroutine at address 0x00002C14
 */
void sub_02C14 ()
{
    asm( "lui $2, 0x8000",
	     "or  $13, $13, $2",
		 "jr $13",
		 "nop");
}

/**
 * Subroutine at address 0x00002C24
 */
void sub_02C24 ()
{
    asm( "lui $2, 0x8000",
	     "or  $14, $14, $2",
		 "jr  $14",
		 "nop");
}

/**
 * Subroutine at address 0x00002C34
 */
void sub_02C34 ()
{
    asm( "lui $2, 0x8000",
	     "or  $15, $15, $2",
		 "jr  $15",
		 "nop");
}

/**
 * Subroutine at address 0x00002C44
 */
void sub_02C44 ()
{
    asm( "lui $2, 0x8000",
	     "or  $24, $24, $2",
		 "jr  $24",
		 "nop");
}

/**
 * Subroutine at address 0x00002C54
 */
void sub_02C54 ()
{
    asm( "lui $2, 0x8000",
	     "or  $25, $25, $2",
		 "jr  $25",
		 "nop");
}

/**
 * Subroutine at address 0x00002C64
 */
void sub_02C64 ()
{
    asm( "lui $2, 0x8000",
	     "or  $3, $16, $2",
		 "jr  $3",
		 "nop");
}

/**
 * Subroutine at address 0x00002C74
 */
void sub_02C74 ()
{
    asm( "lui $2, 0x8000",
	     "or  $3, $17, $2",
		 "jr  $3",
		 "nop");
}

/**
 * Subroutine at address 0x00002C84
 */
void sub_02C84 ()
{
    asm( "lui $2, 0x8000",
	     "or  $3, $18, $2",
		 "jr  $3",
		 "nop");
}

/**
 * Subroutine at address 0x00002C94
 */
void sub_02C94 ()
{
    asm( "lui $2, 0x8000",
	     "or  $3, $19, $2",
		 "jr  $3",
		 "nop");
}

/**
 * Subroutine at address 0x00002CA4
 */
void sub_02CA4 ()
{
    asm( "lui $2, 0x8000",
	     "or  $3, $20, $2",
		 "jr  $3",
		 "nop");
}

/**
 * Subroutine at address 0x00002CB4
 */
void sub_02CB4 ()
{
    asm( "lui $2, 0x8000",
	     "or  $3, $21, $2",
		 "jr  $3",
		 "nop");
}

/**
 * Subroutine at address 0x00002CC4
 */
void sub_02CC4 ()
{
    asm( "lui $2, 0x8000",
	     "or  $3, $22, $2",
		 "jr  $3",
		 "nop");
}

/**
 * Subroutine at address 0x00002CD4
 */
void sub_02CD4 ()
{
    asm( "lui $2, 0x8000",
	     "or  $3, $23, $2",
		 "jr  $3",
		 "nop");
}

/**
 * Subroutine at address 0x00002CE4
 */
void sub_02CE4 ()
{
    asm( "lui $1, 0x8000",
	     "or  $2, $2, $1",
		 "jr  $2",
		 "nop");
}

/**
 * Subroutine at address 0x00002CF4
 */
void sub_02CF4 ()
{
    asm( "lui $1, 0x8000",
	     "or  $3, $3, $1",
		 "jr  $3",
		 "nop");
}

/**
 * Subroutine at address 0x00002D04
 */
void sub_02D04 ()
{
    asm( "lui $1, 0x8000",
	     "or  $4, $4, $1",
		 "jr  $4",
		 "nop");
}

/**
 * Subroutine at address 0x00002D14
 */
void sub_02D14 ()
{
    asm( "lui $1, 0x8000",
	     "or  $5, $5, $1",
		 "jr  $5",
		 "nop");
}

/**
 * Subroutine at address 0x00002D24
 */
void sub_02D24 ()
{
    asm( "lui $1, 0x8000",
	     "or  $6, $6, $1",
		 "jr  $6",
		 "nop");
}

/**
 * Subroutine at address 0x00002D34
 */
void sub_02D34 ()
{
    asm( "lui $1, 0x8000",
	     "or  $7, $7, $1",
		 "jr  $7",
		 "nop");
}

/**
 * Subroutine at address 0x00002D44
 */
void sub_02D44 ()
{
    asm( "lui $1, 0x8000",
	     "or  $8, $8, $1",
		 "jr  $8",
		 "nop");
}

/**
 * Subroutine at address 0x00002D54
 */
void sub_02D54 ()
{
    asm( "lui $1, 0x8000",
	     "or  $9, $9, $1",
		 "jr  $9",
		 "nop");
}

/**
 * Subroutine at address 0x00002D64
 */
void sub_02D64 ()
{
    asm( "lui $1, 0x8000",
	     "or  $10, $10, $1",
		 "jr  $10",
		 "nop");
}

/**
 * Subroutine at address 0x00002D74
 */
void sub_02D74 ()
{
    asm( "lui $1, 0x8000",
	     "or  $11, $11, $1",
		 "jr  $11",
		 "nop");
}

/**
 * Subroutine at address 0x00002D84
 */
void sub_02D84 ()
{
    asm( "lui $1, 0x8000",
	     "or  $12, $12, $1",
		 "jr  $12",
		 "nop");
}

/**
 * Subroutine at address 0x00002D94
 */
void sub_02D94 ()
{
    asm( "lui $1, 0x8000",
	     "or  $13, $13, $1",
		 "jr  $13",
		 "nop");
}

/**
 * Subroutine at address 0x00002DA4
 */
void sub_02DA4 ()
{
    asm( "lui $1, 0x8000",
	     "or  $14, $14, $1",
		 "jr  $14",
		 "nop");
}

/**
 * Subroutine at address 0x00002DB4
 */
void sub_02DB4 ()
{
    asm( "lui $1, 0x8000",
	     "or  $15, $15, $1",
		 "jr  $15",
		 "nop");
}

/**
 * Subroutine at address 0x00002DC4
 */
void sub_02DC4 ()
{
    asm( "lui $1, 0x8000",
	     "or  $24, $24, $1",
		 "jr  $24",
		 "nop");
}

/**
 * Subroutine at address 0x00002DD4
 */
void sub_02DD4 ()
{
    asm( "lui $1, 0x8000",
	     "or  $25, $25, $1",
		 "jr  $25",
		 "nop");
}

/**
 * Subroutine at address 0x00002DE4 pspSdkSetK1
 */

