#include <pspsdk.h>
#include <pspnet_apctl.h>
#include "circulorectangular.h"

/*
 * Imports from library: sceNet_lib
 */
extern int sceNet_lib_7BA3ED91 ();

PSP_MODULE_INFO("Circulo Rectangular", 0x6, 1, 0);

/**
 * Subroutine at address 0x00000000
 */
void sub_00000 (int arg1, int arg2, int arg3) {
    char *var1 = arg2 + arg3;
    if(arg3 != 0) {
        char *a3 = arg2 + arg3 -1;
        char *v1 = a3;
        if(arg1 != a3) {
            int v0 = 0;
            t2 = a3 - arg2;
            t1 = a3 - arg1;
            do {
                if(t0 != v0) v0++;
                else goto;
                v1++;
            } while(t1 < v0);
        }
    }
  var1 = arg2 + arg3;
  var2 = arg1;
  if (arg2 == var1)
  {
    var4 = arg2;

  label10:
    if (arg3 == 0x00000000)
    {

    label18:
    }
    else
    {
      while (1) {
        var8 = ((unsigned char *) var4)[0];
        ((char *) var2)[0] = var8;
        var2 = var2 + 0x00000001;
        var4 = var4 + 0x00000001;
        if (var2 != ((arg1 + (arg3 + 0xFFFFFFFF)) + 0x00000001))
          continue;
        break;
      }
    }
  }
  else
  {
    var3 = var1 + 0xFFFFFFFF;
    var4 = var3;
    if (arg1 == var3)
    {

    label9:
      if (var4 == arg2)
        goto label10;
      if (!(arg3 == 0x00000000))
      {
        var6 = arg1 + arg3;
        while (1) {
          var7 = ((unsigned char *) var3)[0];
          var6 = var6 + 0xFFFFFFFF;
          ((char *) var6)[0] = var7;
          if (!(((var6 - (arg3 + 0xFFFFFFFF)) + 0xFFFFFFFF) != var6))
            break;
          var3 = var3 + 0xFFFFFFFF;
          continue;
        }
      }
      goto label18;
    }
    else
    {
      var5 = 0x00000000;
      while (1) {
        if ((var3 - arg2) == var5)
        {
          goto label10;
        }
        else
        {
          var5 = var5 + 0x00000001;
          var4 = var4 + 0xFFFFFFFF;
          if ((var3 - arg1) != var5)
            continue;
          break;
        }
        goto label19;
      }
      goto label9;
    }
  }

label19:
  return;
}

/**
 * Subroutine at address 0x000000A0
 */
void module_start ()
{
  return;
}

/**
 * Subroutine at address 0x000000A8
 */
void module_stop ()
{
  return;
}

/**
 * Subroutine at address 0x000000B0
 */
void HappyWorld_87654321 (int stackSize, int initPriority) {
    if (stackSize == 0x1000) {
        if(initPriority == 0x42) stackSize = 0x1600;
    }
    sceNetApctlInit(stackSize, initPriority);
}

/**
 * Subroutine at address 0x000000D0
 */
void HappyWorld_01234567(int connIndex) {
    sceNetApctlConnect(connIndex+1);
}

/**
 * Subroutine at address 0x000000D8
 */
int HappyWorld_12345678 (int arg1, int arg2, void *arg3, void *arg4) {
    int ret = sceNet_lib_7BA3ED91(arg1, arg2);
    if(ret >= 4) {
        int var1 = (u32 *)arg3[0]/0x60;
        if(var1 > 0) {
            int i = 0;
            char *ptr1 = arg4;
            char *ptr2 = arg4;
            do {
                sub_00000(ptr1, ptr2, 0x54);
                ptr1 += 0x54;
                ptr2 += 0x60;
                i++;
            } while(i < var1);
        }
    }
    return ret;
}

