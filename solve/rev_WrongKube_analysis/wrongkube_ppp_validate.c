
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 * validate_cluster(char *param_1)

{
  char *pcVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  longlong lVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  ulonglong uVar15;
  char *pcVar16;
  char *pcVar17;
  longlong lVar18;
  longlong lVar19;
  undefined8 *puVar20;
  char cVar21;
  uint uVar22;
  int iVar23;
  int iVar24;
  byte bVar25;
  int iVar26;
  undefined4 uVar27;
  int iVar28;
  undefined4 uVar29;
  undefined1 *puVar30;
  int iVar31;
  longlong lVar32;
  undefined1 auVar33 [16];
  undefined1 auVar34 [16];
  undefined1 auVar35 [16];
  undefined1 auVar36 [16];
  undefined1 auVar37 [16];
  undefined4 unaff_XMM6_Da;
  undefined4 unaff_XMM6_Db;
  undefined4 unaff_XMM6_Dc;
  undefined4 unaff_XMM6_Dd;
  undefined4 unaff_XMM7_Da;
  undefined4 unaff_XMM7_Db;
  undefined4 unaff_XMM7_Dc;
  undefined4 unaff_XMM7_Dd;
  int aiStackX_8 [8];
  undefined8 uStack_48;

                    /* 0x1000  5  validate_cluster */
  uStack_48 = 0x180001016;
  uVar15 = FUN_180009520();
  lVar5 = -uVar15;
  *(undefined4 *)(&stack0x0002a730 + lVar5) = unaff_XMM7_Da;
  *(undefined4 *)(&stack0x0002a734 + lVar5) = unaff_XMM7_Db;
  *(undefined4 *)(&stack0x0002a738 + lVar5) = unaff_XMM7_Dc;
  *(undefined4 *)(&stack0x0002a73c + lVar5) = unaff_XMM7_Dd;
  *(undefined4 *)(&stack0x0002a720 + lVar5) = unaff_XMM6_Da;
  *(undefined4 *)(&stack0x0002a724 + lVar5) = unaff_XMM6_Db;
  *(undefined4 *)(&stack0x0002a728 + lVar5) = unaff_XMM6_Dc;
  *(undefined4 *)(&stack0x0002a72c + lVar5) = unaff_XMM6_Dd;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000103e;
  pcVar16 = strstr(param_1,"\"nodes\":[");
  lVar32 = 0;
  if (pcVar16 != (char *)0x0) {
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000105d;
    pcVar16 = strchr(pcVar16,0x5b);
    lVar32 = 0;
    if (pcVar16 != (char *)0x0) {
      *(char **)(&stack0x0002a710 + lVar5) = param_1;
      puVar30 = &stack0x00000060 + lVar5;
      lVar32 = 0;
      pcVar1 = &stack0x00029e60 + lVar5;
      while( true ) {
        if ((pcVar16[1] == '\0') || (pcVar16[1] == ']')) goto LAB_1800018c7;
        if (lVar32 == 0xa0) break;
        *(longlong *)(&stack0x0002a718 + lVar5) = lVar32;
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800010fd;
        pcVar16 = strchr(pcVar16 + 1,0x7b);
        if (pcVar16 == (char *)0x0) {
LAB_1800018b2:
          lVar32 = *(longlong *)(&stack0x0002a718 + lVar5);
          goto LAB_1800018c7;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001116;
        pcVar17 = strchr(pcVar16,0x7d);
        if (pcVar17 == (char *)0x0) goto LAB_1800018b2;
        *(char **)(&stack0x0002a708 + lVar5) = pcVar17;
        pcVar17 = pcVar17 + (1 - (longlong)pcVar16);
        if ((char *)0x3fe < pcVar17) {
          pcVar17 = (char *)0x3ff;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001158;
        FUN_180009370((undefined8 *)(&stack0x00015960 + lVar5),(undefined8 *)pcVar16,
                      (ulonglong)pcVar17);
        (&stack0x00015960)[(longlong)pcVar17 + lVar5] = 0;
        lVar32 = *(longlong *)(&stack0x0002a718 + lVar5) * 0x228 + lVar5;
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000118b;
        FUN_1800083d0(pcVar1,0x40,"\"%s\":\"",&DAT_18002c3ae);
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001196;
        pcVar16 = strstr(&stack0x00015960 + lVar5,pcVar1);
        if (pcVar16 == (char *)0x0) {
          (&stack0x00000060)[lVar32] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800011aa;
          lVar18 = FUN_180008440((longlong)pcVar1);
          lVar19 = 1;
          for (pcVar16 = pcVar16 + lVar18; (cVar21 = *pcVar16, cVar21 != '\0' && (cVar21 != '\"'));
              pcVar16 = pcVar16 + 1) {
            pcVar17 = pcVar16;
            if (cVar21 == '\\') {
              pcVar17 = pcVar16 + 1;
              cVar21 = pcVar16[1];
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar17 = pcVar16;
              }
            }
            puVar30[lVar19 + -1] = cVar21;
            cVar21 = pcVar17[1];
            if ((cVar21 == '\0') || (cVar21 == '\"')) goto LAB_180001280;
            if (lVar19 == 0x3f) {
              lVar19 = 0x3f;
              goto LAB_180001280;
            }
            pcVar16 = pcVar17 + 1;
            if (cVar21 == '\\') {
              cVar21 = pcVar17[2];
              pcVar16 = pcVar17 + 2;
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar16 = pcVar17 + 1;
              }
            }
            puVar30[lVar19] = cVar21;
            lVar19 = lVar19 + 2;
          }
          lVar19 = lVar19 + -1;
LAB_180001280:
          (&stack0x00000060 + lVar32)[lVar19] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000129c;
        FUN_1800083d0(pcVar1,0x40,"\"%s\":\"",&DAT_18002c3b1);
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800012ab;
        pcVar16 = strstr(&stack0x00015960 + lVar5,pcVar1);
        if (pcVar16 == (char *)0x0) {
          (&stack0x000000a0)[lVar32] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800012bf;
          lVar18 = FUN_180008440((longlong)pcVar1);
          pcVar16 = pcVar16 + lVar18;
          lVar18 = 0;
          while( true ) {
            cVar21 = *pcVar16;
            if ((cVar21 == '\0') || (cVar21 == '\"')) goto LAB_180001370;
            pcVar17 = pcVar16;
            if (cVar21 == '\\') {
              pcVar17 = pcVar16 + 1;
              cVar21 = pcVar16[1];
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar17 = pcVar16;
              }
            }
            puVar30[lVar18 + 0x40] = cVar21;
            cVar21 = pcVar17[1];
            if ((cVar21 == '\0') || (cVar21 == '\"')) break;
            if (lVar18 == 0x1e) {
              lVar18 = 0x1f;
              goto LAB_180001370;
            }
            pcVar16 = pcVar17 + 1;
            if (cVar21 == '\\') {
              cVar21 = pcVar17[2];
              pcVar16 = pcVar17 + 2;
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar16 = pcVar17 + 1;
              }
            }
            pcVar16 = pcVar16 + 1;
            puVar30[lVar18 + 0x41] = cVar21;
            lVar18 = lVar18 + 2;
          }
          lVar18 = lVar18 + 1;
LAB_180001370:
          (&stack0x000000a0)[lVar18 + lVar32] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000138d;
        FUN_1800083d0(pcVar1,0x40,"\"%s\":\"",&DAT_18002c3b6);
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000139c;
        pcVar16 = strstr(&stack0x00015960 + lVar5,pcVar1);
        if (pcVar16 == (char *)0x0) {
          (&stack0x000000c0)[lVar32] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800013b0;
          lVar18 = FUN_180008440((longlong)pcVar1);
          pcVar16 = pcVar16 + lVar18;
          lVar18 = 0;
          while( true ) {
            cVar21 = *pcVar16;
            if ((cVar21 == '\0') || (cVar21 == '\"')) goto LAB_180001460;
            pcVar17 = pcVar16;
            if (cVar21 == '\\') {
              pcVar17 = pcVar16 + 1;
              cVar21 = pcVar16[1];
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar17 = pcVar16;
              }
            }
            puVar30[lVar18 + 0x60] = cVar21;
            cVar21 = pcVar17[1];
            if ((cVar21 == '\0') || (cVar21 == '\"')) break;
            if (lVar18 == 0x3e) {
              lVar18 = 0x3f;
              goto LAB_180001460;
            }
            pcVar16 = pcVar17 + 1;
            if (cVar21 == '\\') {
              cVar21 = pcVar17[2];
              pcVar16 = pcVar17 + 2;
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar16 = pcVar17 + 1;
              }
            }
            pcVar16 = pcVar16 + 1;
            puVar30[lVar18 + 0x61] = cVar21;
            lVar18 = lVar18 + 2;
          }
          lVar18 = lVar18 + 1;
LAB_180001460:
          (&stack0x000000c0)[lVar18 + lVar32] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000147d;
        FUN_1800083d0(pcVar1,0x40,"\"%s\":\"","namespace");
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000148c;
        pcVar16 = strstr(&stack0x00015960 + lVar5,pcVar1);
        if (pcVar16 == (char *)0x0) {
          (&stack0x00000100)[lVar32] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800014a0;
          lVar18 = FUN_180008440((longlong)pcVar1);
          pcVar16 = pcVar16 + lVar18;
          lVar18 = 0;
          while( true ) {
            cVar21 = *pcVar16;
            if ((cVar21 == '\0') || (cVar21 == '\"')) goto LAB_180001550;
            pcVar17 = pcVar16;
            if (cVar21 == '\\') {
              pcVar17 = pcVar16 + 1;
              cVar21 = pcVar16[1];
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar17 = pcVar16;
              }
            }
            puVar30[lVar18 + 0xa0] = cVar21;
            cVar21 = pcVar17[1];
            if ((cVar21 == '\0') || (cVar21 == '\"')) break;
            if (lVar18 == 0x3e) {
              lVar18 = 0x3f;
              goto LAB_180001550;
            }
            pcVar16 = pcVar17 + 1;
            if (cVar21 == '\\') {
              cVar21 = pcVar17[2];
              pcVar16 = pcVar17 + 2;
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar16 = pcVar17 + 1;
              }
            }
            pcVar16 = pcVar16 + 1;
            puVar30[lVar18 + 0xa1] = cVar21;
            lVar18 = lVar18 + 2;
          }
          lVar18 = lVar18 + 1;
LAB_180001550:
          (&stack0x00000100)[lVar18 + lVar32] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001570;
        FUN_1800083d0(pcVar1,0x40,"\"%s\":\"","labels");
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000157f;
        pcVar16 = strstr(&stack0x00015960 + lVar5,pcVar1);
        if (pcVar16 == (char *)0x0) {
          (&stack0x00000140)[lVar32] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001593;
          lVar18 = FUN_180008440((longlong)pcVar1);
          pcVar16 = pcVar16 + lVar18;
          lVar18 = 0;
          while( true ) {
            cVar21 = *pcVar16;
            if ((cVar21 == '\0') || (cVar21 == '\"')) goto LAB_180001640;
            pcVar17 = pcVar16;
            if (cVar21 == '\\') {
              pcVar17 = pcVar16 + 1;
              cVar21 = pcVar16[1];
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar17 = pcVar16;
              }
            }
            puVar30[lVar18 + 0xe0] = cVar21;
            cVar21 = pcVar17[1];
            if ((cVar21 == '\0') || (cVar21 == '\"')) break;
            if (lVar18 == 0x7e) {
              lVar18 = 0x7f;
              goto LAB_180001640;
            }
            pcVar16 = pcVar17 + 1;
            if (cVar21 == '\\') {
              cVar21 = pcVar17[2];
              pcVar16 = pcVar17 + 2;
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar16 = pcVar17 + 1;
              }
            }
            pcVar16 = pcVar16 + 1;
            puVar30[lVar18 + 0xe1] = cVar21;
            lVar18 = lVar18 + 2;
          }
          lVar18 = lVar18 + 1;
LAB_180001640:
          (&stack0x00000140)[lVar18 + lVar32] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001660;
        FUN_1800083d0(pcVar1,0x40,"\"%s\":\"","selector");
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000166f;
        pcVar16 = strstr(&stack0x00015960 + lVar5,pcVar1);
        if (pcVar16 == (char *)0x0) {
          (&stack0x000001c0)[lVar32] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001683;
          lVar18 = FUN_180008440((longlong)pcVar1);
          pcVar16 = pcVar16 + lVar18;
          lVar18 = 0;
          while( true ) {
            cVar21 = *pcVar16;
            if ((cVar21 == '\0') || (cVar21 == '\"')) goto LAB_180001730;
            pcVar17 = pcVar16;
            if (cVar21 == '\\') {
              pcVar17 = pcVar16 + 1;
              cVar21 = pcVar16[1];
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar17 = pcVar16;
              }
            }
            puVar30[lVar18 + 0x160] = cVar21;
            cVar21 = pcVar17[1];
            if ((cVar21 == '\0') || (cVar21 == '\"')) break;
            if (lVar18 == 0x7e) {
              lVar18 = 0x7f;
              goto LAB_180001730;
            }
            pcVar16 = pcVar17 + 1;
            if (cVar21 == '\\') {
              cVar21 = pcVar17[2];
              pcVar16 = pcVar17 + 2;
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar16 = pcVar17 + 1;
              }
            }
            pcVar16 = pcVar16 + 1;
            puVar30[lVar18 + 0x161] = cVar21;
            lVar18 = lVar18 + 2;
          }
          lVar18 = lVar18 + 1;
LAB_180001730:
          (&stack0x000001c0)[lVar18 + lVar32] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001750;
        FUN_1800083d0(pcVar1,0x40,"\"%s\":\"","mount");
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000175f;
        pcVar16 = strstr(&stack0x00015960 + lVar5,pcVar1);
        if (pcVar16 == (char *)0x0) {
          (&stack0x00000240)[lVar32] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001773;
          lVar18 = FUN_180008440((longlong)pcVar1);
          pcVar16 = pcVar16 + lVar18;
          lVar18 = 0;
          while( true ) {
            cVar21 = *pcVar16;
            if ((cVar21 == '\0') || (cVar21 == '\"')) goto LAB_180001820;
            pcVar17 = pcVar16;
            if (cVar21 == '\\') {
              pcVar17 = pcVar16 + 1;
              cVar21 = pcVar16[1];
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar17 = pcVar16;
              }
            }
            puVar30[lVar18 + 0x1e0] = cVar21;
            cVar21 = pcVar17[1];
            if ((cVar21 == '\0') || (cVar21 == '\"')) break;
            if (lVar18 == 0x3e) {
              lVar18 = 0x3f;
              goto LAB_180001820;
            }
            pcVar16 = pcVar17 + 1;
            if (cVar21 == '\\') {
              cVar21 = pcVar17[2];
              pcVar16 = pcVar17 + 2;
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar16 = pcVar17 + 1;
              }
            }
            pcVar16 = pcVar16 + 1;
            puVar30[lVar18 + 0x1e1] = cVar21;
            lVar18 = lVar18 + 2;
          }
          lVar18 = lVar18 + 1;
LAB_180001820:
          (&stack0x00000240)[lVar18 + lVar32] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001840;
        FUN_1800083d0(pcVar1,0x40,"\"%s\":","replicas");
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000184f;
        pcVar16 = strstr(&stack0x00015960 + lVar5,pcVar1);
        if (pcVar16 == (char *)0x0) {
          iVar14 = 1;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000185f;
          lVar18 = FUN_180008440((longlong)pcVar1);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000186a;
          iVar14 = atoi(pcVar16 + lVar18);
        }
        *(int *)(&stack0x00000280 + lVar32) = iVar14;
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001893;
        FUN_1800083d0(pcVar1,0x40,"\"%s\":",&DAT_18002c3e4);
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800018a2;
        pcVar16 = strstr(&stack0x00015960 + lVar5,pcVar1);
        if (pcVar16 == (char *)0x0) {
          iVar14 = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000109b;
          lVar18 = FUN_180008440((longlong)pcVar1);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800010a6;
          iVar14 = atoi(pcVar16 + lVar18);
        }
        pcVar16 = *(char **)(&stack0x0002a708 + lVar5);
        *(int *)(&stack0x00000284 + lVar32) = iVar14;
        lVar32 = *(longlong *)(&stack0x0002a718 + lVar5) + 1;
        puVar30 = puVar30 + 0x228;
      }
      lVar32 = 0xa0;
LAB_1800018c7:
      param_1 = *(char **)(&stack0x0002a710 + lVar5);
    }
  }
  uVar29 = 0;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800018dd;
  pcVar16 = strstr(param_1,"\"edges\":[");
  if (pcVar16 != (char *)0x0) {
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800018f3;
    pcVar16 = strchr(pcVar16,0x5b);
    if (pcVar16 != (char *)0x0) {
      *(longlong *)(&stack0x0002a718 + lVar5) = lVar32;
      puVar30 = &stack0x00015960 + lVar5;
      lVar32 = 0;
      pcVar1 = &stack0x0002a510 + lVar5;
      while( true ) {
        if ((pcVar16[1] == '\0') || (pcVar16[1] == ']')) goto LAB_180001de2;
        if (lVar32 == 0x140) break;
        *(longlong *)(&stack0x0002a708 + lVar5) = lVar32;
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000198d;
        pcVar16 = strchr(pcVar16 + 1,0x7b);
        if (pcVar16 == (char *)0x0) {
LAB_180001dd3:
          lVar32 = *(longlong *)(&stack0x0002a708 + lVar5);
          goto LAB_180001de2;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800019a6;
        pcVar17 = strchr(pcVar16,0x7d);
        if (pcVar17 == (char *)0x0) goto LAB_180001dd3;
        *(char **)(&stack0x0002a710 + lVar5) = pcVar17;
        pcVar17 = pcVar17 + (1 - (longlong)pcVar16);
        if ((char *)0x2fe < pcVar17) {
          pcVar17 = (char *)0x2ff;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800019e5;
        FUN_180009370((undefined8 *)(&stack0x00029e60 + lVar5),(undefined8 *)pcVar16,
                      (ulonglong)pcVar17);
        (&stack0x00029e60)[(longlong)pcVar17 + lVar5] = 0;
        lVar32 = *(longlong *)(&stack0x0002a708 + lVar5) * 0x104 + lVar5;
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001a22;
        FUN_1800083d0(pcVar1,0x40,"\"%s\":\"","source_id");
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001a2d;
        pcVar16 = strstr(&stack0x00029e60 + lVar5,pcVar1);
        if (pcVar16 == (char *)0x0) {
          (&stack0x00015960)[lVar32] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001a41;
          lVar18 = FUN_180008440((longlong)pcVar1);
          lVar19 = 1;
          for (pcVar16 = pcVar16 + lVar18; (cVar21 = *pcVar16, cVar21 != '\0' && (cVar21 != '\"'));
              pcVar16 = pcVar16 + 1) {
            pcVar17 = pcVar16;
            if (cVar21 == '\\') {
              pcVar17 = pcVar16 + 1;
              cVar21 = pcVar16[1];
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar17 = pcVar16;
              }
            }
            puVar30[lVar19 + -1] = cVar21;
            cVar21 = pcVar17[1];
            if ((cVar21 == '\0') || (cVar21 == '\"')) goto LAB_180001af0;
            if (lVar19 == 0x3f) {
              lVar19 = 0x3f;
              goto LAB_180001af0;
            }
            pcVar16 = pcVar17 + 1;
            if (cVar21 == '\\') {
              cVar21 = pcVar17[2];
              pcVar16 = pcVar17 + 2;
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar16 = pcVar17 + 1;
              }
            }
            puVar30[lVar19] = cVar21;
            lVar19 = lVar19 + 2;
          }
          lVar19 = lVar19 + -1;
LAB_180001af0:
          (&stack0x00015960 + lVar32)[lVar19] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001b0c;
        FUN_1800083d0(pcVar1,0x40,"\"%s\":\"","target_id");
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001b1b;
        pcVar16 = strstr(&stack0x00029e60 + lVar5,pcVar1);
        if (pcVar16 == (char *)0x0) {
          (&stack0x000159a0)[lVar32] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001b2f;
          lVar18 = FUN_180008440((longlong)pcVar1);
          lVar19 = 1;
          for (pcVar16 = pcVar16 + lVar18; (cVar21 = *pcVar16, cVar21 != '\0' && (cVar21 != '\"'));
              pcVar16 = pcVar16 + 1) {
            pcVar17 = pcVar16;
            if (cVar21 == '\\') {
              pcVar17 = pcVar16 + 1;
              cVar21 = pcVar16[1];
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar17 = pcVar16;
              }
            }
            puVar30[lVar19 + 0x3f] = cVar21;
            cVar21 = pcVar17[1];
            if ((cVar21 == '\0') || (cVar21 == '\"')) goto LAB_180001bd0;
            if (lVar19 == 0x3f) {
              lVar19 = 0x3f;
              goto LAB_180001bd0;
            }
            pcVar16 = pcVar17 + 1;
            if (cVar21 == '\\') {
              cVar21 = pcVar17[2];
              pcVar16 = pcVar17 + 2;
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar16 = pcVar17 + 1;
              }
            }
            puVar30[lVar19 + 0x40] = cVar21;
            lVar19 = lVar19 + 2;
          }
          lVar19 = lVar19 + -1;
LAB_180001bd0:
          (&stack0x000159a0)[lVar19 + lVar32] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001bed;
        FUN_1800083d0(pcVar1,0x40,"\"%s\":\"","binding");
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001bfc;
        pcVar16 = strstr(&stack0x00029e60 + lVar5,pcVar1);
        if (pcVar16 == (char *)0x0) {
          (&stack0x000159e0)[lVar32] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001c10;
          lVar18 = FUN_180008440((longlong)pcVar1);
          pcVar16 = pcVar16 + lVar18;
          lVar18 = 0;
          while( true ) {
            cVar21 = *pcVar16;
            if ((cVar21 == '\0') || (cVar21 == '\"')) goto LAB_180001cb0;
            pcVar17 = pcVar16;
            if (cVar21 == '\\') {
              pcVar17 = pcVar16 + 1;
              cVar21 = pcVar16[1];
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar17 = pcVar16;
              }
            }
            puVar30[lVar18 + 0x80] = cVar21;
            cVar21 = pcVar17[1];
            if ((cVar21 == '\0') || (cVar21 == '\"')) break;
            if (lVar18 == 0x3e) {
              lVar18 = 0x3f;
              goto LAB_180001cb0;
            }
            pcVar16 = pcVar17 + 1;
            if (cVar21 == '\\') {
              cVar21 = pcVar17[2];
              pcVar16 = pcVar17 + 2;
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar16 = pcVar17 + 1;
              }
            }
            pcVar16 = pcVar16 + 1;
            puVar30[lVar18 + 0x81] = cVar21;
            lVar18 = lVar18 + 2;
          }
          lVar18 = lVar18 + 1;
LAB_180001cb0:
          (&stack0x000159e0)[lVar18 + lVar32] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001cd0;
        FUN_1800083d0(pcVar1,0x40,"\"%s\":\"",&DAT_18002c41c);
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001cdf;
        pcVar16 = strstr(&stack0x00029e60 + lVar5,pcVar1);
        if (pcVar16 == (char *)0x0) {
          (&stack0x00015a20)[lVar32] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001cf3;
          lVar18 = FUN_180008440((longlong)pcVar1);
          pcVar16 = pcVar16 + lVar18;
          lVar18 = 0;
          while( true ) {
            cVar21 = *pcVar16;
            if ((cVar21 == '\0') || (cVar21 == '\"')) goto LAB_180001d90;
            pcVar17 = pcVar16;
            if (cVar21 == '\\') {
              pcVar17 = pcVar16 + 1;
              cVar21 = pcVar16[1];
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar17 = pcVar16;
              }
            }
            puVar30[lVar18 + 0xc0] = cVar21;
            cVar21 = pcVar17[1];
            if ((cVar21 == '\0') || (cVar21 == '\"')) break;
            if (lVar18 == 0x3e) {
              lVar18 = 0x3f;
              goto LAB_180001d90;
            }
            pcVar16 = pcVar17 + 1;
            if (cVar21 == '\\') {
              cVar21 = pcVar17[2];
              pcVar16 = pcVar17 + 2;
              if (cVar21 == '\0') {
                cVar21 = '\\';
                pcVar16 = pcVar17 + 1;
              }
            }
            pcVar16 = pcVar16 + 1;
            puVar30[lVar18 + 0xc1] = cVar21;
            lVar18 = lVar18 + 2;
          }
          lVar18 = lVar18 + 1;
LAB_180001d90:
          (&stack0x00015a20)[lVar18 + lVar32] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001db4;
        FUN_1800083d0(pcVar1,0x40,"\"%s\":",&DAT_18002c3e4);
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001dc3;
        pcVar16 = strstr(&stack0x00029e60 + lVar5,pcVar1);
        if (pcVar16 == (char *)0x0) {
          iVar14 = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000192b;
          lVar18 = FUN_180008440((longlong)pcVar1);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001936;
          iVar14 = atoi(pcVar16 + lVar18);
        }
        pcVar16 = *(char **)(&stack0x0002a710 + lVar5);
        *(int *)(&stack0x00015a60 + lVar32) = iVar14;
        lVar32 = *(longlong *)(&stack0x0002a708 + lVar5) + 1;
        puVar30 = puVar30 + 0x104;
      }
      lVar32 = 0x140;
LAB_180001de2:
      uVar29 = (undefined4)lVar32;
      lVar32 = *(longlong *)(&stack0x0002a718 + lVar5);
    }
  }
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = uVar29;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001e08;
  FUN_1800023a0((int *)(&stack0x0002a6b0 + lVar5),&stack0x00000060 + lVar5,(uint)lVar32,
                &stack0x00015960 + lVar5,*(uint *)(&stack0xffffffffffffffe0 + lVar5));
  iVar6 = *(int *)(&stack0x0002a6b0 + lVar5);
  iVar7 = *(int *)(&stack0x0002a6b4 + lVar5);
  iVar8 = *(int *)(&stack0x0002a6b8 + lVar5);
  iVar9 = *(int *)(&stack0x0002a6bc + lVar5);
  iVar14 = *(int *)(&stack0x0002a6c4 + lVar5);
  iVar2 = *(int *)(&stack0x0002a6c0 + lVar5);
  uVar27 = *(undefined4 *)(&stack0x0002a6d0 + lVar5);
  uVar29 = *(undefined4 *)(&stack0x0002a6cc + lVar5);
  auVar33._0_4_ = -(uint)((int)*(undefined8 *)(&stack0x0002a6c0 + lVar5) == _DAT_18002c000);
  auVar33._4_4_ =
       -(uint)((int)((ulonglong)*(undefined8 *)(&stack0x0002a6c0 + lVar5) >> 0x20) == _UNK_18002c004
              );
  auVar33._8_4_ = -(uint)((int)*(undefined8 *)(&stack0x0002a6cc + lVar5) == _UNK_18002c008);
  auVar33._12_4_ =
       -(uint)((int)((ulonglong)*(undefined8 *)(&stack0x0002a6cc + lVar5) >> 0x20) == _UNK_18002c00c
              );
  auVar33 = packssdw(auVar33,auVar33);
  auVar34._0_4_ = -(uint)(_DAT_18002c010 == iVar6);
  auVar34._4_4_ = -(uint)(_UNK_18002c014 == iVar7);
  auVar34._8_4_ = -(uint)(_UNK_18002c018 == iVar8);
  auVar34._12_4_ = -(uint)(_UNK_18002c01c == iVar9);
  iVar10 = *(int *)(&stack0x0002a6d4 + lVar5);
  iVar11 = *(int *)(&stack0x0002a6d8 + lVar5);
  iVar12 = *(int *)(&stack0x0002a6dc + lVar5);
  iVar13 = *(int *)(&stack0x0002a6e0 + lVar5);
  auVar37._0_4_ = -(uint)(_DAT_18002c020 == iVar10);
  auVar37._4_4_ = -(uint)(_UNK_18002c024 == iVar11);
  auVar37._8_4_ = -(uint)(_UNK_18002c028 == iVar12);
  auVar37._12_4_ = -(uint)(_UNK_18002c02c == iVar13);
  auVar34 = pshuflw(auVar34,auVar37 & auVar34,0xe8);
  auVar34 = pshufhw(auVar34,auVar34,0xe8);
  auVar35._0_8_ = auVar34._4_8_ << 0x20;
  auVar35._8_4_ = auVar34._0_4_;
  auVar35._12_4_ = auVar34._8_4_;
  auVar36._8_8_ = auVar33._8_8_;
  auVar36._0_8_ = auVar35._8_8_;
  auVar33 = psllw(auVar36,0xf);
  auVar33 = packsswb(auVar33,auVar33);
  if (((byte)(SUB161(auVar33 >> 7,0) & 1 | (SUB161(auVar33 >> 0xf,0) & 1) << 1 |
              (SUB161(auVar33 >> 0x17,0) & 1) << 2 | (SUB161(auVar33 >> 0x1f,0) & 1) << 3 |
              (SUB161(auVar33 >> 0x27,0) & 1) << 4 | (SUB161(auVar33 >> 0x2f,0) & 1) << 5 |
              (SUB161(auVar33 >> 0x37,0) & 1) << 6 | SUB161(auVar33 >> 0x3f,0) << 7) == 0xff) &&
     (*(int *)(&stack0x0002a6fc + lVar5) == 0x34af33db)) {
    *(undefined8 *)(&stack0x0002a6a0 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a6a8 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a690 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a698 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a680 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a688 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a670 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a678 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a660 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a668 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a650 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a658 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a640 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a648 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a630 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a638 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a620 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a628 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a610 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a618 + lVar5) = 0;
    if (*(int *)(&stack0x0002a700 + lVar5) == 0xd96b0) {
      *(undefined4 *)(&stack0x0002a718 + lVar5) = uVar27;
      iVar31 = 0x34af33db;
      bVar25 = 0x49;
      iVar26 = 0x47502943;
      lVar32 = 1;
      iVar23 = 0x47502932;
      iVar24 = 0x3c6ef35f;
      uVar22 = 0;
      do {
        iVar28 = iVar31 * 0x19660d + iVar24;
        (&stack0x0002a60f)[lVar32 + lVar5] =
             (&UNK_18002d59f)[lVar32] ^ bVar25 + 0xb7 ^ (byte)((uint)iVar28 >> 0x10) ^ (byte)iVar28;
        iVar28 = iVar31 * 0x17385ca9;
        iVar31 = uVar22 + 1 + (uVar22 | 1) * 0x10 + iVar23 + iVar28;
        iVar28 = iVar28 + iVar26;
        (&stack0x0002a610)[lVar32 + lVar5] =
             (byte)((uint)iVar28 >> 0x10) ^ bVar25 ^ (&DAT_18002d5a0)[lVar32] ^ (byte)iVar28;
        uVar22 = uVar22 + 2;
        bVar25 = bVar25 + 0x92;
        iVar26 = iVar26 + 0x35f8ddc;
        lVar32 = lVar32 + 2;
        iVar23 = iVar23 + 0x35f8dba;
        iVar24 = iVar24 + 0x22;
      } while (lVar32 != 0x31);
      (&stack0x0002a640)[lVar5] = 0;
      *(undefined8 *)(&stack0x0002a510 + lVar5) = s_Abyssal_control_plane_reconciled_18002c0d0._0_8_
      ;
      *(undefined8 *)(&stack0x0002a518 + lVar5) = s_Abyssal_control_plane_reconciled_18002c0d0._8_8_
      ;
      *(undefined8 *)(&stack0x0002a520 + lVar5) =
           s_Abyssal_control_plane_reconciled_18002c0d0._16_8_;
      *(undefined8 *)(&stack0x0002a528 + lVar5) =
           s_Abyssal_control_plane_reconciled_18002c0d0._24_8_;
      *(undefined8 *)(&stack0x0002a530 + lVar5) =
           s_Abyssal_control_plane_reconciled_18002c0d0._32_8_;
      *(ulonglong *)(&stack0x0002a538 + lVar5) =
           CONCAT35(s_Abyssal_control_plane_reconciled_18002c0d0._45_3_,
                    s_Abyssal_control_plane_reconciled_18002c0d0._40_5_);
      *(ulonglong *)(&stack0x0002a53d + lVar5) =
           CONCAT53(s_Abyssal_control_plane_reconciled_18002c0d0._48_5_,
                    s_Abyssal_control_plane_reconciled_18002c0d0._45_3_);
      *(undefined8 *)(&stack0x0002a545 + lVar5) =
           s_Abyssal_control_plane_reconciled_18002c0d0._53_8_;
      pcVar16 = "true";
      uVar27 = *(undefined4 *)(&stack0x0002a718 + lVar5);
      goto LAB_1800022ae;
    }
  }
  else {
    *(undefined8 *)(&stack0x0002a6a0 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a6a8 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a690 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a698 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a680 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a688 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a670 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a678 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a660 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a668 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a650 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a658 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a640 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a648 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a630 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a638 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a620 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a628 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a610 + lVar5) = 0;
    *(undefined8 *)(&stack0x0002a618 + lVar5) = 0;
  }
  if ((iVar14 < 10) || (iVar13 < 4)) {
    if ((iVar2 < 0xb) || (iVar12 < 4)) {
      if (iVar10 < 5 || iVar9 < 0xc) {
        if ((iVar7 < 0x30) || (iVar8 < 0x12)) {
          if (iVar6 < 0x18) {
            *(undefined8 *)(&stack0x0002a540 + lVar5) =
                 s_Abyssal_control_plane_unstable__C_18002c298._48_8_;
            *(undefined8 *)(&stack0x0002a548 + lVar5) =
                 s_Abyssal_control_plane_unstable__C_18002c298._56_8_;
            *(undefined8 *)(&stack0x0002a530 + lVar5) =
                 s_Abyssal_control_plane_unstable__C_18002c298._32_8_;
            *(undefined8 *)(&stack0x0002a538 + lVar5) =
                 s_Abyssal_control_plane_unstable__C_18002c298._40_8_;
            *(undefined8 *)(&stack0x0002a520 + lVar5) =
                 s_Abyssal_control_plane_unstable__C_18002c298._16_8_;
            *(undefined8 *)(&stack0x0002a528 + lVar5) =
                 s_Abyssal_control_plane_unstable__C_18002c298._24_8_;
            *(undefined8 *)(&stack0x0002a510 + lVar5) =
                 s_Abyssal_control_plane_unstable__C_18002c298._0_8_;
            *(undefined8 *)(&stack0x0002a518 + lVar5) =
                 s_Abyssal_control_plane_unstable__C_18002c298._8_8_;
            *(undefined4 *)(&stack0x0002a550 + lVar5) = 0x2e6574;
          }
          else {
            *(ulonglong *)(&stack0x0002a55a + lVar5) =
                 CONCAT26(s_Manifest_is_close__but_scheduler_18002c23e._80_2_,
                          s_Manifest_is_close__but_scheduler_18002c23e._74_6_);
            *(undefined8 *)(&stack0x0002a562 + lVar5) =
                 s_Manifest_is_close__but_scheduler_18002c23e._82_8_;
            *(undefined8 *)(&stack0x0002a550 + lVar5) =
                 s_Manifest_is_close__but_scheduler_18002c23e._64_8_;
            *(ulonglong *)(&stack0x0002a558 + lVar5) =
                 CONCAT62(s_Manifest_is_close__but_scheduler_18002c23e._74_6_,
                          s_Manifest_is_close__but_scheduler_18002c23e._72_2_);
            *(undefined8 *)(&stack0x0002a540 + lVar5) =
                 s_Manifest_is_close__but_scheduler_18002c23e._48_8_;
            *(undefined8 *)(&stack0x0002a548 + lVar5) =
                 s_Manifest_is_close__but_scheduler_18002c23e._56_8_;
            *(undefined8 *)(&stack0x0002a530 + lVar5) =
                 s_Manifest_is_close__but_scheduler_18002c23e._32_8_;
            *(undefined8 *)(&stack0x0002a538 + lVar5) =
                 s_Manifest_is_close__but_scheduler_18002c23e._40_8_;
            *(undefined8 *)(&stack0x0002a520 + lVar5) =
                 s_Manifest_is_close__but_scheduler_18002c23e._16_8_;
            *(undefined8 *)(&stack0x0002a528 + lVar5) =
                 s_Manifest_is_close__but_scheduler_18002c23e._24_8_;
            *(undefined8 *)(&stack0x0002a510 + lVar5) =
                 s_Manifest_is_close__but_scheduler_18002c23e._0_8_;
            *(undefined8 *)(&stack0x0002a518 + lVar5) =
                 s_Manifest_is_close__but_scheduler_18002c23e._8_8_;
          }
        }
        else {
          *(undefined8 *)(&stack0x0002a550 + lVar5) =
               s_Control_plane_is_close__Northbou_18002c1e9._64_8_;
          *(undefined8 *)(&stack0x0002a558 + lVar5) =
               s_Control_plane_is_close__Northbou_18002c1e9._72_8_;
          *(undefined8 *)(&stack0x0002a540 + lVar5) =
               s_Control_plane_is_close__Northbou_18002c1e9._48_8_;
          *(undefined8 *)(&stack0x0002a548 + lVar5) =
               s_Control_plane_is_close__Northbou_18002c1e9._56_8_;
          *(undefined8 *)(&stack0x0002a530 + lVar5) =
               s_Control_plane_is_close__Northbou_18002c1e9._32_8_;
          *(undefined8 *)(&stack0x0002a538 + lVar5) =
               s_Control_plane_is_close__Northbou_18002c1e9._40_8_;
          *(undefined8 *)(&stack0x0002a520 + lVar5) =
               s_Control_plane_is_close__Northbou_18002c1e9._16_8_;
          *(undefined8 *)(&stack0x0002a528 + lVar5) =
               s_Control_plane_is_close__Northbou_18002c1e9._24_8_;
          *(undefined8 *)(&stack0x0002a510 + lVar5) =
               s_Control_plane_is_close__Northbou_18002c1e9._0_8_;
          *(undefined8 *)(&stack0x0002a518 + lVar5) =
               s_Control_plane_is_close__Northbou_18002c1e9._8_8_;
          *(undefined8 *)(&stack0x0002a55d + lVar5) = 0x2e656572676173;
        }
      }
      else {
        *(ulonglong *)(&stack0x0002a54f + lVar5) =
             CONCAT71(s_Shadow_lineage_is_mostly_stable__18002c19a._64_7_,
                      s_Shadow_lineage_is_mostly_stable__18002c19a[0x3f]);
        *(undefined8 *)(&stack0x0002a557 + lVar5) =
             s_Shadow_lineage_is_mostly_stable__18002c19a._71_8_;
        *(undefined8 *)(&stack0x0002a540 + lVar5) =
             s_Shadow_lineage_is_mostly_stable__18002c19a._48_8_;
        *(ulonglong *)(&stack0x0002a548 + lVar5) =
             CONCAT17(s_Shadow_lineage_is_mostly_stable__18002c19a[0x3f],
                      s_Shadow_lineage_is_mostly_stable__18002c19a._56_7_);
        *(undefined8 *)(&stack0x0002a530 + lVar5) =
             s_Shadow_lineage_is_mostly_stable__18002c19a._32_8_;
        *(undefined8 *)(&stack0x0002a538 + lVar5) =
             s_Shadow_lineage_is_mostly_stable__18002c19a._40_8_;
        *(undefined8 *)(&stack0x0002a520 + lVar5) =
             s_Shadow_lineage_is_mostly_stable__18002c19a._16_8_;
        *(undefined8 *)(&stack0x0002a528 + lVar5) =
             s_Shadow_lineage_is_mostly_stable__18002c19a._24_8_;
        *(undefined8 *)(&stack0x0002a510 + lVar5) =
             s_Shadow_lineage_is_mostly_stable__18002c19a._0_8_;
        *(undefined8 *)(&stack0x0002a518 + lVar5) =
             s_Shadow_lineage_is_mostly_stable__18002c19a._8_8_;
      }
    }
    else {
      *(undefined8 *)(&stack0x0002a540 + lVar5) =
           s_Phantom_derivation_stabilizes__b_18002c155._48_8_;
      *(undefined8 *)(&stack0x0002a548 + lVar5) =
           s_Phantom_derivation_stabilizes__b_18002c155._56_8_;
      *(undefined8 *)(&stack0x0002a530 + lVar5) =
           s_Phantom_derivation_stabilizes__b_18002c155._32_8_;
      *(undefined8 *)(&stack0x0002a538 + lVar5) =
           s_Phantom_derivation_stabilizes__b_18002c155._40_8_;
      *(undefined8 *)(&stack0x0002a520 + lVar5) =
           s_Phantom_derivation_stabilizes__b_18002c155._16_8_;
      *(undefined8 *)(&stack0x0002a528 + lVar5) =
           s_Phantom_derivation_stabilizes__b_18002c155._24_8_;
      *(undefined8 *)(&stack0x0002a510 + lVar5) = s_Phantom_derivation_stabilizes__b_18002c155._0_8_
      ;
      *(undefined8 *)(&stack0x0002a518 + lVar5) = s_Phantom_derivation_stabilizes__b_18002c155._8_8_
      ;
      *(undefined8 *)(&stack0x0002a54d + lVar5) = 0x2e6465766c6f73;
    }
  }
  else {
    *(undefined8 *)(&stack0x0002a540 + lVar5) = s_Oracle_projection_is_close__but_a_18002c10d._48_8_
    ;
    *(undefined8 *)(&stack0x0002a548 + lVar5) = s_Oracle_projection_is_close__but_a_18002c10d._56_8_
    ;
    *(undefined8 *)(&stack0x0002a530 + lVar5) = s_Oracle_projection_is_close__but_a_18002c10d._32_8_
    ;
    *(undefined8 *)(&stack0x0002a538 + lVar5) = s_Oracle_projection_is_close__but_a_18002c10d._40_8_
    ;
    *(undefined8 *)(&stack0x0002a520 + lVar5) = s_Oracle_projection_is_close__but_a_18002c10d._16_8_
    ;
    *(undefined8 *)(&stack0x0002a528 + lVar5) = s_Oracle_projection_is_close__but_a_18002c10d._24_8_
    ;
    *(undefined8 *)(&stack0x0002a510 + lVar5) = s_Oracle_projection_is_close__but_a_18002c10d._0_8_;
    *(undefined8 *)(&stack0x0002a518 + lVar5) = s_Oracle_projection_is_close__but_a_18002c10d._8_8_;
    *(undefined8 *)(&stack0x0002a550 + lVar5) = 0x2e736567726576;
  }
  pcVar16 = "false";
LAB_1800022ae:
  uVar3 = *(undefined4 *)(&stack0x0002a6c8 + lVar5);
  uVar4 = *(undefined4 *)(&stack0x0002a700 + lVar5);
  *(int *)(&stack0x00000058 + lVar5) = iVar13;
  *(int *)(&stack0x00000050 + lVar5) = iVar12;
  *(int *)(&stack0x00000048 + lVar5) = iVar11;
  *(int *)(&stack0x00000040 + lVar5) = iVar10;
  *(undefined4 *)(&stack0x00000038 + lVar5) = uVar27;
  *(undefined4 *)(&stack0x00000030 + lVar5) = uVar29;
  *(int *)(&stack0x00000028 + lVar5) = iVar14;
  *(int *)((longlong)aiStackX_8 + lVar5 + 0x18) = iVar2;
  *(int *)((longlong)aiStackX_8 + lVar5 + 0x10) = iVar9;
  *(int *)((longlong)aiStackX_8 + lVar5 + 8) = iVar8;
  *(int *)((longlong)aiStackX_8 + lVar5) = iVar7;
  *(int *)((longlong)aiStackX_8 + lVar5 + -8) = iVar6;
  *(undefined1 **)(&stack0xfffffffffffffff8 + lVar5) = &stack0x0002a610 + lVar5;
  *(undefined1 **)(&stack0xfffffffffffffff0 + lVar5) = &stack0x0002a510 + lVar5;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = uVar4;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = uVar3;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000234a;
  FUN_1800083d0(&stack0x00029e60 + lVar5,0x6a4,
                "{\"ok\":%s,\"score\":%d,\"signature\":%d,\"summary\":\"%s\",\"flag\":\"%s\",\"manifest\":%d,\"edges\":%d,\"meta\":%d,\"shadow\":%d,\"specter\":%d,\"phantom\":%d,\"vm\":%d,\"vm2\":%d,\"vm3\":%d,\"vm4\":%d,\"vm5\":%d,\"vm6\":%d}"
                ,pcVar16);
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002352;
  lVar32 = FUN_180008440((longlong)(&stack0x00029e60 + lVar5));
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002361;
  puVar20 = malloc(lVar32 + 1U);
  if (puVar20 != (undefined8 *)0x0) {
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000237b;
    FUN_180009370(puVar20,(undefined8 *)(&stack0x00029e60 + lVar5),lVar32 + 1U);
  }
  return puVar20;
}
