
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 * validate_cluster(char *param_1)

{
  undefined1 *puVar1;
  longlong *plVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  ushort uVar7;
  longlong lVar8;
  longlong lVar9;
  byte bVar10;
  int iVar11;
  uint uVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  int iVar19;
  int iVar20;
  int iVar21;
  ulonglong uVar22;
  char *pcVar23;
  char *pcVar24;
  longlong lVar25;
  longlong lVar26;
  char *pcVar27;
  undefined4 extraout_var;
  undefined4 extraout_var_00;
  undefined4 extraout_var_01;
  undefined4 extraout_var_02;
  undefined4 extraout_var_03;
  undefined4 extraout_var_04;
  undefined4 extraout_var_05;
  undefined8 *puVar28;
  longlong lVar29;
  char cVar30;
  uint uVar31;
  uint uVar32;
  uint uVar33;
  uint uVar34;
  uint uVar35;
  size_t sVar36;
  undefined4 *puVar37;
  undefined1 *puVar38;
  byte *pbVar39;
  uint uVar40;
  int iVar41;
  ulonglong uVar42;
  int iVar43;
  uint uVar44;
  int iVar45;
  int iVar46;
  uint uVar47;
  char *pcVar48;
  byte *pbVar49;
  uint uVar50;
  char *pcVar51;
  undefined8 uVar52;
  uint uVar53;
  uint uVar54;
  int iVar55;
  uint uVar56;
  uint uVar57;
  int iVar58;
  byte *pbVar59;
  code *pcVar60;
  bool bVar61;
  undefined8 unaff_XMM6_Qa;
  undefined8 unaff_XMM6_Qb;
  undefined8 unaff_XMM7_Qa;
  undefined8 unaff_XMM7_Qb;
  undefined1 auVar62 [16];
  undefined8 unaff_XMM8_Qa;
  undefined8 unaff_XMM8_Qb;
  undefined1 auVar63 [16];
  undefined1 auVar64 [16];
  undefined1 auVar65 [16];
  undefined8 unaff_XMM9_Qa;
  undefined8 unaff_XMM9_Qb;
  undefined1 auVar66 [16];
  undefined1 auVar67 [16];
  undefined8 unaff_XMM10_Qa;
  undefined8 unaff_XMM10_Qb;
  undefined8 unaff_XMM11_Qa;
  undefined8 unaff_XMM11_Qb;
  undefined8 unaff_XMM12_Qa;
  undefined8 unaff_XMM12_Qb;
  undefined8 unaff_XMM13_Qa;
  undefined8 unaff_XMM13_Qb;
  undefined8 unaff_XMM14_Qa;
  undefined8 unaff_XMM14_Qb;
  undefined8 unaff_XMM15_Qa;
  undefined8 unaff_XMM15_Qb;
  int aiStackX_8 [8];
  undefined8 uStack_48;

                    /* 0x1000  5  validate_cluster */
  uStack_48 = 0x180001016;
  uVar22 = FUN_180007dc0();
  lVar8 = -uVar22;
  *(undefined8 *)(&stack0x0002a820 + lVar8) = unaff_XMM15_Qa;
  *(undefined8 *)(&stack0x0002a828 + lVar8) = unaff_XMM15_Qb;
  *(undefined8 *)(&stack0x0002a810 + lVar8) = unaff_XMM14_Qa;
  *(undefined8 *)(&stack0x0002a818 + lVar8) = unaff_XMM14_Qb;
  *(undefined8 *)(&stack0x0002a800 + lVar8) = unaff_XMM13_Qa;
  *(undefined8 *)(&stack0x0002a808 + lVar8) = unaff_XMM13_Qb;
  *(undefined8 *)(&stack0x0002a7f0 + lVar8) = unaff_XMM12_Qa;
  *(undefined8 *)(&stack0x0002a7f8 + lVar8) = unaff_XMM12_Qb;
  *(undefined8 *)(&stack0x0002a7e0 + lVar8) = unaff_XMM11_Qa;
  *(undefined8 *)(&stack0x0002a7e8 + lVar8) = unaff_XMM11_Qb;
  *(undefined8 *)(&stack0x0002a7d0 + lVar8) = unaff_XMM10_Qa;
  *(undefined8 *)(&stack0x0002a7d8 + lVar8) = unaff_XMM10_Qb;
  *(undefined8 *)(&stack0x0002a7c0 + lVar8) = unaff_XMM9_Qa;
  *(undefined8 *)(&stack0x0002a7c8 + lVar8) = unaff_XMM9_Qb;
  *(undefined8 *)(&stack0x0002a7b0 + lVar8) = unaff_XMM8_Qa;
  *(undefined8 *)(&stack0x0002a7b8 + lVar8) = unaff_XMM8_Qb;
  *(undefined8 *)(&stack0x0002a7a0 + lVar8) = unaff_XMM7_Qa;
  *(undefined8 *)(&stack0x0002a7a8 + lVar8) = unaff_XMM7_Qb;
  *(undefined8 *)(&stack0x0002a790 + lVar8) = unaff_XMM6_Qa;
  *(undefined8 *)(&stack0x0002a798 + lVar8) = unaff_XMM6_Qb;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000107e;
  pcVar23 = strstr(param_1,"\"nodes\":[");
  uVar22 = 0;
  if (pcVar23 != (char *)0x0) {
    *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000109b;
    pcVar23 = strchr(pcVar23,0x5b);
    uVar22 = 0;
    if (pcVar23 != (char *)0x0) {
      *(char **)(&stack0x0002a770 + lVar8) = param_1;
      puVar38 = &stack0x00014550 + lVar8;
      *(undefined8 *)(&stack0x0002a788 + lVar8) = 0;
      pcVar51 = &stack0x00000050 + lVar8;
      pcVar27 = &stack0x00029e50 + lVar8;
      while ((pcVar23[1] != '\0' && (pcVar23[1] != ']'))) {
        if (*(longlong *)(&stack0x0002a788 + lVar8) == 0xa0) {
          uVar22 = 0xa0;
          goto LAB_180001875;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001144;
        pcVar24 = strchr(pcVar23 + 1,0x7b);
        if (pcVar24 == (char *)0x0) break;
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000115d;
        pcVar23 = strchr(pcVar24,0x7d);
        if (pcVar23 == (char *)0x0) break;
        pcVar48 = pcVar23 + (1 - (longlong)pcVar24);
        if ((char *)0x3fe < pcVar48) {
          pcVar48 = (char *)0x3ff;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001191;
        FUN_180007c10((undefined8 *)pcVar51,(undefined8 *)pcVar24,(ulonglong)pcVar48);
        (&stack0x00000050)[(longlong)pcVar48 + lVar8] = 0;
        lVar29 = *(longlong *)(&stack0x0002a788 + lVar8) * 0x228 + lVar8;
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800011c8;
        FUN_180006c70(pcVar27,0x40,"\"%s\":\"",&DAT_18002a342);
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800011d3;
        pcVar24 = strstr(pcVar51,pcVar27);
        if (pcVar24 == (char *)0x0) {
          (&stack0x00014550)[lVar29] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800011e7;
          lVar25 = FUN_180006ce0((longlong)pcVar27);
          lVar26 = 1;
          for (pcVar24 = pcVar24 + lVar25; (cVar30 = *pcVar24, cVar30 != '\0' && (cVar30 != '\"'));
              pcVar24 = pcVar24 + 1) {
            pcVar48 = pcVar24;
            if (cVar30 == '\\') {
              pcVar48 = pcVar24 + 1;
              cVar30 = pcVar24[1];
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar48 = pcVar24;
              }
            }
            puVar38[lVar26 + -1] = cVar30;
            cVar30 = pcVar48[1];
            if ((cVar30 == '\0') || (cVar30 == '\"')) goto LAB_180001290;
            if (lVar26 == 0x3f) {
              lVar26 = 0x3f;
              goto LAB_180001290;
            }
            pcVar24 = pcVar48 + 1;
            if (cVar30 == '\\') {
              cVar30 = pcVar48[2];
              pcVar24 = pcVar48 + 2;
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar24 = pcVar48 + 1;
              }
            }
            puVar38[lVar26] = cVar30;
            lVar26 = lVar26 + 2;
          }
          lVar26 = lVar26 + -1;
LAB_180001290:
          (&stack0x00014550 + lVar29)[lVar26] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800012b0;
        FUN_180006c70(pcVar27,0x40,"\"%s\":\"",&DAT_18002a345);
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800012bb;
        pcVar24 = strstr(pcVar51,pcVar27);
        if (pcVar24 == (char *)0x0) {
          (&stack0x00014590)[lVar29] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800012cf;
          lVar25 = FUN_180006ce0((longlong)pcVar27);
          pcVar24 = pcVar24 + lVar25;
          lVar25 = 0;
          while( true ) {
            cVar30 = *pcVar24;
            if ((cVar30 == '\0') || (cVar30 == '\"')) goto LAB_180001370;
            pcVar48 = pcVar24;
            if (cVar30 == '\\') {
              pcVar48 = pcVar24 + 1;
              cVar30 = pcVar24[1];
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar48 = pcVar24;
              }
            }
            puVar38[lVar25 + 0x40] = cVar30;
            cVar30 = pcVar48[1];
            if ((cVar30 == '\0') || (cVar30 == '\"')) break;
            if (lVar25 == 0x1e) {
              lVar25 = 0x1f;
              goto LAB_180001370;
            }
            pcVar24 = pcVar48 + 1;
            if (cVar30 == '\\') {
              cVar30 = pcVar48[2];
              pcVar24 = pcVar48 + 2;
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar24 = pcVar48 + 1;
              }
            }
            pcVar24 = pcVar24 + 1;
            puVar38[lVar25 + 0x41] = cVar30;
            lVar25 = lVar25 + 2;
          }
          lVar25 = lVar25 + 1;
LAB_180001370:
          (&stack0x00014590)[lVar25 + lVar29] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001391;
        FUN_180006c70(pcVar27,0x40,"\"%s\":\"",&DAT_18002a34a);
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000139c;
        pcVar24 = strstr(pcVar51,pcVar27);
        if (pcVar24 == (char *)0x0) {
          (&stack0x000145b0)[lVar29] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800013b0;
          lVar25 = FUN_180006ce0((longlong)pcVar27);
          pcVar24 = pcVar24 + lVar25;
          lVar25 = 0;
          while( true ) {
            cVar30 = *pcVar24;
            if ((cVar30 == '\0') || (cVar30 == '\"')) goto LAB_180001450;
            pcVar48 = pcVar24;
            if (cVar30 == '\\') {
              pcVar48 = pcVar24 + 1;
              cVar30 = pcVar24[1];
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar48 = pcVar24;
              }
            }
            puVar38[lVar25 + 0x60] = cVar30;
            cVar30 = pcVar48[1];
            if ((cVar30 == '\0') || (cVar30 == '\"')) break;
            if (lVar25 == 0x3e) {
              lVar25 = 0x3f;
              goto LAB_180001450;
            }
            pcVar24 = pcVar48 + 1;
            if (cVar30 == '\\') {
              cVar30 = pcVar48[2];
              pcVar24 = pcVar48 + 2;
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar24 = pcVar48 + 1;
              }
            }
            pcVar24 = pcVar24 + 1;
            puVar38[lVar25 + 0x61] = cVar30;
            lVar25 = lVar25 + 2;
          }
          lVar25 = lVar25 + 1;
LAB_180001450:
          (&stack0x000145b0)[lVar25 + lVar29] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001471;
        FUN_180006c70(pcVar27,0x40,"\"%s\":\"","namespace");
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000147c;
        pcVar24 = strstr(pcVar51,pcVar27);
        if (pcVar24 == (char *)0x0) {
          (&stack0x000145f0)[lVar29] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001490;
          lVar25 = FUN_180006ce0((longlong)pcVar27);
          pcVar24 = pcVar24 + lVar25;
          lVar25 = 0;
          while( true ) {
            cVar30 = *pcVar24;
            if ((cVar30 == '\0') || (cVar30 == '\"')) goto LAB_180001530;
            pcVar48 = pcVar24;
            if (cVar30 == '\\') {
              pcVar48 = pcVar24 + 1;
              cVar30 = pcVar24[1];
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar48 = pcVar24;
              }
            }
            puVar38[lVar25 + 0xa0] = cVar30;
            cVar30 = pcVar48[1];
            if ((cVar30 == '\0') || (cVar30 == '\"')) break;
            if (lVar25 == 0x3e) {
              lVar25 = 0x3f;
              goto LAB_180001530;
            }
            pcVar24 = pcVar48 + 1;
            if (cVar30 == '\\') {
              cVar30 = pcVar48[2];
              pcVar24 = pcVar48 + 2;
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar24 = pcVar48 + 1;
              }
            }
            pcVar24 = pcVar24 + 1;
            puVar38[lVar25 + 0xa1] = cVar30;
            lVar25 = lVar25 + 2;
          }
          lVar25 = lVar25 + 1;
LAB_180001530:
          (&stack0x000145f0)[lVar25 + lVar29] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001554;
        FUN_180006c70(pcVar27,0x40,"\"%s\":\"","labels");
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000155f;
        pcVar24 = strstr(pcVar51,pcVar27);
        if (pcVar24 == (char *)0x0) {
          (&stack0x00014630)[lVar29] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001573;
          lVar25 = FUN_180006ce0((longlong)pcVar27);
          pcVar24 = pcVar24 + lVar25;
          lVar25 = 0;
          while( true ) {
            cVar30 = *pcVar24;
            if ((cVar30 == '\0') || (cVar30 == '\"')) goto LAB_180001610;
            pcVar48 = pcVar24;
            if (cVar30 == '\\') {
              pcVar48 = pcVar24 + 1;
              cVar30 = pcVar24[1];
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar48 = pcVar24;
              }
            }
            puVar38[lVar25 + 0xe0] = cVar30;
            cVar30 = pcVar48[1];
            if ((cVar30 == '\0') || (cVar30 == '\"')) break;
            if (lVar25 == 0x7e) {
              lVar25 = 0x7f;
              goto LAB_180001610;
            }
            pcVar24 = pcVar48 + 1;
            if (cVar30 == '\\') {
              cVar30 = pcVar48[2];
              pcVar24 = pcVar48 + 2;
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar24 = pcVar48 + 1;
              }
            }
            pcVar24 = pcVar24 + 1;
            puVar38[lVar25 + 0xe1] = cVar30;
            lVar25 = lVar25 + 2;
          }
          lVar25 = lVar25 + 1;
LAB_180001610:
          (&stack0x00014630)[lVar25 + lVar29] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001634;
        FUN_180006c70(pcVar27,0x40,"\"%s\":\"","selector");
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000163f;
        pcVar24 = strstr(pcVar51,pcVar27);
        if (pcVar24 == (char *)0x0) {
          (&stack0x000146b0)[lVar29] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001653;
          lVar25 = FUN_180006ce0((longlong)pcVar27);
          pcVar24 = pcVar24 + lVar25;
          lVar25 = 0;
          while( true ) {
            cVar30 = *pcVar24;
            if ((cVar30 == '\0') || (cVar30 == '\"')) goto LAB_1800016f0;
            pcVar48 = pcVar24;
            if (cVar30 == '\\') {
              pcVar48 = pcVar24 + 1;
              cVar30 = pcVar24[1];
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar48 = pcVar24;
              }
            }
            puVar38[lVar25 + 0x160] = cVar30;
            cVar30 = pcVar48[1];
            if ((cVar30 == '\0') || (cVar30 == '\"')) break;
            if (lVar25 == 0x7e) {
              lVar25 = 0x7f;
              goto LAB_1800016f0;
            }
            pcVar24 = pcVar48 + 1;
            if (cVar30 == '\\') {
              cVar30 = pcVar48[2];
              pcVar24 = pcVar48 + 2;
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar24 = pcVar48 + 1;
              }
            }
            pcVar24 = pcVar24 + 1;
            puVar38[lVar25 + 0x161] = cVar30;
            lVar25 = lVar25 + 2;
          }
          lVar25 = lVar25 + 1;
LAB_1800016f0:
          (&stack0x000146b0)[lVar25 + lVar29] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001714;
        FUN_180006c70(pcVar27,0x40,"\"%s\":\"","mount");
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000171f;
        pcVar24 = strstr(pcVar51,pcVar27);
        if (pcVar24 == (char *)0x0) {
          (&stack0x00014730)[lVar29] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001733;
          lVar25 = FUN_180006ce0((longlong)pcVar27);
          pcVar24 = pcVar24 + lVar25;
          lVar25 = 0;
          while( true ) {
            cVar30 = *pcVar24;
            if ((cVar30 == '\0') || (cVar30 == '\"')) goto LAB_1800017d0;
            pcVar48 = pcVar24;
            if (cVar30 == '\\') {
              pcVar48 = pcVar24 + 1;
              cVar30 = pcVar24[1];
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar48 = pcVar24;
              }
            }
            puVar38[lVar25 + 0x1e0] = cVar30;
            cVar30 = pcVar48[1];
            if ((cVar30 == '\0') || (cVar30 == '\"')) break;
            if (lVar25 == 0x3e) {
              lVar25 = 0x3f;
              goto LAB_1800017d0;
            }
            pcVar24 = pcVar48 + 1;
            if (cVar30 == '\\') {
              cVar30 = pcVar48[2];
              pcVar24 = pcVar48 + 2;
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar24 = pcVar48 + 1;
              }
            }
            pcVar24 = pcVar24 + 1;
            puVar38[lVar25 + 0x1e1] = cVar30;
            lVar25 = lVar25 + 2;
          }
          lVar25 = lVar25 + 1;
LAB_1800017d0:
          (&stack0x00014730)[lVar25 + lVar29] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800017f4;
        FUN_180006c70(pcVar27,0x40,"\"%s\":","replicas");
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800017ff;
        pcVar24 = strstr(pcVar51,pcVar27);
        if (pcVar24 == (char *)0x0) {
          iVar11 = 1;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000180f;
          lVar25 = FUN_180006ce0((longlong)pcVar27);
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000181a;
          iVar11 = atoi(pcVar24 + lVar25);
        }
        *(int *)(&stack0x00014770 + lVar29) = iVar11;
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001848;
        FUN_180006c70(pcVar27,0x40,"\"%s\":",&DAT_18002a378);
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001853;
        pcVar24 = strstr(pcVar51,pcVar27);
        if (pcVar24 == (char *)0x0) {
          iVar11 = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800010eb;
          lVar25 = FUN_180006ce0((longlong)pcVar27);
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800010f6;
          iVar11 = atoi(pcVar24 + lVar25);
        }
        *(int *)(&stack0x00014774 + lVar29) = iVar11;
        *(longlong *)(&stack0x0002a788 + lVar8) = *(longlong *)(&stack0x0002a788 + lVar8) + 1;
        puVar38 = puVar38 + 0x228;
      }
      uVar22 = *(ulonglong *)(&stack0x0002a788 + lVar8);
LAB_180001875:
      param_1 = *(char **)(&stack0x0002a770 + lVar8);
    }
  }
  uVar42 = 0;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000188e;
  pcVar23 = strstr(param_1,"\"edges\":[");
  *(ulonglong *)(&stack0x0002a788 + lVar8) = uVar22;
  if (pcVar23 != (char *)0x0) {
    *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800018ab;
    pcVar23 = strchr(pcVar23,0x5b);
    if (pcVar23 != (char *)0x0) {
      puVar38 = &stack0x00000050 + lVar8;
      *(undefined8 *)(&stack0x0002a750 + lVar8) = 0;
      pcVar51 = &stack0x0002a400 + lVar8;
      while ((pcVar23[1] != '\0' && (pcVar23[1] != ']'))) {
        if (*(longlong *)(&stack0x0002a750 + lVar8) == 0x140) {
          uVar42 = 0x140;
          goto LAB_180001d96;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001948;
        pcVar23 = strchr(pcVar23 + 1,0x7b);
        if (pcVar23 == (char *)0x0) break;
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001961;
        pcVar27 = strchr(pcVar23,0x7d);
        if (pcVar27 == (char *)0x0) break;
        *(char **)(&stack0x0002a770 + lVar8) = pcVar27;
        pcVar27 = pcVar27 + (1 - (longlong)pcVar23);
        if ((char *)0x2fe < pcVar27) {
          pcVar27 = (char *)0x2ff;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800019a0;
        FUN_180007c10((undefined8 *)(&stack0x00029e50 + lVar8),(undefined8 *)pcVar23,
                      (ulonglong)pcVar27);
        (&stack0x00029e50)[(longlong)pcVar27 + lVar8] = 0;
        lVar29 = *(longlong *)(&stack0x0002a750 + lVar8) * 0x104 + lVar8;
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800019dd;
        FUN_180006c70(pcVar51,0x40,"\"%s\":\"","source_id");
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800019e8;
        pcVar23 = strstr(&stack0x00029e50 + lVar8,pcVar51);
        if (pcVar23 == (char *)0x0) {
          (&stack0x00000050)[lVar29] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800019fc;
          lVar25 = FUN_180006ce0((longlong)pcVar51);
          lVar26 = 1;
          for (pcVar23 = pcVar23 + lVar25; (cVar30 = *pcVar23, cVar30 != '\0' && (cVar30 != '\"'));
              pcVar23 = pcVar23 + 1) {
            pcVar27 = pcVar23;
            if (cVar30 == '\\') {
              pcVar27 = pcVar23 + 1;
              cVar30 = pcVar23[1];
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar27 = pcVar23;
              }
            }
            puVar38[lVar26 + -1] = cVar30;
            cVar30 = pcVar27[1];
            if ((cVar30 == '\0') || (cVar30 == '\"')) goto LAB_180001aa0;
            if (lVar26 == 0x3f) {
              lVar26 = 0x3f;
              goto LAB_180001aa0;
            }
            pcVar23 = pcVar27 + 1;
            if (cVar30 == '\\') {
              cVar30 = pcVar27[2];
              pcVar23 = pcVar27 + 2;
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar23 = pcVar27 + 1;
              }
            }
            puVar38[lVar26] = cVar30;
            lVar26 = lVar26 + 2;
          }
          lVar26 = lVar26 + -1;
LAB_180001aa0:
          (&stack0x00000050 + lVar29)[lVar26] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001abc;
        FUN_180006c70(pcVar51,0x40,"\"%s\":\"","target_id");
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001acb;
        pcVar23 = strstr(&stack0x00029e50 + lVar8,pcVar51);
        if (pcVar23 == (char *)0x0) {
          (&stack0x00000090)[lVar29] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001adf;
          lVar25 = FUN_180006ce0((longlong)pcVar51);
          lVar26 = 1;
          for (pcVar23 = pcVar23 + lVar25; (cVar30 = *pcVar23, cVar30 != '\0' && (cVar30 != '\"'));
              pcVar23 = pcVar23 + 1) {
            pcVar27 = pcVar23;
            if (cVar30 == '\\') {
              pcVar27 = pcVar23 + 1;
              cVar30 = pcVar23[1];
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar27 = pcVar23;
              }
            }
            puVar38[lVar26 + 0x3f] = cVar30;
            cVar30 = pcVar27[1];
            if ((cVar30 == '\0') || (cVar30 == '\"')) goto LAB_180001b80;
            if (lVar26 == 0x3f) {
              lVar26 = 0x3f;
              goto LAB_180001b80;
            }
            pcVar23 = pcVar27 + 1;
            if (cVar30 == '\\') {
              cVar30 = pcVar27[2];
              pcVar23 = pcVar27 + 2;
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar23 = pcVar27 + 1;
              }
            }
            puVar38[lVar26 + 0x40] = cVar30;
            lVar26 = lVar26 + 2;
          }
          lVar26 = lVar26 + -1;
LAB_180001b80:
          (&stack0x00000090)[lVar26 + lVar29] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001b9d;
        FUN_180006c70(pcVar51,0x40,"\"%s\":\"","binding");
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001bac;
        pcVar23 = strstr(&stack0x00029e50 + lVar8,pcVar51);
        if (pcVar23 == (char *)0x0) {
          (&stack0x000000d0)[lVar29] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001bc0;
          lVar25 = FUN_180006ce0((longlong)pcVar51);
          pcVar23 = pcVar23 + lVar25;
          lVar25 = 0;
          while( true ) {
            cVar30 = *pcVar23;
            if ((cVar30 == '\0') || (cVar30 == '\"')) goto LAB_180001c60;
            pcVar27 = pcVar23;
            if (cVar30 == '\\') {
              pcVar27 = pcVar23 + 1;
              cVar30 = pcVar23[1];
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar27 = pcVar23;
              }
            }
            puVar38[lVar25 + 0x80] = cVar30;
            cVar30 = pcVar27[1];
            if ((cVar30 == '\0') || (cVar30 == '\"')) break;
            if (lVar25 == 0x3e) {
              lVar25 = 0x3f;
              goto LAB_180001c60;
            }
            pcVar23 = pcVar27 + 1;
            if (cVar30 == '\\') {
              cVar30 = pcVar27[2];
              pcVar23 = pcVar27 + 2;
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar23 = pcVar27 + 1;
              }
            }
            pcVar23 = pcVar23 + 1;
            puVar38[lVar25 + 0x81] = cVar30;
            lVar25 = lVar25 + 2;
          }
          lVar25 = lVar25 + 1;
LAB_180001c60:
          (&stack0x000000d0)[lVar25 + lVar29] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001c80;
        FUN_180006c70(pcVar51,0x40,"\"%s\":\"",&DAT_18002a3b0);
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001c8f;
        pcVar23 = strstr(&stack0x00029e50 + lVar8,pcVar51);
        if (pcVar23 == (char *)0x0) {
          (&stack0x00000110)[lVar29] = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001ca3;
          lVar25 = FUN_180006ce0((longlong)pcVar51);
          pcVar23 = pcVar23 + lVar25;
          lVar25 = 0;
          while( true ) {
            cVar30 = *pcVar23;
            if ((cVar30 == '\0') || (cVar30 == '\"')) goto LAB_180001d40;
            pcVar27 = pcVar23;
            if (cVar30 == '\\') {
              pcVar27 = pcVar23 + 1;
              cVar30 = pcVar23[1];
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar27 = pcVar23;
              }
            }
            puVar38[lVar25 + 0xc0] = cVar30;
            cVar30 = pcVar27[1];
            if ((cVar30 == '\0') || (cVar30 == '\"')) break;
            if (lVar25 == 0x3e) {
              lVar25 = 0x3f;
              goto LAB_180001d40;
            }
            pcVar23 = pcVar27 + 1;
            if (cVar30 == '\\') {
              cVar30 = pcVar27[2];
              pcVar23 = pcVar27 + 2;
              if (cVar30 == '\0') {
                cVar30 = '\\';
                pcVar23 = pcVar27 + 1;
              }
            }
            pcVar23 = pcVar23 + 1;
            puVar38[lVar25 + 0xc1] = cVar30;
            lVar25 = lVar25 + 2;
          }
          lVar25 = lVar25 + 1;
LAB_180001d40:
          (&stack0x00000110)[lVar25 + lVar29] = 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001d64;
        FUN_180006c70(pcVar51,0x40,"\"%s\":",&DAT_18002a378);
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001d73;
        pcVar23 = strstr(&stack0x00029e50 + lVar8,pcVar51);
        if (pcVar23 == (char *)0x0) {
          iVar11 = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800018eb;
          lVar25 = FUN_180006ce0((longlong)pcVar51);
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800018f6;
          iVar11 = atoi(pcVar23 + lVar25);
        }
        pcVar23 = *(char **)(&stack0x0002a770 + lVar8);
        *(int *)(&stack0x00000150 + lVar29) = iVar11;
        *(longlong *)(&stack0x0002a750 + lVar8) = *(longlong *)(&stack0x0002a750 + lVar8) + 1;
        puVar38 = puVar38 + 0x104;
      }
      uVar42 = *(ulonglong *)(&stack0x0002a750 + lVar8);
LAB_180001d96:
      uVar22 = *(ulonglong *)(&stack0x0002a788 + lVar8);
    }
  }
  *(ulonglong *)(&stack0x0002a778 + lVar8) = uVar22 & 0xffffffff;
  *(ulonglong *)(&stack0x0002a750 + lVar8) = uVar42;
  if ((int)uVar22 < 1) {
    sVar36 = (size_t)(int)uVar22;
  }
  else {
    pbVar59 = &stack0x00014591 + lVar8;
    pbVar49 = &stack0x000145b1 + lVar8;
    *(undefined1 **)(&stack0x0002a738 + lVar8) = &stack0x000145f1 + lVar8;
    *(undefined1 **)(&stack0x0002a740 + lVar8) = &stack0x00014631 + lVar8;
    *(undefined1 **)(&stack0x0002a730 + lVar8) = &stack0x000146b1 + lVar8;
    *(undefined1 **)(&stack0x0002a728 + lVar8) = &stack0x00014731 + lVar8;
    lVar29 = 0;
    do {
      *(longlong *)(&stack0x0002a768 + lVar8) = lVar29;
      lVar29 = lVar29 * 0x228;
      bVar10 = (&stack0x00014590)[lVar29 + lVar8];
      *(byte **)(&stack0x0002a780 + lVar8) = pbVar59;
      if (bVar10 == 0) {
        *(undefined4 *)(&stack0x0002a758 + lVar8) = 0x5bf44983;
      }
      else {
        *(longlong *)(&stack0x0002a770 + lVar8) = lVar29;
        uVar56 = 0x811c9dc5;
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001f18;
          uVar12 = tolower((uint)bVar10);
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001f1e;
          iVar11 = isalnum((int)bVar10);
          uVar31 = (uVar12 & 0xff ^ uVar56) * 0x1000193;
          if ((uVar12 & 0xff) == 0x5f) {
            uVar56 = uVar31;
          }
          if ((uVar12 & 0xef) == 0x2d) {
            uVar56 = uVar31;
          }
          if (iVar11 != 0) {
            uVar56 = uVar31;
          }
          bVar10 = *pbVar59;
          pbVar59 = pbVar59 + 1;
        } while (bVar10 != 0);
        *(uint *)(&stack0x0002a758 + lVar8) = (uVar56 & 0x7fffffff) * 0x4e67c6a7;
        lVar29 = *(longlong *)(&stack0x0002a770 + lVar8);
      }
      *(undefined1 **)(&stack0x0002a770 + lVar8) = &stack0x00014550 + lVar29 + lVar8;
      bVar10 = (&stack0x000145b0)[lVar29 + lVar8];
      if (bVar10 == 0) {
        uVar56 = 0x11c9dc5;
      }
      else {
        uVar56 = 0x811c9dc5;
        pbVar59 = pbVar49;
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001fc8;
          uVar12 = tolower((uint)bVar10);
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001fcf;
          iVar11 = isalnum((int)bVar10);
          uVar31 = (uVar12 & 0xff ^ uVar56) * 0x1000193;
          if ((uVar12 & 0xff) == 0x5f) {
            uVar56 = uVar31;
          }
          if ((uVar12 & 0xef) == 0x2d) {
            uVar56 = uVar31;
          }
          if (iVar11 != 0) {
            uVar56 = uVar31;
          }
          bVar10 = *pbVar59;
          pbVar59 = pbVar59 + 1;
        } while (bVar10 != 0);
        uVar56 = uVar56 & 0x7fffffff;
      }
      *(byte **)(&stack0x0002a760 + lVar8) = pbVar49;
      bVar10 = *(byte *)(*(longlong *)(&stack0x0002a770 + lVar8) + 0xa0);
      if (bVar10 == 0) {
        uVar12 = 0x2393b8a;
      }
      else {
        uVar12 = 0x811c9dc5;
        pbVar59 = *(byte **)(&stack0x0002a738 + lVar8);
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002048;
          uVar31 = tolower((uint)bVar10);
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000204f;
          iVar11 = isalnum((int)bVar10);
          uVar32 = (uVar31 & 0xff ^ uVar12) * 0x1000193;
          if ((uVar31 & 0xff) == 0x5f) {
            uVar12 = uVar32;
          }
          if ((uVar31 & 0xef) == 0x2d) {
            uVar12 = uVar32;
          }
          if (iVar11 != 0) {
            uVar12 = uVar32;
          }
          bVar10 = *pbVar59;
          pbVar59 = pbVar59 + 1;
        } while (bVar10 != 0);
        uVar12 = uVar12 * 2;
      }
      *(uint *)(&stack0x0002a748 + lVar8) = uVar56;
      bVar10 = *(byte *)(*(longlong *)(&stack0x0002a770 + lVar8) + 0xe0);
      if (bVar10 == 0) {
        uVar56 = 0x4727714;
      }
      else {
        uVar56 = 0x811c9dc5;
        pbVar59 = *(byte **)(&stack0x0002a740 + lVar8);
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800020d8;
          uVar31 = tolower((uint)bVar10);
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800020df;
          iVar11 = isalnum((int)bVar10);
          uVar32 = (uVar31 & 0xff ^ uVar56) * 0x1000193;
          if ((uVar31 & 0xff) == 0x5f) {
            uVar56 = uVar32;
          }
          if ((uVar31 & 0xef) == 0x2d) {
            uVar56 = uVar32;
          }
          if (iVar11 != 0) {
            uVar56 = uVar32;
          }
          bVar10 = *pbVar59;
          pbVar59 = pbVar59 + 1;
        } while (bVar10 != 0);
        uVar56 = uVar56 << 2;
      }
      bVar10 = *(byte *)(*(longlong *)(&stack0x0002a770 + lVar8) + 0x160);
      if (bVar10 == 0) {
        uVar31 = 0x8e4ee28;
      }
      else {
        uVar31 = 0x811c9dc5;
        pbVar59 = *(byte **)(&stack0x0002a730 + lVar8);
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000215b;
          uVar32 = tolower((uint)bVar10);
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002162;
          iVar11 = isalnum((uint)bVar10);
          uVar33 = (uVar32 & 0xff ^ uVar31) * 0x1000193;
          if ((uVar32 & 0xff) == 0x5f) {
            uVar31 = uVar33;
          }
          if ((uVar32 & 0xef) == 0x2d) {
            uVar31 = uVar33;
          }
          if (iVar11 != 0) {
            uVar31 = uVar33;
          }
          bVar10 = *pbVar59;
          pbVar59 = pbVar59 + 1;
        } while (bVar10 != 0);
        uVar31 = uVar31 << 3;
      }
      pcVar23 = (char *)(*(longlong *)(&stack0x0002a770 + lVar8) + 0xe0);
      bVar10 = *(byte *)(*(longlong *)(&stack0x0002a770 + lVar8) + 0x1e0);
      if (bVar10 == 0) {
        uVar32 = 0x11c9dc50;
      }
      else {
        *(char **)(&stack0x0002a700 + lVar8) = pcVar23;
        uVar32 = 0x811c9dc5;
        pbVar59 = *(byte **)(&stack0x0002a728 + lVar8);
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800021eb;
          uVar33 = tolower((uint)bVar10);
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800021f6;
          iVar11 = isalnum((uint)bVar10);
          uVar34 = (uVar33 & 0xff ^ uVar32) * 0x1000193;
          if ((uVar33 & 0xff) == 0x5f) {
            uVar32 = uVar34;
          }
          if ((uVar33 & 0xef) == 0x2d) {
            uVar32 = uVar34;
          }
          if (iVar11 != 0) {
            uVar32 = uVar34;
          }
          bVar10 = *pbVar59;
          pbVar59 = pbVar59 + 1;
        } while (bVar10 != 0);
        uVar32 = uVar32 << 4;
        pcVar23 = *(char **)(&stack0x0002a700 + lVar8);
      }
      *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180001e1a;
      FUN_1800056a0(pcVar23);
      lVar29 = *(longlong *)(&stack0x0002a768 + lVar8);
      *(uint *)(&stack0x0002a400 + lVar29 * 4 + lVar8) =
           (*(int *)(*(longlong *)(&stack0x0002a770 + lVar8) + 0x224) << 6 ^
            *(int *)(*(longlong *)(&stack0x0002a770 + lVar8) + 0x220) << 5 ^
            uVar56 ^ uVar31 ^ uVar12 ^ *(uint *)(&stack0x0002a758 + lVar8) ^ uVar32) & 0x7fffffff ^
           *(uint *)(&stack0x0002a748 + lVar8);
      lVar29 = lVar29 + 1;
      pbVar59 = (byte *)(*(longlong *)(&stack0x0002a780 + lVar8) + 0x228);
      pbVar49 = (byte *)(*(longlong *)(&stack0x0002a760 + lVar8) + 0x228);
      *(longlong *)(&stack0x0002a738 + lVar8) = *(longlong *)(&stack0x0002a738 + lVar8) + 0x228;
      *(longlong *)(&stack0x0002a740 + lVar8) = *(longlong *)(&stack0x0002a740 + lVar8) + 0x228;
      *(longlong *)(&stack0x0002a730 + lVar8) = *(longlong *)(&stack0x0002a730 + lVar8) + 0x228;
      *(longlong *)(&stack0x0002a728 + lVar8) = *(longlong *)(&stack0x0002a728 + lVar8) + 0x228;
      uVar22 = *(ulonglong *)(&stack0x0002a788 + lVar8);
    } while (lVar29 != *(longlong *)(&stack0x0002a778 + lVar8));
    sVar36 = *(size_t *)(&stack0x0002a778 + lVar8);
    uVar42 = *(ulonglong *)(&stack0x0002a750 + lVar8);
  }
  uVar12 = (uint)uVar22;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002267;
  qsort(&stack0x0002a400 + lVar8,sVar36,4,FUN_180005880);
  uVar56 = (uint)uVar42;
  *(ulonglong *)(&stack0x0002a770 + lVar8) = uVar42 & 0xffffffff;
  if ((int)uVar56 < 1) {
    sVar36 = (size_t)(int)uVar56;
  }
  else {
    *(undefined1 **)(&stack0x0002a780 + lVar8) = &stack0x000000d1 + lVar8;
    *(undefined1 **)(&stack0x0002a760 + lVar8) = &stack0x00000111 + lVar8;
    lVar29 = 0;
    do {
      if (0 < (int)uVar22) {
        lVar26 = lVar29 * 0x104 + lVar8;
        pcVar23 = &stack0x00014550 + lVar8;
        lVar25 = *(longlong *)(&stack0x0002a778 + lVar8);
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000231b;
          iVar11 = strcmp(pcVar23,&stack0x00000050 + lVar26);
          if (iVar11 == 0) goto LAB_18000232f;
          pcVar23 = pcVar23 + 0x228;
          lVar25 = lVar25 + -1;
        } while (lVar25 != 0);
        pcVar23 = (char *)0x0;
LAB_18000232f:
        *(undefined1 **)(&stack0x0002a768 + lVar8) = &stack0x00000050 + lVar26;
        pbVar59 = &stack0x000145b1 + lVar8;
        pbVar49 = &stack0x00014591 + lVar8;
        pcVar51 = &stack0x00014550 + lVar8;
        lVar25 = *(longlong *)(&stack0x0002a778 + lVar8);
LAB_180002360:
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000236b;
        iVar11 = strcmp(pcVar51,&stack0x00000090 + lVar26);
        if (iVar11 != 0) goto code_r0x00018000236f;
        if (pcVar23 != (char *)0x0) {
          *(longlong *)(&stack0x0002a740 + lVar8) = lVar29;
          bVar10 = pcVar23[0x40];
          *(char **)(&stack0x0002a758 + lVar8) = pcVar51;
          if (bVar10 == 0) {
            uVar42 = 0x11c9dc5;
            uVar22 = *(ulonglong *)(&stack0x0002a788 + lVar8);
          }
          else {
            pbVar39 = (byte *)(pcVar23 + 0x41);
            uVar56 = 0x811c9dc5;
            do {
              *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800023ce;
              uVar12 = tolower((uint)bVar10);
              *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800023d9;
              iVar11 = isalnum((uint)bVar10);
              uVar31 = (uVar12 & 0xff ^ uVar56) * 0x1000193;
              if ((uVar12 & 0xff) == 0x5f) {
                uVar56 = uVar31;
              }
              if ((uVar12 & 0xef) == 0x2d) {
                uVar56 = uVar31;
              }
              if (iVar11 != 0) {
                uVar56 = uVar31;
              }
              bVar10 = *pbVar39;
              pbVar39 = pbVar39 + 1;
            } while (bVar10 != 0);
            uVar42 = (ulonglong)(uVar56 & 0x7fffffff);
            uVar22 = *(ulonglong *)(&stack0x0002a788 + lVar8);
            pcVar51 = *(char **)(&stack0x0002a758 + lVar8);
          }
          bVar10 = pcVar23[0x60];
          *(ulonglong *)(&stack0x0002a748 + lVar8) = uVar42;
          if (bVar10 == 0) {
            *(undefined4 *)(&stack0x0002a738 + lVar8) = 0x4727714;
          }
          else {
            pbVar39 = (byte *)(pcVar23 + 0x61);
            uVar56 = 0x811c9dc5;
            do {
              *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000247b;
              uVar12 = tolower((uint)bVar10);
              *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002483;
              iVar11 = isalnum((uint)bVar10);
              uVar31 = (uVar12 & 0xff ^ uVar56) * 0x1000193;
              if ((uVar12 & 0xff) == 0x5f) {
                uVar56 = uVar31;
              }
              if ((uVar12 & 0xef) == 0x2d) {
                uVar56 = uVar31;
              }
              if (iVar11 != 0) {
                uVar56 = uVar31;
              }
              bVar10 = *pbVar39;
              pbVar39 = pbVar39 + 1;
            } while (bVar10 != 0);
            *(uint *)(&stack0x0002a738 + lVar8) = uVar56 << 2;
            uVar22 = *(ulonglong *)(&stack0x0002a788 + lVar8);
            pcVar51 = *(char **)(&stack0x0002a758 + lVar8);
            uVar42 = *(ulonglong *)(&stack0x0002a748 + lVar8);
          }
          iVar11 = (int)uVar42;
          bVar10 = pcVar51[0x40];
          if (bVar10 == 0) {
            uVar56 = 0x11c9dc5;
          }
          else {
            uVar56 = 0x811c9dc5;
            do {
              *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002507;
              uVar12 = tolower((int)bVar10);
              *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000250f;
              iVar11 = isalnum((uint)bVar10);
              uVar31 = (uVar12 & 0xff ^ uVar56) * 0x1000193;
              if ((uVar12 & 0xff) == 0x5f) {
                uVar56 = uVar31;
              }
              if ((uVar12 & 0xef) == 0x2d) {
                uVar56 = uVar31;
              }
              if (iVar11 != 0) {
                uVar56 = uVar31;
              }
              bVar10 = *pbVar49;
              pbVar49 = pbVar49 + 1;
            } while (bVar10 != 0);
            uVar56 = uVar56 & 0x7fffffff;
            uVar22 = *(ulonglong *)(&stack0x0002a788 + lVar8);
            pcVar51 = *(char **)(&stack0x0002a758 + lVar8);
            iVar11 = (int)*(undefined8 *)(&stack0x0002a748 + lVar8);
          }
          bVar10 = pcVar51[0x60];
          if (bVar10 == 0) {
            uVar12 = 0x11c9dc50;
          }
          else {
            uVar12 = 0x811c9dc5;
            do {
              *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002587;
              uVar31 = tolower((int)bVar10);
              *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000258f;
              iVar11 = isalnum((uint)bVar10);
              uVar32 = (uVar31 & 0xff ^ uVar12) * 0x1000193;
              if ((uVar31 & 0xff) == 0x5f) {
                uVar12 = uVar32;
              }
              if ((uVar31 & 0xef) == 0x2d) {
                uVar12 = uVar32;
              }
              if (iVar11 != 0) {
                uVar12 = uVar32;
              }
              bVar10 = *pbVar59;
              pbVar59 = pbVar59 + 1;
            } while (bVar10 != 0);
            uVar12 = uVar12 << 4;
            uVar22 = *(ulonglong *)(&stack0x0002a788 + lVar8);
            iVar11 = (int)*(undefined8 *)(&stack0x0002a748 + lVar8);
          }
          lVar29 = *(longlong *)(&stack0x0002a768 + lVar8);
          bVar10 = *(byte *)(lVar29 + 0x80);
          if (bVar10 == 0) {
            uVar31 = 0x2393b8a0;
          }
          else {
            uVar31 = 0x811c9dc5;
            pbVar59 = *(byte **)(&stack0x0002a780 + lVar8);
            do {
              *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000261b;
              uVar32 = tolower((uint)bVar10);
              *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002623;
              iVar11 = isalnum((uint)bVar10);
              uVar33 = (uVar32 & 0xff ^ uVar31) * 0x1000193;
              if ((uVar32 & 0xff) == 0x5f) {
                uVar31 = uVar33;
              }
              if ((uVar32 & 0xef) == 0x2d) {
                uVar31 = uVar33;
              }
              if (iVar11 != 0) {
                uVar31 = uVar33;
              }
              bVar10 = *pbVar59;
              pbVar59 = pbVar59 + 1;
            } while (bVar10 != 0);
            uVar31 = uVar31 << 5;
            uVar22 = *(ulonglong *)(&stack0x0002a788 + lVar8);
            lVar29 = *(longlong *)(&stack0x0002a768 + lVar8);
            iVar11 = (int)*(undefined8 *)(&stack0x0002a748 + lVar8);
          }
          bVar10 = *(byte *)(lVar29 + 0xc0);
          if (bVar10 == 0) {
            uVar32 = 0x47277140;
          }
          else {
            uVar32 = 0x811c9dc5;
            pbVar59 = *(byte **)(&stack0x0002a760 + lVar8);
            do {
              *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000269b;
              uVar33 = tolower((uint)bVar10);
              *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800026a6;
              iVar11 = isalnum((uint)bVar10);
              uVar34 = (uVar33 & 0xff ^ uVar32) * 0x1000193;
              if ((uVar33 & 0xff) == 0x5f) {
                uVar32 = uVar34;
              }
              if ((uVar33 & 0xef) == 0x2d) {
                uVar32 = uVar34;
              }
              if (iVar11 != 0) {
                uVar32 = uVar34;
              }
              bVar10 = *pbVar59;
              pbVar59 = pbVar59 + 1;
            } while (bVar10 != 0);
            uVar32 = uVar32 << 6;
            uVar22 = *(ulonglong *)(&stack0x0002a788 + lVar8);
            iVar11 = (int)*(undefined8 *)(&stack0x0002a748 + lVar8);
          }
          lVar29 = *(longlong *)(&stack0x0002a740 + lVar8);
          *(uint *)(&stack0x00029e50 + lVar29 * 4 + lVar8) =
               (*(int *)(*(longlong *)(&stack0x0002a768 + lVar8) + 0x100) << 7 ^
                uVar56 * 8 ^ uVar12 ^ *(uint *)(&stack0x0002a738 + lVar8) ^ iVar11 * 2 ^ uVar31 ^
               uVar32) & 0x7fffffff;
          if ((iVar11 == 0x56dfde64) && (uVar56 == 0x45334cec)) {
            *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002767;
            FUN_1800056a0((char *)(*(longlong *)(&stack0x0002a758 + lVar8) + 0xe0));
          }
          goto LAB_1800022b6;
        }
      }
LAB_1800022a0:
      *(undefined4 *)(&stack0x00029e50 + lVar29 * 4 + lVar8) = 0;
      uVar22 = *(ulonglong *)(&stack0x0002a788 + lVar8);
LAB_1800022b6:
      uVar12 = (uint)uVar22;
      lVar29 = lVar29 + 1;
      *(longlong *)(&stack0x0002a780 + lVar8) = *(longlong *)(&stack0x0002a780 + lVar8) + 0x104;
      *(longlong *)(&stack0x0002a760 + lVar8) = *(longlong *)(&stack0x0002a760 + lVar8) + 0x104;
    } while (lVar29 != *(longlong *)(&stack0x0002a770 + lVar8));
    sVar36 = *(size_t *)(&stack0x0002a770 + lVar8);
    uVar56 = (uint)*(undefined8 *)(&stack0x0002a750 + lVar8);
  }
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000279e;
  qsort(&stack0x00029e50 + lVar8,sVar36,4,FUN_180005880);
  pcVar23 = &stack0x00014550 + lVar8;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800027bc;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x6369e029,0x2047d5a7);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800027d3;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x6369e029,0x251b4cfe);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800027ea;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x6369e029,0x133c1bd8);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002801;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x6369e029,0x45334cec);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002818;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x6369e029,0x667c6911);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000282f;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x6369e029,0x56dfde64);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002846;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x7c3044e6,0x2047d5a7);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000285d;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x7c3044e6,0x251b4cfe);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002874;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x7c3044e6,0x133c1bd8);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000288b;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x7c3044e6,0x45334cec);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800028a2;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x7c3044e6,0x667c6911);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800028b9;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x7c3044e6,0x56dfde64);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800028d0;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x8bb40c5,0x2047d5a7);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800028e7;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x8bb40c5,0x251b4cfe);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800028fe;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x8bb40c5,0x133c1bd8);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002915;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x8bb40c5,0x45334cec);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000292c;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x8bb40c5,0x667c6911);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002943;
  FUN_1800058a0((longlong)pcVar23,uVar12,0x8bb40c5,0x56dfde64);
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x56dfde64;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x4af021b;
  puVar38 = &stack0x00000050 + lVar8;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002968;
  iVar11 = FUN_180005a70(pcVar23,uVar12,(longlong)puVar38,uVar56,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8));
  *(ulonglong *)(&stack0x0002a740 + lVar8) = CONCAT44(extraout_var,iVar11);
  uVar31 = iVar11 + 0x3b54aU ^ 0xbaeb1811;
  uVar32 = (uVar31 << 7 | uVar31 >> 0x19) * -0x61c8864f + 0x3165b;
  *(uint *)(&stack0x0002a760 + lVar8) = uVar32;
  uVar32 = uVar32 & 0x7fffffff;
  *(uint *)(&stack0x0002a400 + lVar8) = uVar32;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x251b4cfe;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x9bdb79f;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800029c1;
  iVar11 = FUN_180005a70(pcVar23,uVar12,(longlong)puVar38,uVar56,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8));
  *(ulonglong *)(&stack0x0002a708 + lVar8) = CONCAT44(extraout_var_00,iVar11);
  uVar31 = iVar11 + 0x3b54aU ^ 0x38399c13;
  uVar31 = (uVar31 << 7 | uVar31 >> 0x19) * 0x1e3779b1 + 0x3165b & 0x7fffffff;
  *(ulonglong *)(&stack0x0002a748 + lVar8) = (ulonglong)uVar31;
  *(uint *)(&stack0x0002a404 + lVar8) = uVar31;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x56dfde64;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x6994bce3;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002a13;
  iVar11 = FUN_180005a70(pcVar23,uVar12,(longlong)puVar38,uVar56,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8));
  *(ulonglong *)(&stack0x0002a738 + lVar8) = CONCAT44(extraout_var_01,iVar11);
  uVar31 = iVar11 + 0x3b54aU ^ 0x49818ea;
  uVar31 = (uVar31 << 7 | uVar31 >> 0x19) * 0x1e3779b1 + 0x3165b & 0x7fffffff;
  *(ulonglong *)(&stack0x0002a758 + lVar8) = (ulonglong)uVar31;
  *(uint *)(&stack0x0002a408 + lVar8) = uVar31;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x56dfde64;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x5e098a07;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002a67;
  iVar11 = FUN_180005a70(pcVar23,uVar12,(longlong)puVar38,uVar56,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8));
  *(ulonglong *)(&stack0x0002a730 + lVar8) = CONCAT44(extraout_var_02,iVar11);
  uVar31 = iVar11 + 0x31713U ^ 0x45ae65cf;
  uVar31 = (uVar31 << 6 | uVar31 >> 0x1a) * 0x1e3779b1 + 0x315fa & 0x7fffffff;
  *(ulonglong *)(&stack0x0002a780 + lVar8) = (ulonglong)uVar31;
  *(uint *)(&stack0x0002a40c + lVar8) = uVar31;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x31c14e0d;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x23f97dbd;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002abe;
  uVar31 = FUN_180005a70(pcVar23,uVar12,(longlong)puVar38,uVar56,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8));
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x31c14e0d;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x20f97904;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002ae1;
  uVar56 = FUN_180005a70(pcVar23,uVar12,(longlong)puVar38,uVar56,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8));
  *(ulonglong *)(&stack0x0002a718 + lVar8) = (ulonglong)uVar31;
  uVar31 = uVar31 + 0x13c6e ^ 0xf579efe6;
  uVar31 = (uVar31 << 3 | uVar31 >> 0x1d) * -0x61c8864f + 0x314d7 ^ 0x20fb53a9;
  *(ulonglong *)(&stack0x0002a720 + lVar8) = (ulonglong)uVar56;
  uVar56 = uVar56 + 0x278dc ^ (uVar31 << 4 | uVar31 >> 0x1c) * -0x61c8864f + 0x31538;
  uVar56 = (uVar56 << 5 | uVar56 >> 0x1b) * -0x61c8864f + 0x31599 ^ 0x554bd1c0;
  uVar56 = (uVar56 << 6 | uVar56 >> 0x1a) * -0x61c8864f + 0x315fa ^ 0x524c6b3e;
  uVar53 = (uVar56 << 7 | uVar56 >> 0x19) * 0x1e3779b1 + 0x3165b;
  uVar54 = uVar53 & 0x7fffffff;
  *(uint *)(&stack0x0002a410 + lVar8) = uVar54;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002b81;
  uVar56 = FUN_1800058a0((longlong)pcVar23,uVar12,0x8bb40c5,0x45334cec);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002b9a;
  uVar31 = FUN_1800058a0((longlong)pcVar23,uVar12,0x8bb40c5,0x56dfde64);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002bb3;
  uVar33 = FUN_1800058a0((longlong)pcVar23,uVar12,0x8bb40c5,0x667c6911);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002bcd;
  iVar11 = FUN_1800058a0((longlong)pcVar23,uVar12,0x8bb40c5,0x251b4cfe);
  *(ulonglong *)(&stack0x0002a710 + lVar8) = (ulonglong)uVar56;
  uVar56 = uVar56 + 0x13c6e ^ 0xfc57e5c6;
  *(ulonglong *)(&stack0x0002a680 + lVar8) = (ulonglong)uVar31;
  uVar56 = uVar31 + 0x1daa5 ^ (uVar56 << 3 | uVar56 >> 0x1d) * -0x61c8864f + 0x314d7;
  *(ulonglong *)(&stack0x0002a660 + lVar8) = (ulonglong)uVar33;
  uVar56 = uVar33 + 0x278dc ^ (uVar56 << 4 | uVar56 >> 0x1c) * -0x61c8864f + 0x31538;
  *(ulonglong *)(&stack0x0002a670 + lVar8) = CONCAT44(extraout_var_03,iVar11);
  uVar56 = iVar11 + 0x31713U ^ (uVar56 << 5 | uVar56 >> 0x1b) * -0x61c8864f + 0x31599;
  uVar57 = (uVar56 << 6 | uVar56 >> 0x1a) * 0x1e3779b1 + 0x315fa & 0x7fffffff;
  *(uint *)(&stack0x0002a414 + lVar8) = uVar57;
  *(undefined4 *)(&stack0x0002a418 + lVar8) = 0x2a87820d;
  uVar56 = (int)*(undefined8 *)(&stack0x0002a740 + lVar8) + 0x278dcU ^ 0x2d6c918a;
  uVar56 = (int)*(undefined8 *)(&stack0x0002a738 + lVar8) + 0x31713U ^
           (uVar56 << 5 | uVar56 >> 0x1b) * -0x61c8864f + 0x31599;
  uVar56 = (int)*(undefined8 *)(&stack0x0002a730 + lVar8) + 0x3b54aU ^
           (uVar56 << 6 | uVar56 >> 0x1a) * -0x61c8864f + 0x315fa;
  uVar33 = (uVar56 << 7 | uVar56 >> 0x19) * 0x1e3779b1 + 0x3165b & 0x7fffffff;
  *(uint *)(&stack0x0002a41c + lVar8) = uVar33;
  uVar31 = ((uVar32 + 0x9e37 ^ 0x13572468) << 2 | uVar32 + 0x9e37 >> 0x1e) * -0x61c8864f + 0x31476;
  *(uint *)(&stack0x0002a768 + lVar8) = uVar31;
  uVar56 = (uint)*(undefined8 *)(&stack0x0002a748 + lVar8);
  uVar31 = uVar56 + 0x13c6e ^ uVar31;
  uVar12 = (uint)*(undefined8 *)(&stack0x0002a758 + lVar8);
  uVar34 = uVar12 + 0x1daa5 ^ (uVar31 << 3 | uVar31 >> 0x1d) * -0x61c8864f + 0x314d7;
  uVar31 = (uint)*(undefined8 *)(&stack0x0002a780 + lVar8);
  uVar34 = uVar31 + 0x278dc ^ (uVar34 << 4 | uVar34 >> 0x1c) * -0x61c8864f + 0x31538;
  uVar34 = uVar54 + 0x31713 ^ (uVar34 << 5 | uVar34 >> 0x1b) * -0x61c8864f + 0x31599;
  *(undefined4 *)(&stack0x0002a420 + lVar8) = 0x452d8558;
  uVar34 = uVar57 + 0x3b54a ^ (uVar34 << 6 | uVar34 >> 0x1a) * -0x61c8864f + 0x315fa;
  uVar34 = (uVar34 << 7 | uVar34 >> 0x19) * 0x1e3779b1 + 0x3165b & 0x7fffffff;
  *(uint *)(&stack0x0002a424 + lVar8) = uVar34;
  uVar35 = uVar33 + 0x13c6e ^ 0xe67dce26;
  uVar35 = (uVar35 << 3 | uVar35 >> 0x1d) * -0x61c8864f + 0x314d7 ^ 0x452f5ffd;
  uVar34 = uVar34 + 0x278dc ^ (uVar35 << 4 | uVar35 >> 0x1c) * -0x61c8864f + 0x31538;
  uVar32 = (uVar32 ^ uVar31) + 0x9e37;
  uVar32 = (uVar54 ^ uVar56) + 0x13c6e ^
           ((uVar32 ^ 0x13572468) << 2 | uVar32 >> 0x1e) * -0x61c8864f + 0x31476;
  uVar40 = (uVar57 ^ uVar12) + 0x1daa5 ^ (uVar32 << 3 | uVar32 >> 0x1d) * -0x61c8864f + 0x314d7;
  uVar32 = (uVar34 << 5 | uVar34 >> 0x1b) * -0x61c8864f + 0x31599 ^ 0x6cce084b;
  uVar32 = (uVar32 << 6 | uVar32 >> 0x1a) * -0x61c8864f + 0x315fa ^ 0x6c1a2004;
  uVar34 = (uVar32 << 7 | uVar32 >> 0x19) * 0x1e3779b1 + 0x3165b;
  uVar35 = uVar34 & 0x7fffffff;
  *(uint *)(&stack0x0002a428 + lVar8) = uVar35;
  *(uint *)(&stack0x0002a778 + lVar8) = uVar35;
  uVar32 = (uVar33 ^ 0x2a87820d) + 0x278dc ^ (uVar40 << 4 | uVar40 >> 0x1c) * -0x61c8864f + 0x31538;
  uVar33 = (uVar32 << 5 | uVar32 >> 0x1b) * 0x1e3779b1 + 0x31599;
  uVar50 = uVar33 & 0x7fffffff;
  *(uint *)(&stack0x0002a42c + lVar8) = uVar50;
  *(ulonglong *)(&stack0x0002a780 + lVar8) = (ulonglong)(uVar31 + 0x13c6e);
  uVar56 = ((uVar56 + 0x9e37 ^ 0x13572468) << 2 | uVar56 + 0x9e37 >> 0x1e) * -0x61c8864f + 0x31476 ^
           uVar31 + 0x13c6e;
  uVar56 = (uVar56 << 3 | uVar56 >> 0x1d) * -0x61c8864f + 0x314d7 ^ 0x2a895cb2;
  *(undefined8 *)(&stack0x0002a430 + lVar8) = 0x2bbfb29d1c645cb4;
  uVar56 = (uVar56 << 4 | uVar56 >> 0x1c) * -0x61c8864f + 0x31538 ^ 0x1866d590;
  *(uint *)(&stack0x0002a438 + lVar8) =
       (uVar56 << 5 | uVar56 >> 0x1b) * 0x1e3779b1 + 0x31599 & 0x7fffffff;
  uVar56 = ((uVar53 * 0x80 | uVar54 >> 0x19) ^ (uVar12 << 3 | uVar12 >> 0x1d) ^
            *(uint *)(&stack0x0002a760 + lVar8) ^ (uVar34 * 0x800 | uVar35 >> 0x15)) & 0x7fffffff;
  *(ulonglong *)(&stack0x0002a728 + lVar8) = (ulonglong)uVar56;
  uVar56 = uVar56 ^ 0x6a09e667;
  *(ulonglong *)(&stack0x0002a760 + lVar8) = (ulonglong)uVar56;
  *(uint *)(&stack0x0002a43c + lVar8) = uVar56;
  pcVar23 = &stack0x00014550 + lVar8;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002f81;
  uVar56 = FUN_1800058a0((longlong)pcVar23,(uint)*(undefined8 *)(&stack0x0002a788 + lVar8),
                         0x679c62b7,0x45334cec);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002f9e;
  uVar12 = FUN_1800058a0((longlong)pcVar23,(uint)*(undefined8 *)(&stack0x0002a788 + lVar8),
                         0x679c62b7,0x56dfde64);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180002fbb;
  iVar11 = FUN_1800058a0((longlong)pcVar23,(uint)*(undefined8 *)(&stack0x0002a788 + lVar8),
                         0x679c62b7,0x133c1bd8);
  *(ulonglong *)(&stack0x0002a688 + lVar8) = (ulonglong)uVar56;
  uVar56 = uVar56 + 0x13c6e ^ 0xfd7ce8bf;
  *(ulonglong *)(&stack0x0002a690 + lVar8) = (ulonglong)uVar12;
  uVar56 = uVar12 + 0x1daa5 ^ (uVar56 << 3 | uVar56 >> 0x1d) * -0x61c8864f + 0x314d7;
  *(ulonglong *)(&stack0x0002a668 + lVar8) = CONCAT44(extraout_var_04,iVar11);
  uVar56 = iVar11 + 0x278dcU ^ (uVar56 << 4 | uVar56 >> 0x1c) * -0x61c8864f + 0x31538;
  uVar34 = (uVar56 << 5 | uVar56 >> 0x1b) * 0x1e3779b1 + 0x31599 & 0x7fffffff;
  *(uint *)(&stack0x0002a440 + lVar8) = uVar34;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x31c14e0d;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x21f97a97;
  uVar52 = *(undefined8 *)(&stack0x0002a750 + lVar8);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180003055;
  uVar56 = FUN_180005a70(pcVar23,(uint)*(undefined8 *)(&stack0x0002a788 + lVar8),
                         (longlong)(&stack0x00000050 + lVar8),(uint)uVar52,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8));
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar8) = 0x5348b787;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar8) = 0x29ddeb14;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x31c14e0d;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x21f97a97;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000308c;
  iVar11 = FUN_180005c10((longlong)pcVar23,(uint)*(undefined8 *)(&stack0x0002a788 + lVar8),
                         (longlong)(&stack0x00000050 + lVar8),(uint)uVar52,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff0 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff8 + lVar8));
  *(ulonglong *)(&stack0x0002a698 + lVar8) = (ulonglong)uVar56;
  uVar56 = uVar56 + 0x13c6e ^ 0x9c70a78e;
  uVar56 = (uVar56 << 3 | uVar56 >> 0x1d) * -0x61c8864f + 0x314d7 ^ 0x534a922c;
  *(ulonglong *)(&stack0x0002a678 + lVar8) = CONCAT44(extraout_var_05,iVar11);
  uVar56 = iVar11 + 0x278dcU ^ (uVar56 << 4 | uVar56 >> 0x1c) * -0x61c8864f + 0x31538;
  uVar31 = (uVar56 << 5 | uVar56 >> 0x1b) * 0x1e3779b1 + 0x31599;
  uVar56 = (int)*(undefined8 *)(&stack0x0002a760 + lVar8) + 0x9e37;
  uVar56 = ((uVar56 ^ 0x13572468) << 2 | uVar56 >> 0x1e) * -0x61c8864f + 0x31476 ^ uVar34 + 0x13c6e;
  uVar32 = uVar31 & 0x7fffffff;
  uVar56 = (uVar56 << 3 | uVar56 >> 0x1d) * -0x61c8864f + 0x314d7 ^ uVar32 + 0x1daa5;
  uVar56 = (uVar56 << 4 | uVar56 >> 0x1c) * -0x61c8864f + 0x31538 ^ 0x1cc72f42;
  uVar56 = (uVar56 << 5 | uVar56 >> 0x1b) * -0x61c8864f + 0x31599 ^ 0x5e86e725;
  uVar56 = (uVar56 << 6 | uVar56 >> 0x1a) * -0x61c8864f + 0x315fa;
  uVar12 = uVar56 & 0x7fffffff;
  uVar35 = ((uVar33 * 0x200 | uVar50 >> 0x17) ^ (uVar31 * 0x20 | uVar32 >> 0x1b) ^ uVar56) &
           0x7fffffff ^ 0x31415927;
  uVar31 = (uint)*(undefined8 *)(&stack0x0002a780 + lVar8) ^ *(uint *)(&stack0x0002a768 + lVar8);
  uVar33 = (int)*(undefined8 *)(&stack0x0002a760 + lVar8) + 0x1daa5;
  uVar31 = (uVar31 << 3 | uVar31 >> 0x1d) * -0x61c8864f + 0x314d7 ^ uVar33;
  uVar31 = (uVar31 << 4 | uVar31 >> 0x1c) * -0x61c8864f + 0x31538 ^ uVar12 + 0x278dc;
  *(undefined4 *)(&stack0x0002a5c0 + lVar8) = 0x79c3a46;
  uVar31 = (uVar31 << 5 | uVar31 >> 0x1b) * -0x61c8864f + 0x31599 ^ uVar35 + 0x31713;
  uVar31 = (uVar31 << 6 | uVar31 >> 0x1a) * 0x1e3779b1 + 0x315fa & 0x7fffffff;
  *(uint *)(&stack0x0002a5c4 + lVar8) = uVar31;
  *(undefined8 *)(&stack0x0002a5c8 + lVar8) = 0x24cca07a42081e72;
  uVar40 = ((uVar57 + 0x9e37 ^ 0x13572468) << 2 | uVar57 + 0x9e37 >> 0x1e) * -0x61c8864f + 0x31476 ^
           0x452ec1c6;
  iVar11 = *(int *)(&stack0x0002a778 + lVar8);
  *(uint *)(&stack0x0002a778 + lVar8) = iVar11 + 0x1daa5U;
  uVar40 = (uVar40 << 3 | uVar40 >> 0x1d) * -0x61c8864f + 0x314d7 ^ iVar11 + 0x1daa5U;
  uVar40 = uVar50 + 0x278dc ^ (uVar40 << 4 | uVar40 >> 0x1c) * -0x61c8864f + 0x31538;
  *(undefined4 *)(&stack0x0002a5d0 + lVar8) = 0x3313b37b;
  uVar52 = *(undefined8 *)(&stack0x0002a788 + lVar8);
  uVar40 = (uVar40 << 5 | uVar40 >> 0x1b) * -0x61c8864f + 0x31599 ^ 0x1c6773c7;
  uVar40 = (uVar40 << 6 | uVar40 >> 0x1a) * 0x1e3779b1 + 0x315fa & 0x7fffffff;
  uVar50 = uVar31 + 0x13c6e ^ 0xa6cbf28a;
  uVar50 = (uVar50 << 3 | uVar50 >> 0x1d) * -0x61c8864f + 0x314d7 ^ 0x4209f917;
  *(uint *)(&stack0x0002a5d4 + lVar8) = uVar40;
  uVar50 = (uVar50 << 4 | uVar50 >> 0x1c) * -0x61c8864f + 0x31538 ^ 0x24cf1956;
  uVar50 = (uVar50 << 5 | uVar50 >> 0x1b) * -0x61c8864f + 0x31599 ^ 0x6cce084b;
  uVar50 = (uVar50 << 6 | uVar50 >> 0x1a) * -0x61c8864f + 0x315fa ^ 0x6c1a2004;
  uVar47 = (uVar50 << 7 | uVar50 >> 0x19) * 0x1e3779b1 + 0x3165b & 0x7fffffff;
  uVar40 = uVar40 + 0x13c6e ^ 0x3cbd2b5e;
  uVar40 = (uVar40 << 3 | uVar40 >> 0x1d) * -0x61c8864f + 0x314d7;
  uVar40 = uVar47 + 0x278dc ^ ((uVar40 ^ 0xcff3fda) << 4 | uVar40 >> 0x1c) * -0x61c8864f + 0x31538;
  uVar40 = (uVar40 << 5 | uVar40 >> 0x1b) * -0x61c8864f + 0x31599 ^ 0x4c93aa93;
  uVar40 = (uVar40 << 6 | uVar40 >> 0x1a) * -0x61c8864f + 0x315fa ^ 0x3889d853;
  uVar50 = (uVar40 << 7 | uVar40 >> 0x19) * 0x1e3779b1 + 0x3165b;
  uVar53 = uVar50 & 0x7fffffff;
  uVar40 = ((uVar53 + 0x9e37 ^ 0x13572468) << 2 | uVar53 + 0x9e37 >> 0x1e) * -0x61c8864f + 0x31476 ^
           uVar34 + 0x13c6e;
  uVar40 = (uVar40 << 3 | uVar40 >> 0x1d) * -0x61c8864f + 0x314d7 ^ uVar32 + 0x1daa5;
  *(uint *)(&stack0x0002a444 + lVar8) = uVar32;
  *(undefined4 *)(&stack0x0002a5d8 + lVar8) = 0xcfd6535;
  *(uint *)(&stack0x0002a5dc + lVar8) = uVar47;
  *(uint *)(&stack0x0002a5e0 + lVar8) = uVar53;
  uVar40 = (uVar40 << 4 | uVar40 >> 0x1c) * -0x61c8864f + 0x31538 ^ uVar12 + 0x278dc;
  uVar40 = (uVar40 << 5 | uVar40 >> 0x1b) * -0x61c8864f + 0x31599 ^ uVar35 + 0x31713;
  uVar54 = (uVar40 << 6 | uVar40 >> 0x1a) * 0x1e3779b1 + 0x315fa & 0x7fffffff;
  uVar40 = uVar47 + 0x13c6e ^
           ((uVar54 + 0x9e37 ^ 0x13572468) << 2 | uVar54 + 0x9e37 >> 0x1e) * -0x61c8864f + 0x31476;
  *(uint *)(&stack0x0002a5e4 + lVar8) = uVar54;
  uVar40 = (uVar40 << 3 | uVar40 >> 0x1d) * -0x61c8864f + 0x314d7 ^ 0x21fb553c;
  uVar40 = (uVar40 << 4 | uVar40 >> 0x1c) * -0x61c8864f + 0x31538 ^ 0x534b3063;
  uVar40 = (uVar40 << 5 | uVar40 >> 0x1b) * -0x61c8864f + 0x31599 ^ 0x397b34d2;
  uVar40 = (uVar40 << 6 | uVar40 >> 0x1a) * 0x1e3779b1 + 0x315fa & 0x7fffffff;
  *(uint *)(&stack0x0002a5e8 + lVar8) = uVar40;
  uVar40 = uVar40 + 0x9e37;
  *(uint *)(&stack0x0002a448 + lVar8) = uVar12;
  uVar40 = ((uVar40 ^ 0x13572468) << 2 | uVar40 >> 0x1e) * -0x61c8864f + 0x31476 ^ 0x2223c95b;
  uVar40 = (uVar40 << 3 | uVar40 >> 0x1d) * -0x61c8864f + 0x314d7 ^ 0x5f68efd2;
  uVar40 = (uVar40 << 4 | uVar40 >> 0x1c) * -0x61c8864f + 0x31538 ^ 0x7e1206eb;
  *(uint *)(&stack0x0002a44c + lVar8) = uVar35;
  uVar40 = (uVar40 << 5 | uVar40 >> 0x1b) * -0x61c8864f + 0x31599 ^ 0x79ba106e;
  uVar57 = (uVar40 << 6 | uVar40 >> 0x1a) * 0x1e3779b1 + 0x315fa;
  uVar44 = uVar57 & 0x7fffffff;
  *(uint *)(&stack0x0002a5ec + lVar8) = uVar44;
  uVar31 = (uVar47 ^ uVar31) + 0x13c6e ^ 0xbe2018fe;
  uVar31 = (uVar53 ^ 0x42081e72) + 0x1daa5 ^ (uVar31 << 3 | uVar31 >> 0x1d) * -0x61c8864f + 0x314d7;
  uVar31 = (uVar54 ^ 0x24cca07a) + 0x278dc ^ (uVar31 << 4 | uVar31 >> 0x1c) * -0x61c8864f + 0x31538;
  uVar40 = (uVar31 << 5 | uVar31 >> 0x1b) * 0x1e3779b1 + 0x31599;
  uVar54 = uVar40 & 0x7fffffff;
  uVar31 = uVar54 + 0x13c6e ^
           ((uVar44 + 0x9e37 ^ 0x13572468) << 2 | uVar44 + 0x9e37 >> 0x1e) * -0x61c8864f + 0x31476;
  uVar33 = (uVar31 << 3 | uVar31 >> 0x1d) * -0x61c8864f + 0x314d7 ^ uVar33;
  *(uint *)(&stack0x0002a5f0 + lVar8) = uVar54;
  uVar31 = uVar35 + 0x278dc;
  uVar33 = (uVar33 << 4 | uVar33 >> 0x1c) * -0x61c8864f + 0x31538 ^ uVar31;
  uVar33 = (uVar33 << 5 | uVar33 >> 0x1b) * -0x61c8864f + 0x31599 ^ 0x321dd631;
  uVar47 = (uVar33 << 6 | uVar33 >> 0x1a) * -0x61c8864f + 0x315fa;
  uVar33 = (uVar50 * 0x200 | uVar53 >> 0x17) ^ (uVar57 * 0x20 | uVar44 >> 0x1b) ^ uVar47;
  *(uint *)(&stack0x0002a5f4 + lVar8) = uVar47 & 0x7fffffff;
  *(uint *)(&stack0x0002a5f8 + lVar8) = uVar33 & 0x7fffffff ^ 0x55aa1234;
  uVar56 = ((uVar56 * 0x80 | uVar12 >> 0x19) ^ (uVar40 * 8 | uVar54 >> 0x1d) ^ uVar33) & 0x7fffffff
           ^ 0x6666479e;
  *(uint *)(&stack0x0002a6e8 + lVar8) = uVar56;
  *(uint *)(&stack0x0002a5fc + lVar8) = uVar56;
  uVar56 = uVar32 + 0x13c6e ^
           ((uVar34 + 0x9e37 ^ 0x13572468) << 2 | uVar34 + 0x9e37 >> 0x1e) * -0x61c8864f + 0x31476;
  uVar56 = uVar12 + 0x1daa5 ^ (uVar56 << 3 | uVar56 >> 0x1d) * -0x61c8864f + 0x314d7;
  uVar56 = (uVar56 << 4 | uVar56 >> 0x1c) * -0x61c8864f + 0x31538 ^ uVar31;
  uVar56 = (uVar56 << 5 | uVar56 >> 0x1b) * -0x61c8864f + 0x31599 ^ 0x4c93aa93;
  *(undefined8 *)(&stack0x0002a580 + lVar8) = _DAT_18002a000;
  *(undefined8 *)(&stack0x0002a588 + lVar8) = _UNK_18002a008;
  uVar56 = (uVar56 << 6 | uVar56 >> 0x1a) * -0x61c8864f + 0x315fa ^ 0x3889d853;
  uVar56 = (uVar56 << 7 | uVar56 >> 0x19) * 0x1e3779b1 + 0x3165b & 0x7fffffff;
  *(uint *)(&stack0x0002a590 + lVar8) = uVar56;
  uVar56 = uVar56 + 0x31713 ^ 0xba24c65d;
  uVar56 = (uVar56 << 6 | uVar56 >> 0x1a) * -0x61c8864f + 0x315fa ^ 0x2a9a6e84;
  *(undefined8 *)(&stack0x0002a594 + lVar8) = 0x3ad4ff532b96b93a;
  uVar32 = (uVar56 << 7 | uVar56 >> 0x19) * 0x1e3779b1 + 0x3165b;
  uVar33 = uVar32 & 0x7fffffff;
  uVar56 = uVar33 + 0x1daa5 ^ 0xbf00dfe3;
  *(undefined4 *)(&stack0x0002a59c + lVar8) = 0x3ef642b9;
  uVar56 = (uVar56 << 4 | uVar56 >> 0x1c) * -0x61c8864f + 0x31538 ^ 0x6ccd6a14;
  uVar56 = (uVar56 << 5 | uVar56 >> 0x1b) * -0x61c8864f + 0x31599 ^ 0x6e08d0b8;
  uVar56 = (uVar56 << 6 | uVar56 >> 0x1a) * -0x61c8864f + 0x315fa ^ 0x6c1a2004;
  *(uint *)(&stack0x0002a5a0 + lVar8) = uVar33;
  uVar34 = (uVar56 << 7 | uVar56 >> 0x19) * 0x1e3779b1 + 0x3165b;
  uVar40 = uVar34 & 0x7fffffff;
  *(uint *)(&stack0x0002a5a4 + lVar8) = uVar40;
  uVar56 = (uVar33 ^ 0x2b96b93a) + 0x9e37;
  uVar56 = (uVar40 ^ 0x3ad4ff53) + 0x13c6e ^
           ((uVar56 ^ 0x13572468) << 2 | uVar56 >> 0x1e) * -0x61c8864f + 0x31476;
  uVar56 = (uVar12 ^ uVar35) + 0x1daa5 ^ (uVar56 << 3 | uVar56 >> 0x1d) * -0x61c8864f + 0x314d7;
  uVar56 = (uVar56 << 4 | uVar56 >> 0x1c) * -0x61c8864f + 0x31538 ^ 0xaf23a45;
  uVar56 = (uVar56 << 5 | uVar56 >> 0x1b) * 0x1e3779b1 + 0x31599 & 0x7fffffff;
  *(uint *)(&stack0x0002a5a8 + lVar8) = uVar56;
  uVar56 = uVar56 + 0x9e37;
  uVar56 = ((uVar56 ^ 0x13572468) << 2 | uVar56 >> 0x1e) * -0x61c8864f + 0x31476 ^ 0x74863ef8;
  *(undefined4 *)(&stack0x0002a5ac + lVar8) = 0x7485028a;
  uVar56 = (uVar56 << 3 | uVar56 >> 0x1d) * -0x61c8864f + 0x314d7 ^
           *(uint *)(&stack0x0002a778 + lVar8);
  uVar31 = (uVar56 << 4 | uVar56 >> 0x1c) * -0x61c8864f + 0x31538 ^ uVar31;
  uVar56 = (uVar31 << 5 | uVar31 >> 0x1b) * -0x61c8864f + 0x31599 ^ 0x5c86e725;
  uVar56 = (uVar56 << 6 | uVar56 >> 0x1a) * 0x1e3779b1 + 0x315fa;
  uVar12 = uVar56 & 0x7fffffff;
  *(uint *)(&stack0x0002a5b0 + lVar8) = uVar12;
  *(undefined4 *)(&stack0x0002a5b4 + lVar8) = 0x25fd0a80;
  uVar56 = (uVar34 * 0x200 | uVar40 >> 0x17) ^ (uVar56 * 0x20 | uVar12 >> 0x1b) ^ 0xa5fd0a80;
  *(ulonglong *)(&stack0x0002a700 + lVar8) = (ulonglong)uVar35;
  *(uint *)(&stack0x0002a5b8 + lVar8) = uVar56 & 0x7fffffff ^ 0x43d2e1f0;
  uVar56 = ((uVar35 << 7 | uVar35 >> 0x19) ^ (uVar32 * 8 | uVar33 >> 0x1d) ^ uVar56) & 0x7fffffff ^
           0x51e6a2d1;
  *(uint *)(&stack0x0002a6ec + lVar8) = uVar56;
  *(uint *)(&stack0x0002a5bc + lVar8) = uVar56;
  *(undefined8 *)(&stack0x0002a3d0 + lVar8) = _DAT_18002a010;
  *(undefined8 *)(&stack0x0002a3d8 + lVar8) = _UNK_18002a018;
  *(undefined8 *)(&stack0x0002a3e0 + lVar8) = _DAT_18002a020;
  *(undefined8 *)(&stack0x0002a3e8 + lVar8) = _UNK_18002a028;
  *(undefined8 *)(&stack0x0002a3f0 + lVar8) = _DAT_18002a030;
  *(undefined8 *)(&stack0x0002a3f8 + lVar8) = _UNK_18002a038;
  iVar11 = 0;
  lVar29 = 0;
  pcVar60 = isalnum_exref;
  do {
    uVar56 = (&DAT_18002a800)[lVar29 * 9];
    uVar12 = (&DAT_18002a804)[lVar29 * 9];
    *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180003a53;
    lVar25 = FUN_180005e10((longlong)(&stack0x00014550 + lVar8),(uint)uVar52,uVar56 ^ 0x4a3b29c1,
                           uVar12 ^ 0x13579bdf);
    if (lVar25 != 0) {
      *(int *)(&stack0x0002a748 + lVar8) = iVar11;
      puVar37 = &DAT_18002a800 + lVar29 * 9;
      uVar56 = (&DAT_18002a818)[lVar29 * 9];
      uVar12 = 1;
      *(longlong *)(&stack0x0002a778 + lVar8) = lVar25;
      *(undefined4 **)(&stack0x0002a760 + lVar8) = puVar37;
      *(uint *)(&stack0x0002a780 + lVar8) = uVar56;
      if ((uVar56 & 1) == 0) {
        if ((uVar56 & 2) == 0) goto LAB_180003a91;
LAB_180003b93:
        bVar10 = *(byte *)(lVar25 + 0xa0);
        if (bVar10 == 0) {
          uVar31 = 0x11c9dc5;
        }
        else {
          *(uint *)(&stack0x0002a768 + lVar8) = uVar12;
          pbVar59 = (byte *)(lVar25 + 0xa1);
          uVar31 = 0x811c9dc5;
          do {
            *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180003bc8;
            uVar56 = tolower((uint)bVar10);
            *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180003bd0;
            iVar11 = (*pcVar60)(bVar10);
            uVar12 = (uVar56 & 0xff ^ uVar31) * 0x1000193;
            if ((uVar56 & 0xff) == 0x5f) {
              uVar31 = uVar12;
            }
            if ((uVar56 & 0xef) == 0x2d) {
              uVar31 = uVar12;
            }
            if (iVar11 != 0) {
              uVar31 = uVar12;
            }
            bVar10 = *pbVar59;
            pbVar59 = pbVar59 + 1;
          } while (bVar10 != 0);
          uVar31 = uVar31 & 0x7fffffff;
          uVar52 = *(undefined8 *)(&stack0x0002a788 + lVar8);
          lVar25 = *(longlong *)(&stack0x0002a778 + lVar8);
          puVar37 = *(undefined4 **)(&stack0x0002a760 + lVar8);
          uVar56 = *(uint *)(&stack0x0002a780 + lVar8);
          uVar12 = *(uint *)(&stack0x0002a768 + lVar8);
        }
        if ((uVar31 ^ puVar37[2]) != 0x2468ace1) {
          uVar12 = 0;
        }
        if ((uVar56 & 4) != 0) goto LAB_180003c58;
joined_r0x000180004069:
        uVar31 = uVar12;
        if ((uVar56 & 8) == 0) goto LAB_180003aa5;
LAB_180003e4d:
        uVar12 = uVar31;
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180003e5c;
        uVar31 = FUN_1800056a0((char *)(lVar25 + 0xe0));
        uVar56 = *(uint *)(&stack0x0002a780 + lVar8);
        if ((uVar31 ^ puVar37[3]) != 0x4a3b29c1) {
          uVar12 = 0;
        }
        if ((char)uVar56 < '\0') goto LAB_180003e7b;
LAB_180003aae:
        lVar25 = *(longlong *)(&stack0x0002a778 + lVar8);
      }
      else {
        bVar10 = *(byte *)(lVar25 + 0xa0);
        if (bVar10 == 0) {
          uVar12 = 0x11c9dc5;
        }
        else {
          pbVar59 = (byte *)(lVar25 + 0xa1);
          uVar12 = 0x811c9dc5;
          do {
            *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180003b08;
            uVar56 = tolower((uint)bVar10);
            *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180003b10;
            iVar11 = (*pcVar60)(bVar10);
            uVar31 = (uVar56 & 0xff ^ uVar12) * 0x1000193;
            if ((uVar56 & 0xff) == 0x5f) {
              uVar12 = uVar31;
            }
            if ((uVar56 & 0xef) == 0x2d) {
              uVar12 = uVar31;
            }
            if (iVar11 != 0) {
              uVar12 = uVar31;
            }
            bVar10 = *pbVar59;
            pbVar59 = pbVar59 + 1;
          } while (bVar10 != 0);
          uVar12 = uVar12 & 0x7fffffff;
          uVar52 = *(undefined8 *)(&stack0x0002a788 + lVar8);
          lVar25 = *(longlong *)(&stack0x0002a778 + lVar8);
          puVar37 = *(undefined4 **)(&stack0x0002a760 + lVar8);
          uVar56 = *(uint *)(&stack0x0002a780 + lVar8);
        }
        uVar12 = (uint)((uVar12 ^ puVar37[2]) == 0x2468ace1);
        if ((uVar56 & 2) != 0) goto LAB_180003b93;
LAB_180003a91:
        if ((uVar56 & 4) == 0) goto joined_r0x000180004069;
LAB_180003c58:
        cVar30 = *(char *)(lVar25 + 0xe0);
        if (cVar30 != '\0') {
          *(uint *)(&stack0x0002a768 + lVar8) = uVar12;
          pcVar23 = (char *)(lVar25 + 0xe0);
          do {
            while ((cVar30 == ' ' || (cVar30 == ','))) {
              pcVar51 = pcVar23 + 1;
              pcVar23 = pcVar23 + 1;
              cVar30 = *pcVar51;
            }
            if (cVar30 == '\0') break;
            lVar26 = 0;
            while ((cVar30 != '\0' && (cVar30 != ','))) {
              (&stack0x00029e50)[lVar26 + lVar8] = cVar30;
              cVar30 = pcVar23[lVar26 + 1];
              if ((cVar30 == '\0') || (cVar30 == ',')) {
                pcVar51 = pcVar23 + lVar26 + 1;
                lVar26 = lVar26 + 1;
                goto LAB_180003d4a;
              }
              (&stack0x00029e51)[lVar26 + lVar8] = cVar30;
              cVar30 = pcVar23[lVar26 + 2];
              if ((cVar30 == '\0') || (cVar30 == ',')) {
                pcVar51 = pcVar23 + lVar26 + 2;
                lVar26 = lVar26 + 2;
                goto LAB_180003d4a;
              }
              (&stack0x00029e52)[lVar26 + lVar8] = cVar30;
              cVar30 = pcVar23[lVar26 + 3];
              if ((cVar30 == '\0') || (cVar30 == ',')) {
                pcVar51 = pcVar23 + lVar26 + 3;
                lVar26 = lVar26 + 3;
                goto LAB_180003d4a;
              }
              if (lVar26 == 0x7c) {
                pcVar51 = pcVar23 + 0x7f;
                lVar26 = 0x7f;
                goto LAB_180003d4a;
              }
              (&stack0x00029e53)[lVar26 + lVar8] = cVar30;
              lVar9 = lVar26 + 4;
              lVar26 = lVar26 + 4;
              cVar30 = pcVar23[lVar9];
            }
            pcVar51 = pcVar23 + lVar26;
LAB_180003d4a:
            (&stack0x00029e50)[lVar26 + lVar8] = 0;
            bVar10 = (&stack0x00029e50)[lVar8];
            if (bVar10 != 0) {
              *(char **)(&stack0x0002a758 + lVar8) = pcVar51;
              uVar12 = 0x811c9dc5;
              pbVar59 = &stack0x00029e51 + lVar8;
              do {
                *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180003d98;
                uVar56 = tolower((uint)bVar10);
                *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180003da0;
                iVar11 = isalnum((uint)bVar10);
                uVar31 = (uVar56 & 0xff ^ uVar12) * 0x1000193;
                if ((uVar56 & 0xff) == 0x5f) {
                  uVar12 = uVar31;
                }
                if ((uVar56 & 0xef) == 0x2d) {
                  uVar12 = uVar31;
                }
                if (iVar11 != 0) {
                  uVar12 = uVar31;
                }
                bVar10 = *pbVar59;
                pbVar59 = pbVar59 + 1;
              } while (bVar10 != 0);
              lVar25 = *(longlong *)(&stack0x0002a778 + lVar8);
              puVar37 = *(undefined4 **)(&stack0x0002a760 + lVar8);
              uVar56 = *(uint *)(&stack0x0002a780 + lVar8);
              pcVar51 = *(char **)(&stack0x0002a758 + lVar8);
              if ((uVar12 & 0x7fffffff) == 0x307c6f61) {
                uVar52 = *(undefined8 *)(&stack0x0002a788 + lVar8);
                uVar12 = *(uint *)(&stack0x0002a768 + lVar8);
                pcVar60 = isalnum_exref;
                goto joined_r0x000180004069;
              }
            }
            pcVar23 = pcVar51 + (*pcVar51 == ',');
            cVar30 = pcVar51[*pcVar51 == ','];
            uVar52 = *(undefined8 *)(&stack0x0002a788 + lVar8);
            pcVar60 = isalnum_exref;
          } while (cVar30 != '\0');
        }
        uVar12 = 0;
        uVar31 = 0;
        if ((uVar56 & 8) != 0) goto LAB_180003e4d;
LAB_180003aa5:
        if (-1 < (char)uVar56) goto LAB_180003aae;
LAB_180003e7b:
        lVar25 = *(longlong *)(&stack0x0002a778 + lVar8);
        bVar10 = *(byte *)(lVar25 + 0x160);
        if (bVar10 == 0) {
          uVar31 = 0x11c9dc5;
        }
        else {
          *(uint *)(&stack0x0002a768 + lVar8) = uVar12;
          pbVar59 = (byte *)(lVar25 + 0x161);
          uVar31 = 0x811c9dc5;
          do {
            *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180003eb8;
            uVar56 = tolower((uint)bVar10);
            *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180003ec0;
            iVar11 = (*pcVar60)(bVar10);
            uVar12 = (uVar56 & 0xff ^ uVar31) * 0x1000193;
            if ((uVar56 & 0xff) == 0x5f) {
              uVar31 = uVar12;
            }
            if ((uVar56 & 0xef) == 0x2d) {
              uVar31 = uVar12;
            }
            if (iVar11 != 0) {
              uVar31 = uVar12;
            }
            bVar10 = *pbVar59;
            pbVar59 = pbVar59 + 1;
          } while (bVar10 != 0);
          uVar31 = uVar31 & 0x7fffffff;
          uVar52 = *(undefined8 *)(&stack0x0002a788 + lVar8);
          lVar25 = *(longlong *)(&stack0x0002a778 + lVar8);
          puVar37 = *(undefined4 **)(&stack0x0002a760 + lVar8);
          uVar56 = *(uint *)(&stack0x0002a780 + lVar8);
          uVar12 = *(uint *)(&stack0x0002a768 + lVar8);
        }
        if ((uVar31 ^ puVar37[4]) != 0x13579bdf) {
          uVar12 = 0;
        }
      }
      if ((uVar56 & 0x10) != 0) {
        bVar10 = *(byte *)(lVar25 + 0x1e0);
        if (bVar10 == 0) {
          uVar31 = 0x11c9dc5;
        }
        else {
          *(uint *)(&stack0x0002a768 + lVar8) = uVar12;
          pbVar59 = (byte *)(lVar25 + 0x1e1);
          uVar31 = 0x811c9dc5;
          do {
            *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180003f88;
            uVar56 = tolower((uint)bVar10);
            *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180003f90;
            iVar11 = (*pcVar60)(bVar10);
            uVar12 = (uVar56 & 0xff ^ uVar31) * 0x1000193;
            if ((uVar56 & 0xff) == 0x5f) {
              uVar31 = uVar12;
            }
            if ((uVar56 & 0xef) == 0x2d) {
              uVar31 = uVar12;
            }
            if (iVar11 != 0) {
              uVar31 = uVar12;
            }
            bVar10 = *pbVar59;
            pbVar59 = pbVar59 + 1;
          } while (bVar10 != 0);
          uVar31 = uVar31 & 0x7fffffff;
          uVar52 = *(undefined8 *)(&stack0x0002a788 + lVar8);
          lVar25 = *(longlong *)(&stack0x0002a778 + lVar8);
          puVar37 = *(undefined4 **)(&stack0x0002a760 + lVar8);
          uVar56 = *(uint *)(&stack0x0002a780 + lVar8);
          uVar12 = *(uint *)(&stack0x0002a768 + lVar8);
        }
        if ((uVar31 ^ puVar37[5]) != 0x2468ace1) {
          uVar12 = 0;
        }
      }
      if (((uVar56 & 0x20) != 0) && (*(int *)(lVar25 + 0x224) != puVar37[8])) {
        uVar12 = 0;
      }
      if (((uVar56 & 0x40) != 0) && (*(int *)(lVar25 + 0x220) != puVar37[7])) {
        uVar12 = 0;
      }
      iVar11 = *(int *)(&stack0x0002a748 + lVar8) + uVar12;
    }
    lVar29 = lVar29 + 1;
  } while (lVar29 != 0x1f);
  *(int *)(&stack0x0002a748 + lVar8) = iVar11;
  *(int *)(&stack0x0002a6a8 + lVar8) = iVar11;
  *(undefined8 *)(&stack0x0002a760 + lVar8) = 0;
  lVar29 = 0;
  do {
    *(longlong *)(&stack0x0002a778 + lVar8) = lVar29;
    uVar56 = (&DAT_18002ac60)[lVar29 * 7];
    uVar12 = (&DAT_18002ac64)[lVar29 * 7];
    uVar31 = (&DAT_18002ac68)[lVar29 * 7];
    uVar32 = (&DAT_18002ac6c)[lVar29 * 7];
    uVar52 = *(undefined8 *)(&stack0x0002a788 + lVar8);
    *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004153;
    pcVar23 = (char *)FUN_180005e10((longlong)(&stack0x00014550 + lVar8),(uint)uVar52,
                                    uVar12 ^ 0x13579bdf,uVar56 ^ 0x4a3b29c1);
    *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004166;
    pcVar51 = (char *)FUN_180005e10((longlong)(&stack0x00014550 + lVar8),(uint)uVar52,
                                    uVar32 ^ 0x4a3b29c1,uVar31 ^ 0x2468ace1);
    if (((0 < *(int *)(&stack0x0002a750 + lVar8)) && (pcVar23 != (char *)0x0)) &&
       (pcVar51 != (char *)0x0)) {
      pbVar59 = &stack0x00000111 + lVar8;
      pbVar49 = &stack0x000000d1 + lVar8;
      pcVar27 = &stack0x00000050 + lVar8;
      lVar25 = *(longlong *)(&stack0x0002a770 + lVar8);
LAB_1800041cf:
      *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800041da;
      iVar11 = strcmp(pcVar27,pcVar23);
      if (iVar11 != 0) goto LAB_1800041b0;
      *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800041eb;
      iVar11 = strcmp(pcVar27 + 0x40,pcVar51);
      if (iVar11 != 0) goto LAB_1800041b0;
      *(undefined4 **)(&stack0x0002a780 + lVar8) = &DAT_18002ac60 + lVar29 * 7;
      bVar10 = pcVar27[0x80];
      uVar12 = 0x11c9dc5;
      uVar56 = 0x11c9dc5;
      if (bVar10 != 0) {
        uVar56 = 0x811c9dc5;
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000422b;
          uVar31 = tolower((uint)bVar10);
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004236;
          iVar11 = isalnum((uint)bVar10);
          uVar32 = (uVar31 & 0xff ^ uVar56) * 0x1000193;
          if ((uVar31 & 0xff) == 0x5f) {
            uVar56 = uVar32;
          }
          if ((uVar31 & 0xef) == 0x2d) {
            uVar56 = uVar32;
          }
          if (iVar11 != 0) {
            uVar56 = uVar32;
          }
          bVar10 = *pbVar49;
          pbVar49 = pbVar49 + 1;
        } while (bVar10 != 0);
        uVar56 = uVar56 & 0x7fffffff;
      }
      uVar31 = *(uint *)(*(longlong *)(&stack0x0002a780 + lVar8) + 0x10);
      bVar10 = pcVar27[0xc0];
      if (bVar10 != 0) {
        uVar12 = 0x811c9dc5;
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800042a7;
          uVar32 = tolower((uint)bVar10);
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800042b2;
          iVar11 = isalnum((uint)bVar10);
          uVar33 = (uVar32 & 0xff ^ uVar12) * 0x1000193;
          if ((uVar32 & 0xff) == 0x5f) {
            uVar12 = uVar33;
          }
          if ((uVar32 & 0xef) == 0x2d) {
            uVar12 = uVar33;
          }
          if (iVar11 != 0) {
            uVar12 = uVar33;
          }
          bVar10 = *pbVar59;
          pbVar59 = pbVar59 + 1;
        } while (bVar10 != 0);
        uVar12 = uVar12 & 0x7fffffff;
      }
      *(ulonglong *)(&stack0x0002a760 + lVar8) =
           (ulonglong)
           ((int)*(undefined8 *)(&stack0x0002a760 + lVar8) +
           (uint)((*(int *)(pcVar27 + 0x100) ==
                   *(int *)(*(longlong *)(&stack0x0002a780 + lVar8) + 0x18) &&
                  (uVar12 ^ *(uint *)(*(longlong *)(&stack0x0002a780 + lVar8) + 0x14)) == 0x2468ace1
                  ) && (uVar56 ^ uVar31) == 0x13579bdf));
    }
LAB_1800040e2:
    lVar29 = *(longlong *)(&stack0x0002a778 + lVar8) + 1;
  } while (lVar29 != 0x3d);
  bVar61 = *(int *)(&stack0x0002a740 + lVar8) == 3;
  uVar56 = bVar61 + 1;
  *(ulonglong *)(&stack0x0002a6a0 + lVar8) = (ulonglong)bVar61;
  if (*(int *)(&stack0x0002a738 + lVar8) != 2) {
    uVar56 = (uint)bVar61;
  }
  *(uint *)(&stack0x0002a780 + lVar8) = uVar56;
  *(int *)(&stack0x0002a6ac + lVar8) = (int)*(undefined8 *)(&stack0x0002a760 + lVar8);
  *(uint *)(&stack0x0002a758 + lVar8) = (uint)(*(int *)(&stack0x0002a730 + lVar8) == 1);
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x56dfde64;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x1cc4b666;
  pcVar23 = &stack0x00014550 + lVar8;
  puVar38 = &stack0x00000050 + lVar8;
  uVar52 = *(undefined8 *)(&stack0x0002a788 + lVar8);
  uVar31 = (uint)uVar52;
  uVar12 = (uint)*(undefined8 *)(&stack0x0002a750 + lVar8);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004373;
  iVar11 = FUN_180005a70(pcVar23,uVar31,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8));
  *(int *)(&stack0x0002a768 + lVar8) = iVar11;
  *(uint *)(&stack0x0002a778 + lVar8) = (uint)(*(int *)(&stack0x0002a718 + lVar8) == 3);
  iVar11 = *(int *)(&stack0x0002a720 + lVar8);
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x667c6911;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x4ba70f9b;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800043ba;
  iVar13 = FUN_180005a70(pcVar23,uVar31,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8));
  *(int *)(&stack0x0002a730 + lVar8) = iVar13;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x2047d5a7;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x7af2841;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800043e1;
  iVar13 = FUN_180005a70(pcVar23,uVar31,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8));
  *(int *)(&stack0x0002a718 + lVar8) = iVar13;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x667c6911;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x7af4527a;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004408;
  iVar13 = FUN_180005a70(pcVar23,uVar31,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8));
  *(int *)(&stack0x0002a6f0 + lVar8) = iVar13;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x667c6911;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x7bb6f95b;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000442f;
  iVar13 = FUN_180005a70(pcVar23,uVar31,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8));
  *(int *)(&stack0x0002a720 + lVar8) = iVar13;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x2047d5a7;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x71593832;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004456;
  iVar13 = FUN_180005a70(pcVar23,uVar31,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8));
  *(int *)(&stack0x0002a6f4 + lVar8) = iVar13;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004473;
  iVar13 = FUN_1800058a0((longlong)pcVar23,uVar31,0x6369e029,0x45334cec);
  *(int *)(&stack0x0002a6f8 + lVar8) = iVar13;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004490;
  iVar13 = FUN_1800058a0((longlong)pcVar23,uVar31,0x7c3044e6,0x45334cec);
  *(int *)(&stack0x0002a6fc + lVar8) = iVar13;
  *(uint *)(&stack0x0002a740 + lVar8) = (uint)(*(int *)(&stack0x0002a710 + lVar8) == 1);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800044bf;
  iVar13 = FUN_1800058a0((longlong)pcVar23,uVar31,0x6369e029,0x56dfde64);
  *(int *)(&stack0x0002a710 + lVar8) = iVar13;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800044dc;
  iVar14 = FUN_1800058a0((longlong)pcVar23,uVar31,0x7c3044e6,0x56dfde64);
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x1569150b;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800044f8;
  iVar15 = FUN_180005fe0(pcVar23,uVar31,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8));
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x3b781dbf;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004513;
  iVar16 = FUN_180005fe0(pcVar23,uVar31,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8));
  iVar13 = *(int *)(&stack0x0002a768 + lVar8);
  iVar18 = *(int *)(&stack0x0002a730 + lVar8);
  iVar19 = *(int *)(&stack0x0002a718 + lVar8);
  iVar20 = *(int *)(&stack0x0002a6f0 + lVar8);
  iVar21 = *(int *)(&stack0x0002a710 + lVar8);
  iVar3 = *(int *)(&stack0x0002a720 + lVar8);
  iVar4 = *(int *)(&stack0x0002a6f4 + lVar8);
  iVar5 = *(int *)(&stack0x0002a6f8 + lVar8);
  iVar45 = *(int *)(&stack0x0002a6fc + lVar8);
  iVar41 = *(int *)(&stack0x0002a698 + lVar8);
  iVar43 = *(int *)(&stack0x0002a690 + lVar8);
  iVar46 = *(int *)(&stack0x0002a688 + lVar8);
  iVar55 = *(int *)(&stack0x0002a680 + lVar8);
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x7e0f8e0f;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800045df;
  iVar17 = FUN_180005fe0(pcVar23,uVar31,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8));
  iVar58 = *(int *)(&stack0x0002a740 + lVar8);
  auVar63._0_4_ = -(uint)(iVar3 == _DAT_18002a040);
  auVar63._4_4_ = -(uint)(iVar4 == _UNK_18002a044);
  auVar63._8_4_ = -(uint)(iVar5 == _UNK_18002a048);
  auVar63._12_4_ = -(uint)(iVar45 == _UNK_18002a04c);
  auVar64._0_4_ = -(uint)(iVar21 == _DAT_18002a050);
  auVar64._4_4_ = -(uint)(iVar14 == _UNK_18002a054);
  auVar64._8_4_ = -(uint)(iVar15 == _UNK_18002a058);
  auVar64._12_4_ = -(uint)(iVar16 == _UNK_18002a05c);
  auVar64 = packssdw(auVar63,auVar64);
  auVar67._0_4_ = -(uint)(_DAT_18002a060 == iVar13);
  auVar67._4_4_ = -(uint)(_UNK_18002a064 == iVar18);
  auVar67._8_4_ = -(uint)(_UNK_18002a068 == iVar19);
  auVar67._12_4_ = -(uint)(_UNK_18002a06c == iVar20);
  auVar66._0_4_ = -(uint)(iVar55 == _DAT_18002a070);
  auVar66._4_4_ = -(uint)(iVar46 == _UNK_18002a074);
  auVar66._8_4_ = -(uint)(iVar43 == _UNK_18002a078);
  auVar66._12_4_ = -(uint)(iVar41 == _UNK_18002a07c);
  auVar67 = packssdw(auVar66,auVar67);
  auVar67 = packsswb(auVar67,auVar64);
  uVar7 = (ushort)(SUB161(auVar67 >> 7,0) & 1) | (ushort)(SUB161(auVar67 >> 0xf,0) & 1) << 1 |
          (ushort)(SUB161(auVar67 >> 0x17,0) & 1) << 2 |
          (ushort)(SUB161(auVar67 >> 0x1f,0) & 1) << 3 |
          (ushort)(SUB161(auVar67 >> 0x27,0) & 1) << 4 |
          (ushort)(SUB161(auVar67 >> 0x2f,0) & 1) << 5 |
          (ushort)(SUB161(auVar67 >> 0x37,0) & 1) << 6 |
          (ushort)(SUB161(auVar67 >> 0x3f,0) & 1) << 7 |
          (ushort)(SUB161(auVar67 >> 0x47,0) & 1) << 8 |
          (ushort)(SUB161(auVar67 >> 0x4f,0) & 1) << 9 |
          (ushort)(SUB161(auVar67 >> 0x57,0) & 1) << 10 |
          (ushort)(SUB161(auVar67 >> 0x5f,0) & 1) << 0xb |
          (ushort)(SUB161(auVar67 >> 0x67,0) & 1) << 0xc |
          (ushort)(SUB161(auVar67 >> 0x6f,0) & 1) << 0xd |
          (ushort)(SUB161(auVar67 >> 0x77,0) & 1) << 0xe | (ushort)(byte)(auVar67[0xf] >> 7) << 0xf;
  *(uint *)(&stack0x0002a740 + lVar8) = (uint)uVar7;
  uVar56 = (uint)uVar7 - (uVar7 >> 1 & 0x5555);
  uVar56 = (uVar56 >> 2 & 0x3333) + (uVar56 & 0x3333);
  uVar56 = (uVar56 >> 4) + uVar56 & 0xf0f;
  iVar11 = (uint)(iVar11 == 3) + *(int *)(&stack0x0002a778 + lVar8) +
           *(int *)(&stack0x0002a758 + lVar8) +
           (uint)(iVar17 == 1) + iVar58 + *(int *)(&stack0x0002a780 + lVar8) +
           ((uVar56 >> 8) + uVar56 & 0xff);
  if (0 < (int)uVar12) {
    *(int *)(&stack0x0002a768 + lVar8) = iVar11;
    lVar29 = 0;
    pbVar59 = &stack0x000000d1 + lVar8;
    iVar11 = 0;
    do {
      bVar10 = (&stack0x000000d0)[lVar29 * 0x104 + lVar8];
      if (bVar10 != 0) {
        *(int *)(&stack0x0002a780 + lVar8) = iVar11;
        uVar56 = 0x811c9dc5;
        *(byte **)(&stack0x0002a778 + lVar8) = pbVar59;
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004728;
          uVar12 = tolower((uint)bVar10);
          *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000472f;
          iVar11 = isalnum((uint)bVar10);
          uVar31 = (uVar12 & 0xff ^ uVar56) * 0x1000193;
          if ((uVar12 & 0xff) == 0x5f) {
            uVar56 = uVar31;
          }
          if ((uVar12 & 0xef) == 0x2d) {
            uVar56 = uVar31;
          }
          if (iVar11 != 0) {
            uVar56 = uVar31;
          }
          bVar10 = *pbVar59;
          pbVar59 = pbVar59 + 1;
        } while (bVar10 != 0);
        iVar11 = *(int *)(&stack0x0002a780 + lVar8) + (uint)((uVar56 & 0x7fffffff) == 0x6ccaf138);
        uVar52 = *(undefined8 *)(&stack0x0002a788 + lVar8);
        pbVar59 = *(byte **)(&stack0x0002a778 + lVar8);
      }
      uVar31 = (uint)uVar52;
      lVar29 = lVar29 + 1;
      pbVar59 = pbVar59 + 0x104;
    } while (lVar29 != *(longlong *)(&stack0x0002a770 + lVar8));
    iVar11 = *(int *)(&stack0x0002a768 + lVar8) + (uint)(iVar11 == 0x18);
  }
  bVar61 = iVar13 == _UNK_18002a084;
  iVar13 = *(int *)(&stack0x0002a738 + lVar8);
  *(int *)(&stack0x0002a768 + lVar8) = iVar11;
  *(int *)(&stack0x0002a6b0 + lVar8) = iVar11;
  iVar11 = *(int *)(&stack0x0002a708 + lVar8);
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x251b4cfe;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x67ca41f9;
  pcVar23 = &stack0x00014550 + lVar8;
  puVar38 = &stack0x00000050 + lVar8;
  uVar12 = (uint)*(undefined8 *)(&stack0x0002a750 + lVar8);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800047e3;
  iVar18 = FUN_180005a70(pcVar23,uVar31,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8));
  uVar56 = (iVar11 == 3) + 1;
  if (iVar18 != 2) {
    uVar56 = (uint)(iVar11 == 3);
  }
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x251b4cfe;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x183d8b67;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000480f;
  iVar11 = FUN_180005a70(pcVar23,uVar31,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8));
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x251b4cfe;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x546fe9c0;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000483a;
  iVar18 = FUN_180005a70(pcVar23,uVar31,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8));
  iVar13 = ((ushort)-(ushort)bVar61 & 1) +
           (int)*(undefined8 *)(&stack0x0002a6a0 + lVar8) + *(int *)(&stack0x0002a758 + lVar8) +
           (uint)(iVar13 == 2) +
           (uint)((int)*(undefined8 *)(&stack0x0002a670 + lVar8) == 1 &&
                 (int)*(undefined8 *)(&stack0x0002a660 + lVar8) == 1) + uVar56 + (uint)(iVar11 == 1)
           + (uint)(iVar18 == 3);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004899;
  iVar11 = FUN_1800058a0((longlong)pcVar23,uVar31,0x679c62b7,0x667c6911);
  if (iVar11 == 1) {
    *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800048bb;
    iVar18 = FUN_1800058a0((longlong)(&stack0x00014550 + lVar8),uVar31,0x679c62b7,0x2047d5a7);
    iVar13 = iVar13 + (uint)(iVar18 == 1);
  }
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar8) = 0x5548baad;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar8) = 0x29ddeb14;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x31c14e0d;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x23f97dbd;
  puVar38 = &stack0x00014550 + lVar8;
  pcVar23 = &stack0x00000050 + lVar8;
  uVar56 = (uint)*(undefined8 *)(&stack0x0002a750 + lVar8);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000490b;
  iVar18 = FUN_180005c10((longlong)puVar38,uVar31,(longlong)pcVar23,uVar56,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff0 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff8 + lVar8));
  *(int *)(&stack0x0002a778 + lVar8) = iVar18;
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar8) = 0x5248b5f4;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar8) = 0x29ddeb14;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x31c14e0d;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x20f97904;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004942;
  iVar18 = FUN_180005c10((longlong)puVar38,uVar31,(longlong)pcVar23,uVar56,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff0 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff8 + lVar8));
  *(int *)(&stack0x0002a780 + lVar8) = iVar18;
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar8) = 0x4ba70f9b;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar8) = 0x6c166aba;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x667c6911;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x4ba70f9b;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004979;
  iVar18 = FUN_180005c10((longlong)puVar38,uVar31,(longlong)pcVar23,uVar56,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff0 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff8 + lVar8));
  *(int *)(&stack0x0002a758 + lVar8) = iVar18;
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar8) = 0x7af4527a;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar8) = 0x6c166aba;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x667c6911;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x7af4527a;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800049b0;
  iVar18 = FUN_180005c10((longlong)puVar38,uVar31,(longlong)pcVar23,uVar56,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff0 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff8 + lVar8));
  *(int *)(&stack0x0002a738 + lVar8) = iVar18;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800049cd;
  pcVar51 = (char *)FUN_180005e10((longlong)puVar38,uVar31,0x133c1bd8,0x22dcd889);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800049e7;
  pcVar27 = (char *)FUN_180005e10((longlong)puVar38,uVar31,0x56dfde64,0x4af021b);
  iVar18 = 0;
  if (((0 < (int)uVar56) && (pcVar51 != (char *)0x0)) && (pcVar27 != (char *)0x0)) {
    pcVar24 = &stack0x00000050 + lVar8;
    lVar29 = *(longlong *)(&stack0x0002a770 + lVar8);
    do {
      *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004a28;
      iVar18 = strcmp(pcVar24,pcVar51);
      if (iVar18 == 0) {
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004a39;
        iVar18 = strcmp(pcVar24 + 0x40,pcVar27);
        if (iVar18 == 0) {
          iVar18 = 1;
          goto LAB_180004a48;
        }
      }
      pcVar24 = pcVar24 + 0x104;
      lVar29 = lVar29 + -1;
    } while (lVar29 != 0);
    iVar18 = 0;
  }
LAB_180004a48:
  uVar56 = (uint)*(undefined8 *)(&stack0x0002a788 + lVar8);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004a6d;
  pcVar51 = (char *)FUN_180005e10((longlong)(&stack0x00014550 + lVar8),uVar56,0x133c1bd8,0x5e83d012)
  ;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004a87;
  pcVar27 = (char *)FUN_180005e10((longlong)(&stack0x00014550 + lVar8),uVar56,0x56dfde64,0x1cc4b666)
  ;
  if ((0 < *(int *)(&stack0x0002a750 + lVar8)) && (pcVar24 = pcVar27, pcVar51 != (char *)0x0)) {
    while (pcVar24 != (char *)0x0) {
      *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800050f0;
      iVar19 = strcmp(pcVar23,pcVar51);
      if (iVar19 == 0) {
        *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180005100;
        iVar19 = strcmp(pcVar23 + 0x40,pcVar27);
        if (iVar19 == 0) {
          iVar19 = 1;
          goto LAB_180004aa4;
        }
      }
      pcVar23 = pcVar23 + 0x104;
      plVar2 = (longlong *)(&stack0x0002a770 + lVar8);
      *plVar2 = *plVar2 + -1;
      pcVar24 = (char *)*plVar2;
    }
  }
  iVar19 = 0;
LAB_180004aa4:
  *(uint *)(&stack0x0002a770 + lVar8) = (uint)(iVar11 == 1);
  uVar31 = (*(uint *)(&stack0x0002a740 + lVar8) & 2) >> 1;
  iVar11 = (uint)(*(int *)(&stack0x0002a738 + lVar8) == 1) + iVar18 + iVar19 +
           (uint)(*(int *)(&stack0x0002a758 + lVar8) == 2) +
           (uint)(*(int *)(&stack0x0002a780 + lVar8) == 3) +
           iVar13 + (uint)(*(int *)(&stack0x0002a778 + lVar8) == 3);
  uVar12 = uVar31 + 1;
  if ((*(uint *)(&stack0x0002a740 + lVar8) & 4) == 0) {
    uVar12 = uVar31;
  }
  *(uint *)(&stack0x0002a778 + lVar8) = uVar12;
  *(int *)(&stack0x0002a6b4 + lVar8) = iVar11;
  *(uint *)(&stack0x0002a780 + lVar8) = (uint)(*(int *)(&stack0x0002a668 + lVar8) == 1);
  puVar1 = &stack0x00014550 + lVar8;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004b46;
  iVar13 = FUN_1800058a0((longlong)puVar1,uVar56,0x679c62b7,0x2047d5a7);
  *(uint *)(&stack0x0002a758 + lVar8) = (uint)(iVar13 == 1);
  iVar13 = *(int *)(&stack0x0002a678 + lVar8);
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar8) = 0x7bb6f95b;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar8) = 0x6c166aba;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x667c6911;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x7bb6f95b;
  puVar38 = &stack0x00000050 + lVar8;
  uVar12 = (uint)*(undefined8 *)(&stack0x0002a750 + lVar8);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004b9e;
  iVar18 = FUN_180005c10((longlong)puVar1,uVar56,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff0 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff8 + lVar8));
  *(uint *)(&stack0x0002a738 + lVar8) = (uint)(iVar18 == 2);
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar8) = 0x71593832;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar8) = 0x6c166aba;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x2047d5a7;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x71593832;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004bdd;
  iVar18 = FUN_180005c10((longlong)puVar1,uVar56,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff0 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff8 + lVar8));
  *(uint *)(&stack0x0002a740 + lVar8) = (uint)(iVar18 == 1);
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar8) = 0x784003d0;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar8) = 0x6e05b9a5;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x56dfde64;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x1cc4b666;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004c1c;
  iVar18 = FUN_180005c10((longlong)puVar1,uVar56,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff0 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff8 + lVar8));
  *(uint *)(&stack0x0002a730 + lVar8) = (uint)(iVar18 == 1);
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar8) = 0x549dd484;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar8) = 0x6e05b9a5;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x56dfde64;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x1cc4b666;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004c5b;
  iVar18 = FUN_180005c10((longlong)puVar1,uVar56,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff0 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff8 + lVar8));
  *(uint *)(&stack0x0002a708 + lVar8) = (uint)(iVar18 == 1);
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar8) = 0x21e0ae1;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar8) = 0x6e05b9a5;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x56dfde64;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x1cc4b666;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004c9a;
  iVar18 = FUN_180005c10((longlong)puVar1,uVar56,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff0 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff8 + lVar8));
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar8) = 0x784003d0;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar8) = 0x3c17895f;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x251b4cfe;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x546fe9c0;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004cd5;
  iVar19 = FUN_180005c10((longlong)puVar1,uVar56,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff0 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff8 + lVar8));
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar8) = 0x549dd484;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar8) = 0x3c17895f;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x251b4cfe;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x546fe9c0;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004d12;
  iVar20 = FUN_180005c10((longlong)(&stack0x00014550 + lVar8),uVar56,(longlong)puVar38,uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff0 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff8 + lVar8));
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar8) = 0x21e0ae1;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar8) = 0x3c17895f;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar8) = 0x251b4cfe;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x546fe9c0;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004d52;
  iVar21 = FUN_180005c10((longlong)(&stack0x00014550 + lVar8),uVar56,
                         (longlong)(&stack0x00000050 + lVar8),uVar12,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff0 + lVar8),
                         *(uint *)(&stack0xfffffffffffffff8 + lVar8));
  iVar13 = (uint)(iVar13 == 3) + *(int *)(&stack0x0002a780 + lVar8) +
           *(int *)(&stack0x0002a770 + lVar8) + *(int *)(&stack0x0002a758 + lVar8) +
           *(int *)(&stack0x0002a738 + lVar8) + *(int *)(&stack0x0002a740 + lVar8) +
           *(int *)(&stack0x0002a730 + lVar8) + *(int *)(&stack0x0002a708 + lVar8) +
           (uint)(iVar18 == 1) + (uint)(iVar19 == 1) + (uint)(iVar20 == 1) + (uint)(iVar21 == 1) +
           *(int *)(&stack0x0002a778 + lVar8);
  *(int *)(&stack0x0002a6b8 + lVar8) = iVar13;
  *(int *)(&stack0x0002a6bc + lVar8) =
       (int)*(undefined8 *)(&stack0x0002a760 + lVar8) + *(int *)(&stack0x0002a748 + lVar8) +
       *(int *)(&stack0x0002a768 + lVar8) + iVar11 + iVar13;
  *(undefined1 **)(&stack0xfffffffffffffff0 + lVar8) = &stack0x0002a6d0 + lVar8;
  *(undefined1 **)(&stack0xffffffffffffffe8 + lVar8) = &stack0x0002a6c0 + lVar8;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x71c2e3a5;
  puVar38 = &stack0x0002a400 + lVar8;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004e04;
  FUN_1800054b0((longlong)puVar38,0x14,0x18002a3c0,0x50,*(uint *)(&stack0xffffffffffffffe0 + lVar8),
                *(int **)(&stack0xffffffffffffffe8 + lVar8),
                *(uint **)(&stack0xfffffffffffffff0 + lVar8));
  *(undefined1 **)(&stack0xfffffffffffffff0 + lVar8) = &stack0x0002a6d4 + lVar8;
  *(undefined1 **)(&stack0xffffffffffffffe8 + lVar8) = &stack0x0002a6c4 + lVar8;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x39a4f17c;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004e45;
  FUN_1800054b0((longlong)(&stack0x0002a5c0 + lVar8),0x10,0x18002a500,0x48,
                *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                *(int **)(&stack0xffffffffffffffe8 + lVar8),
                *(uint **)(&stack0xfffffffffffffff0 + lVar8));
  *(undefined1 **)(&stack0xfffffffffffffff0 + lVar8) = &stack0x0002a6d8 + lVar8;
  *(undefined1 **)(&stack0xffffffffffffffe8 + lVar8) = &stack0x0002a6c8 + lVar8;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x5c31d98e;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004e83;
  FUN_1800054b0((longlong)(&stack0x0002a580 + lVar8),0x10,0x18002a620,0x3e,
                *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                *(int **)(&stack0xffffffffffffffe8 + lVar8),
                *(uint **)(&stack0xfffffffffffffff0 + lVar8));
  *(undefined1 **)(&stack0xfffffffffffffff0 + lVar8) = &stack0x0002a6dc + lVar8;
  *(undefined1 **)(&stack0xffffffffffffffe8 + lVar8) = &stack0x0002a6cc + lVar8;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = 0x2ed4b881;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180004ec1;
  FUN_1800054b0((longlong)(&stack0x0002a3d0 + lVar8),0xc,0x18002a720,0x36,
                *(uint *)(&stack0xffffffffffffffe0 + lVar8),
                *(int **)(&stack0xffffffffffffffe8 + lVar8),
                *(uint **)(&stack0xfffffffffffffff0 + lVar8));
  uVar56 = (uint)*(undefined8 *)(&stack0x0002a728 + lVar8) ^ *(uint *)(&stack0x0002a700 + lVar8) ^
           *(uint *)(&stack0x0002a6ec + lVar8) ^ *(uint *)(&stack0x0002a6e8 + lVar8) ^ 0x6a09e65a;
  iVar45 = uVar56 + (uint)((ulonglong)uVar56 * 0x8637a2a3 >> 0x33) * -0xf4243;
  iVar11 = *(int *)(&stack0x0002a6a8 + lVar8);
  iVar13 = *(int *)(&stack0x0002a6ac + lVar8);
  iVar18 = *(int *)(&stack0x0002a6b0 + lVar8);
  iVar19 = *(int *)(&stack0x0002a6b4 + lVar8);
  iVar20 = *(int *)(&stack0x0002a6b8 + lVar8);
  iVar21 = *(int *)(&stack0x0002a6c0 + lVar8);
  iVar3 = *(int *)(&stack0x0002a6c4 + lVar8);
  iVar4 = *(int *)(&stack0x0002a6c8 + lVar8);
  iVar5 = *(int *)(&stack0x0002a6cc + lVar8);
  if (iVar11 == 0x1f) {
    auVar62._0_4_ = -(uint)(_DAT_18002a090 == iVar21);
    auVar62._4_4_ = -(uint)(_UNK_18002a094 == iVar3);
    auVar62._8_4_ = -(uint)(_UNK_18002a098 == iVar4);
    auVar62._12_4_ = -(uint)(_UNK_18002a09c == iVar5);
    auVar65._0_4_ = -(uint)(_DAT_18002a0a0 == iVar13);
    auVar65._4_4_ = -(uint)(_UNK_18002a0a4 == iVar18);
    auVar65._8_4_ = -(uint)(_UNK_18002a0a8 == iVar19);
    auVar65._12_4_ = -(uint)(_UNK_18002a0ac == iVar20);
    auVar67 = packssdw(auVar65,auVar62);
    auVar67 = packsswb(auVar67,auVar67);
    if (((byte)(SUB161(auVar67 >> 7,0) & 1 | (SUB161(auVar67 >> 0xf,0) & 1) << 1 |
                (SUB161(auVar67 >> 0x17,0) & 1) << 2 | (SUB161(auVar67 >> 0x1f,0) & 1) << 3 |
                (SUB161(auVar67 >> 0x27,0) & 1) << 4 | (SUB161(auVar67 >> 0x2f,0) & 1) << 5 |
                (SUB161(auVar67 >> 0x37,0) & 1) << 6 | SUB161(auVar67 >> 0x3f,0) << 7) != 0xff) ||
       (((*(uint *)(&stack0x0002a6d4 + lVar8) << 7 | *(uint *)(&stack0x0002a6d4 + lVar8) >> 0x19) ^
         *(uint *)(&stack0x0002a6d0 + lVar8) ^
        (*(uint *)(&stack0x0002a6dc + lVar8) << 0x13 | *(uint *)(&stack0x0002a6dc + lVar8) >> 0xd) ^
        (*(uint *)(&stack0x0002a6d8 + lVar8) << 0xd | *(uint *)(&stack0x0002a6d8 + lVar8) >> 0x13))
        != 0xbafbaeea)) goto LAB_18000510f;
    *(undefined1 (*) [16])(&stack0x0002a650 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a640 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a630 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a620 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a610 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a600 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a5f0 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a5e0 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a5d0 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a5c0 + lVar8) = (undefined1  [16])0x0;
    if (iVar45 == 0x2911e) {
      iVar55 = -0x3a4e2d01;
      bVar10 = 0x49;
      iVar41 = 0x47502943;
      iVar43 = 0x47502932;
      iVar46 = 0x3c6ef35f;
      uVar56 = 0;
      for (lVar29 = 1; iVar58 = iVar55 * 0x19660d + iVar46,
          (&stack0x0002a5bf)[lVar29 + lVar8] =
               (&UNK_18002b30f)[lVar29] ^ bVar10 + 0xb7 ^ (byte)((uint)iVar58 >> 0x10) ^
               (byte)iVar58, lVar29 != 0x2d; lVar29 = lVar29 + 2) {
        iVar58 = iVar55 * 0x17385ca9;
        iVar55 = uVar56 + 1 + (uVar56 | 1) * 0x10 + iVar43 + iVar58;
        iVar58 = iVar58 + iVar41;
        (&stack0x0002a5c0)[lVar29 + lVar8] =
             (byte)((uint)iVar58 >> 0x10) ^ bVar10 ^ (&DAT_18002b310)[lVar29] ^ (byte)iVar58;
        uVar56 = uVar56 + 2;
        bVar10 = bVar10 + 0x92;
        iVar41 = iVar41 + 0x35f8ddc;
        iVar43 = iVar43 + 0x35f8dba;
        iVar46 = iVar46 + 0x22;
      }
      (&stack0x0002a5ed)[lVar8] = 0;
      *(undefined8 *)(&stack0x0002a400 + lVar8) = s_Specter_control_plane_reconciled_18002a0d0._0_8_
      ;
      *(undefined8 *)(&stack0x0002a408 + lVar8) = s_Specter_control_plane_reconciled_18002a0d0._8_8_
      ;
      *(undefined8 *)(&stack0x0002a410 + lVar8) =
           s_Specter_control_plane_reconciled_18002a0d0._16_8_;
      *(undefined8 *)(&stack0x0002a418 + lVar8) =
           s_Specter_control_plane_reconciled_18002a0d0._24_8_;
      *(undefined8 *)(&stack0x0002a420 + lVar8) =
           s_Specter_control_plane_reconciled_18002a0d0._32_8_;
      *(ulonglong *)(&stack0x0002a428 + lVar8) =
           CONCAT26(s_Specter_control_plane_reconciled_18002a0d0._46_2_,
                    s_Specter_control_plane_reconciled_18002a0d0._40_6_);
      *(ulonglong *)(&stack0x0002a42e + lVar8) =
           CONCAT62(s_Specter_control_plane_reconciled_18002a0d0._48_6_,
                    s_Specter_control_plane_reconciled_18002a0d0._46_2_);
      *(undefined8 *)(&stack0x0002a436 + lVar8) =
           s_Specter_control_plane_reconciled_18002a0d0._54_8_;
      pcVar23 = "true";
      puVar38 = &stack0x0002a400 + lVar8;
      goto LAB_18000537e;
    }
  }
  else {
LAB_18000510f:
    *(undefined1 (*) [16])(&stack0x0002a650 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a640 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a630 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a620 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a610 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a600 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a5f0 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a5e0 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a5d0 + lVar8) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x0002a5c0 + lVar8) = (undefined1  [16])0x0;
  }
  if ((iVar20 < 0xb) || (iVar5 < 4)) {
    if ((iVar19 < 0xc) || (iVar4 < 5)) {
      if ((iVar13 < 0x30) || (iVar18 < 0x12)) {
        if (iVar11 < 0x18) {
          *(undefined8 *)(&stack0x0002a430 + lVar8) =
               s_Specter_control_plane_unstable__C_18002a24b._48_8_;
          *(undefined8 *)(&stack0x0002a438 + lVar8) =
               s_Specter_control_plane_unstable__C_18002a24b._56_8_;
          *(undefined8 *)(&stack0x0002a420 + lVar8) =
               s_Specter_control_plane_unstable__C_18002a24b._32_8_;
          *(undefined8 *)(&stack0x0002a428 + lVar8) =
               s_Specter_control_plane_unstable__C_18002a24b._40_8_;
          *(undefined8 *)(&stack0x0002a410 + lVar8) =
               s_Specter_control_plane_unstable__C_18002a24b._16_8_;
          *(undefined8 *)(&stack0x0002a418 + lVar8) =
               s_Specter_control_plane_unstable__C_18002a24b._24_8_;
          *(undefined8 *)(&stack0x0002a400 + lVar8) =
               s_Specter_control_plane_unstable__C_18002a24b._0_8_;
          *(undefined8 *)(&stack0x0002a408 + lVar8) =
               s_Specter_control_plane_unstable__C_18002a24b._8_8_;
          *(undefined4 *)(&stack0x0002a440 + lVar8) = 0x2e6574;
        }
        else {
          *(ulonglong *)(&stack0x0002a44a + lVar8) =
               CONCAT26(s_Manifest_is_close__but_scheduler_18002a1f1._80_2_,
                        s_Manifest_is_close__but_scheduler_18002a1f1._74_6_);
          *(undefined8 *)(&stack0x0002a452 + lVar8) =
               s_Manifest_is_close__but_scheduler_18002a1f1._82_8_;
          *(undefined8 *)(&stack0x0002a440 + lVar8) =
               s_Manifest_is_close__but_scheduler_18002a1f1._64_8_;
          *(ulonglong *)(&stack0x0002a448 + lVar8) =
               CONCAT62(s_Manifest_is_close__but_scheduler_18002a1f1._74_6_,
                        s_Manifest_is_close__but_scheduler_18002a1f1._72_2_);
          *(undefined8 *)(&stack0x0002a430 + lVar8) =
               s_Manifest_is_close__but_scheduler_18002a1f1._48_8_;
          *(undefined8 *)(&stack0x0002a438 + lVar8) =
               s_Manifest_is_close__but_scheduler_18002a1f1._56_8_;
          *(undefined8 *)(&stack0x0002a420 + lVar8) =
               s_Manifest_is_close__but_scheduler_18002a1f1._32_8_;
          *(undefined8 *)(&stack0x0002a428 + lVar8) =
               s_Manifest_is_close__but_scheduler_18002a1f1._40_8_;
          *(undefined8 *)(&stack0x0002a410 + lVar8) =
               s_Manifest_is_close__but_scheduler_18002a1f1._16_8_;
          *(undefined8 *)(&stack0x0002a418 + lVar8) =
               s_Manifest_is_close__but_scheduler_18002a1f1._24_8_;
          *(undefined8 *)(&stack0x0002a400 + lVar8) =
               s_Manifest_is_close__but_scheduler_18002a1f1._0_8_;
          *(undefined8 *)(&stack0x0002a408 + lVar8) =
               s_Manifest_is_close__but_scheduler_18002a1f1._8_8_;
        }
      }
      else {
        *(ulonglong *)(&stack0x0002a43d + lVar8) =
             CONCAT53(s_Control_plane_is_close__Northbou_18002a1a4._64_5_,
                      s_Control_plane_is_close__Northbou_18002a1a4._61_3_);
        *(undefined8 *)(&stack0x0002a445 + lVar8) =
             s_Control_plane_is_close__Northbou_18002a1a4._69_8_;
        *(undefined8 *)(&stack0x0002a430 + lVar8) =
             s_Control_plane_is_close__Northbou_18002a1a4._48_8_;
        *(ulonglong *)(&stack0x0002a438 + lVar8) =
             CONCAT35(s_Control_plane_is_close__Northbou_18002a1a4._61_3_,
                      s_Control_plane_is_close__Northbou_18002a1a4._56_5_);
        *(undefined8 *)(&stack0x0002a420 + lVar8) =
             s_Control_plane_is_close__Northbou_18002a1a4._32_8_;
        *(undefined8 *)(&stack0x0002a428 + lVar8) =
             s_Control_plane_is_close__Northbou_18002a1a4._40_8_;
        *(undefined8 *)(&stack0x0002a410 + lVar8) =
             s_Control_plane_is_close__Northbou_18002a1a4._16_8_;
        *(undefined8 *)(&stack0x0002a418 + lVar8) =
             s_Control_plane_is_close__Northbou_18002a1a4._24_8_;
        *(undefined8 *)(&stack0x0002a400 + lVar8) =
             s_Control_plane_is_close__Northbou_18002a1a4._0_8_;
        *(undefined8 *)(&stack0x0002a408 + lVar8) =
             s_Control_plane_is_close__Northbou_18002a1a4._8_8_;
      }
    }
    else {
      *(ulonglong *)(&stack0x0002a43e + lVar8) =
           CONCAT62(s_Shadow_lineage_is_mostly_stable__18002a156._64_6_,
                    s_Shadow_lineage_is_mostly_stable__18002a156._62_2_);
      *(undefined8 *)(&stack0x0002a446 + lVar8) =
           s_Shadow_lineage_is_mostly_stable__18002a156._70_8_;
      *(undefined8 *)(&stack0x0002a430 + lVar8) =
           s_Shadow_lineage_is_mostly_stable__18002a156._48_8_;
      *(ulonglong *)(&stack0x0002a438 + lVar8) =
           CONCAT26(s_Shadow_lineage_is_mostly_stable__18002a156._62_2_,
                    s_Shadow_lineage_is_mostly_stable__18002a156._56_6_);
      *(undefined8 *)(&stack0x0002a420 + lVar8) =
           s_Shadow_lineage_is_mostly_stable__18002a156._32_8_;
      *(undefined8 *)(&stack0x0002a428 + lVar8) =
           s_Shadow_lineage_is_mostly_stable__18002a156._40_8_;
      *(undefined8 *)(&stack0x0002a410 + lVar8) =
           s_Shadow_lineage_is_mostly_stable__18002a156._16_8_;
      *(undefined8 *)(&stack0x0002a418 + lVar8) =
           s_Shadow_lineage_is_mostly_stable__18002a156._24_8_;
      *(undefined8 *)(&stack0x0002a400 + lVar8) = s_Shadow_lineage_is_mostly_stable__18002a156._0_8_
      ;
      *(undefined8 *)(&stack0x0002a408 + lVar8) = s_Shadow_lineage_is_mostly_stable__18002a156._8_8_
      ;
    }
  }
  else {
    *(undefined8 *)(&stack0x0002a430 + lVar8) = s_Visible_topology_converges__but_s_18002a10e._48_8_
    ;
    *(undefined8 *)(&stack0x0002a438 + lVar8) = s_Visible_topology_converges__but_s_18002a10e._56_8_
    ;
    *(undefined8 *)(&stack0x0002a420 + lVar8) = s_Visible_topology_converges__but_s_18002a10e._32_8_
    ;
    *(undefined8 *)(&stack0x0002a428 + lVar8) = s_Visible_topology_converges__but_s_18002a10e._40_8_
    ;
    *(undefined8 *)(&stack0x0002a410 + lVar8) = s_Visible_topology_converges__but_s_18002a10e._16_8_
    ;
    *(undefined8 *)(&stack0x0002a418 + lVar8) = s_Visible_topology_converges__but_s_18002a10e._24_8_
    ;
    *(undefined8 *)(&stack0x0002a400 + lVar8) = s_Visible_topology_converges__but_s_18002a10e._0_8_;
    *(undefined8 *)(&stack0x0002a408 + lVar8) = s_Visible_topology_converges__but_s_18002a10e._8_8_;
    *(undefined8 *)(&stack0x0002a440 + lVar8) = 0x2e737466697264;
  }
  pcVar23 = "false";
LAB_18000537e:
  uVar6 = *(undefined4 *)(&stack0x0002a6bc + lVar8);
  *(int *)(&stack0x00000040 + lVar8) = iVar5;
  *(int *)(&stack0x00000038 + lVar8) = iVar4;
  *(int *)(&stack0x00000030 + lVar8) = iVar3;
  *(int *)(&stack0x00000028 + lVar8) = iVar21;
  *(int *)((longlong)aiStackX_8 + lVar8 + 0x18) = iVar20;
  *(int *)((longlong)aiStackX_8 + lVar8 + 0x10) = iVar19;
  *(int *)((longlong)aiStackX_8 + lVar8 + 8) = iVar18;
  *(int *)((longlong)aiStackX_8 + lVar8) = iVar13;
  *(int *)((longlong)aiStackX_8 + lVar8 + -8) = iVar11;
  *(undefined1 **)(&stack0xfffffffffffffff8 + lVar8) = &stack0x0002a5c0 + lVar8;
  *(undefined1 **)(&stack0xfffffffffffffff0 + lVar8) = puVar38;
  *(int *)(&stack0xffffffffffffffe8 + lVar8) = iVar45;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar8) = uVar6;
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800053ee;
  FUN_180006c70(&stack0x00029e50 + lVar8,0x578,
                "{\"ok\":%s,\"score\":%d,\"signature\":%d,\"summary\":\"%s\",\"flag\":\"%s\",\"manifest\":%d,\"edges\":%d,\"meta\":%d,\"shadow\":%d,\"specter\":%d,\"vm\":%d,\"vm2\":%d,\"vm3\":%d,\"vm4\":%d}"
                ,pcVar23);
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x1800053f6;
  lVar29 = FUN_180006ce0((longlong)(&stack0x00029e50 + lVar8));
  *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x180005405;
  puVar28 = malloc(lVar29 + 1U);
  if (puVar28 != (undefined8 *)0x0) {
    *(undefined8 *)((longlong)&uStack_48 + lVar8) = 0x18000541f;
    FUN_180007c10(puVar28,(undefined8 *)(&stack0x00029e50 + lVar8),lVar29 + 1U);
  }
  return puVar28;
code_r0x00018000236f:
  pcVar51 = pcVar51 + 0x228;
  pbVar49 = pbVar49 + 0x228;
  pbVar59 = pbVar59 + 0x228;
  lVar25 = lVar25 + -1;
  if (lVar25 == 0) goto LAB_1800022a0;
  goto LAB_180002360;
LAB_1800041b0:
  pcVar27 = pcVar27 + 0x104;
  pbVar49 = pbVar49 + 0x104;
  pbVar59 = pbVar59 + 0x104;
  lVar25 = lVar25 + -1;
  if (lVar25 == 0) goto LAB_1800040e2;
  goto LAB_1800041cf;
}
