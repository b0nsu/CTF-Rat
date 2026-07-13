
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 * validate_cluster(char *param_1)

{
  longlong *plVar1;
  undefined4 uVar2;
  size_t sVar3;
  ushort uVar4;
  longlong lVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  ulonglong uVar14;
  char *pcVar15;
  char *pcVar16;
  longlong lVar17;
  longlong lVar18;
  longlong lVar19;
  ulonglong uVar20;
  undefined4 extraout_var;
  undefined4 extraout_var_00;
  undefined4 extraout_var_01;
  undefined4 extraout_var_02;
  undefined4 extraout_var_03;
  char *pcVar21;
  undefined8 *puVar22;
  ulonglong uVar23;
  char cVar24;
  uint uVar25;
  uint uVar26;
  uint uVar27;
  ulonglong uVar28;
  undefined1 *puVar29;
  uint uVar30;
  byte *pbVar31;
  byte bVar32;
  char *pcVar33;
  undefined4 *puVar34;
  undefined1 *puVar35;
  ulonglong uVar36;
  byte *pbVar37;
  byte *pbVar38;
  ulonglong uVar39;
  uint uVar40;
  longlong lVar41;
  char *pcVar42;
  uint uVar43;
  uint uVar44;
  char *pcVar45;
  ulonglong uVar46;
  code *pcVar47;
  int iVar48;
  undefined8 uVar49;
  int iVar50;
  uint uVar51;
  byte bVar52;
  undefined1 auVar53 [16];
  undefined1 auVar54 [16];
  undefined1 auVar55 [16];
  undefined8 unaff_XMM6_Qa;
  undefined8 unaff_XMM6_Qb;
  undefined1 auVar56 [16];
  undefined1 auVar57 [16];
  int aiStackX_8 [8];
  undefined8 uStack_48;

                    /* 0x1000  5  validate_cluster */
  uStack_48 = 0x180001016;
  uVar14 = FUN_180008030();
  lVar5 = -uVar14;
  pcVar42 = &stack0x00000040 + lVar5;
  *(undefined8 *)(&stack0x000220c0 + lVar5) = unaff_XMM6_Qa;
  *(undefined8 *)(&stack0x000220c8 + lVar5) = unaff_XMM6_Qb;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001037;
  pcVar15 = strstr(param_1,"\"nodes\":[");
  uVar14 = 0;
  if (pcVar15 != (char *)0x0) {
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001052;
    pcVar15 = strchr(pcVar15,0x5b);
    uVar14 = 0;
    if (pcVar15 != (char *)0x0) {
      *(char **)(&stack0x000220b8 + lVar5) = param_1;
      puVar35 = &stack0x00010440 + lVar5;
      *(undefined8 *)(&stack0x000220b0 + lVar5) = 0;
      pcVar21 = &stack0x00021840 + lVar5;
      while ((pcVar15[1] != '\0' && (pcVar15[1] != ']'))) {
        if (*(longlong *)(&stack0x000220b0 + lVar5) == 0x80) {
          uVar14 = 0x80;
          goto LAB_180001821;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800010f4;
        pcVar16 = strchr(pcVar15 + 1,0x7b);
        if (pcVar16 == (char *)0x0) break;
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000110d;
        pcVar15 = strchr(pcVar16,0x7d);
        if (pcVar15 == (char *)0x0) break;
        pcVar45 = pcVar15 + (1 - (longlong)pcVar16);
        if ((char *)0x3fe < pcVar45) {
          pcVar45 = (char *)0x3ff;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001141;
        FUN_180007e80((undefined8 *)pcVar42,(undefined8 *)pcVar16,(ulonglong)pcVar45);
        pcVar42[(longlong)pcVar45] = '\0';
        lVar19 = *(longlong *)(&stack0x000220b0 + lVar5);
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001178;
        FUN_180006ee0(pcVar21,0x40,"\"%s\":\"",&DAT_18002b24f);
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001183;
        pcVar16 = strstr(pcVar42,pcVar21);
        if (pcVar16 == (char *)0x0) {
          pcVar42[lVar19 * 0x228 + 0x10400] = '\0';
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001197;
          lVar17 = FUN_180006f50((longlong)pcVar21);
          lVar18 = 1;
          for (pcVar16 = pcVar16 + lVar17; (cVar24 = *pcVar16, cVar24 != '\0' && (cVar24 != '\"'));
              pcVar16 = pcVar16 + 1) {
            pcVar45 = pcVar16;
            if (cVar24 == '\\') {
              pcVar45 = pcVar16 + 1;
              cVar24 = pcVar16[1];
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar45 = pcVar16;
              }
            }
            puVar35[lVar18 + -1] = cVar24;
            cVar24 = pcVar45[1];
            if ((cVar24 == '\0') || (cVar24 == '\"')) goto LAB_180001240;
            if (lVar18 == 0x3f) {
              lVar18 = 0x3f;
              goto LAB_180001240;
            }
            pcVar16 = pcVar45 + 1;
            if (cVar24 == '\\') {
              cVar24 = pcVar45[2];
              pcVar16 = pcVar45 + 2;
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar16 = pcVar45 + 1;
              }
            }
            puVar35[lVar18] = cVar24;
            lVar18 = lVar18 + 2;
          }
          lVar18 = lVar18 + -1;
LAB_180001240:
          (pcVar42 + lVar19 * 0x228 + 0x10400)[lVar18] = '\0';
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001260;
        FUN_180006ee0(pcVar21,0x40,"\"%s\":\"",&DAT_18002b252);
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000126b;
        pcVar16 = strstr(pcVar42,pcVar21);
        if (pcVar16 == (char *)0x0) {
          pcVar42[lVar19 * 0x228 + 0x10440] = '\0';
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000127f;
          lVar17 = FUN_180006f50((longlong)pcVar21);
          pcVar16 = pcVar16 + lVar17;
          lVar17 = 0;
          while( true ) {
            cVar24 = *pcVar16;
            if ((cVar24 == '\0') || (cVar24 == '\"')) goto LAB_180001320;
            pcVar45 = pcVar16;
            if (cVar24 == '\\') {
              pcVar45 = pcVar16 + 1;
              cVar24 = pcVar16[1];
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar45 = pcVar16;
              }
            }
            puVar35[lVar17 + 0x40] = cVar24;
            cVar24 = pcVar45[1];
            if ((cVar24 == '\0') || (cVar24 == '\"')) break;
            if (lVar17 == 0x1e) {
              lVar17 = 0x1f;
              goto LAB_180001320;
            }
            pcVar16 = pcVar45 + 1;
            if (cVar24 == '\\') {
              cVar24 = pcVar45[2];
              pcVar16 = pcVar45 + 2;
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar16 = pcVar45 + 1;
              }
            }
            pcVar16 = pcVar16 + 1;
            puVar35[lVar17 + 0x41] = cVar24;
            lVar17 = lVar17 + 2;
          }
          lVar17 = lVar17 + 1;
LAB_180001320:
          pcVar42[lVar17 + lVar19 * 0x228 + 0x10440] = '\0';
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001341;
        FUN_180006ee0(pcVar21,0x40,"\"%s\":\"",&DAT_18002b257);
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000134c;
        pcVar16 = strstr(pcVar42,pcVar21);
        if (pcVar16 == (char *)0x0) {
          pcVar42[lVar19 * 0x228 + 0x10460] = '\0';
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001360;
          lVar17 = FUN_180006f50((longlong)pcVar21);
          pcVar16 = pcVar16 + lVar17;
          lVar17 = 0;
          while( true ) {
            cVar24 = *pcVar16;
            if ((cVar24 == '\0') || (cVar24 == '\"')) goto LAB_180001400;
            pcVar45 = pcVar16;
            if (cVar24 == '\\') {
              pcVar45 = pcVar16 + 1;
              cVar24 = pcVar16[1];
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar45 = pcVar16;
              }
            }
            puVar35[lVar17 + 0x60] = cVar24;
            cVar24 = pcVar45[1];
            if ((cVar24 == '\0') || (cVar24 == '\"')) break;
            if (lVar17 == 0x3e) {
              lVar17 = 0x3f;
              goto LAB_180001400;
            }
            pcVar16 = pcVar45 + 1;
            if (cVar24 == '\\') {
              cVar24 = pcVar45[2];
              pcVar16 = pcVar45 + 2;
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar16 = pcVar45 + 1;
              }
            }
            pcVar16 = pcVar16 + 1;
            puVar35[lVar17 + 0x61] = cVar24;
            lVar17 = lVar17 + 2;
          }
          lVar17 = lVar17 + 1;
LAB_180001400:
          pcVar42[lVar17 + lVar19 * 0x228 + 0x10460] = '\0';
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001421;
        FUN_180006ee0(pcVar21,0x40,"\"%s\":\"","namespace");
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000142c;
        pcVar16 = strstr(pcVar42,pcVar21);
        if (pcVar16 == (char *)0x0) {
          pcVar42[lVar19 * 0x228 + 0x104a0] = '\0';
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001440;
          lVar17 = FUN_180006f50((longlong)pcVar21);
          pcVar16 = pcVar16 + lVar17;
          lVar17 = 0;
          while( true ) {
            cVar24 = *pcVar16;
            if ((cVar24 == '\0') || (cVar24 == '\"')) goto LAB_1800014e0;
            pcVar45 = pcVar16;
            if (cVar24 == '\\') {
              pcVar45 = pcVar16 + 1;
              cVar24 = pcVar16[1];
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar45 = pcVar16;
              }
            }
            puVar35[lVar17 + 0xa0] = cVar24;
            cVar24 = pcVar45[1];
            if ((cVar24 == '\0') || (cVar24 == '\"')) break;
            if (lVar17 == 0x3e) {
              lVar17 = 0x3f;
              goto LAB_1800014e0;
            }
            pcVar16 = pcVar45 + 1;
            if (cVar24 == '\\') {
              cVar24 = pcVar45[2];
              pcVar16 = pcVar45 + 2;
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar16 = pcVar45 + 1;
              }
            }
            pcVar16 = pcVar16 + 1;
            puVar35[lVar17 + 0xa1] = cVar24;
            lVar17 = lVar17 + 2;
          }
          lVar17 = lVar17 + 1;
LAB_1800014e0:
          pcVar42[lVar17 + lVar19 * 0x228 + 0x104a0] = '\0';
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001504;
        FUN_180006ee0(pcVar21,0x40,"\"%s\":\"","labels");
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000150f;
        pcVar16 = strstr(pcVar42,pcVar21);
        if (pcVar16 == (char *)0x0) {
          pcVar42[lVar19 * 0x228 + 0x104e0] = '\0';
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001523;
          lVar17 = FUN_180006f50((longlong)pcVar21);
          pcVar16 = pcVar16 + lVar17;
          lVar17 = 0;
          while( true ) {
            cVar24 = *pcVar16;
            if ((cVar24 == '\0') || (cVar24 == '\"')) goto LAB_1800015c0;
            pcVar45 = pcVar16;
            if (cVar24 == '\\') {
              pcVar45 = pcVar16 + 1;
              cVar24 = pcVar16[1];
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar45 = pcVar16;
              }
            }
            puVar35[lVar17 + 0xe0] = cVar24;
            cVar24 = pcVar45[1];
            if ((cVar24 == '\0') || (cVar24 == '\"')) break;
            if (lVar17 == 0x7e) {
              lVar17 = 0x7f;
              goto LAB_1800015c0;
            }
            pcVar16 = pcVar45 + 1;
            if (cVar24 == '\\') {
              cVar24 = pcVar45[2];
              pcVar16 = pcVar45 + 2;
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar16 = pcVar45 + 1;
              }
            }
            pcVar16 = pcVar16 + 1;
            puVar35[lVar17 + 0xe1] = cVar24;
            lVar17 = lVar17 + 2;
          }
          lVar17 = lVar17 + 1;
LAB_1800015c0:
          pcVar42[lVar17 + lVar19 * 0x228 + 0x104e0] = '\0';
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800015e4;
        FUN_180006ee0(pcVar21,0x40,"\"%s\":\"","selector");
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800015ef;
        pcVar16 = strstr(pcVar42,pcVar21);
        if (pcVar16 == (char *)0x0) {
          pcVar42[lVar19 * 0x228 + 0x10560] = '\0';
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001603;
          lVar17 = FUN_180006f50((longlong)pcVar21);
          pcVar16 = pcVar16 + lVar17;
          lVar17 = 0;
          while( true ) {
            cVar24 = *pcVar16;
            if ((cVar24 == '\0') || (cVar24 == '\"')) goto LAB_1800016a0;
            pcVar45 = pcVar16;
            if (cVar24 == '\\') {
              pcVar45 = pcVar16 + 1;
              cVar24 = pcVar16[1];
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar45 = pcVar16;
              }
            }
            puVar35[lVar17 + 0x160] = cVar24;
            cVar24 = pcVar45[1];
            if ((cVar24 == '\0') || (cVar24 == '\"')) break;
            if (lVar17 == 0x7e) {
              lVar17 = 0x7f;
              goto LAB_1800016a0;
            }
            pcVar16 = pcVar45 + 1;
            if (cVar24 == '\\') {
              cVar24 = pcVar45[2];
              pcVar16 = pcVar45 + 2;
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar16 = pcVar45 + 1;
              }
            }
            pcVar16 = pcVar16 + 1;
            puVar35[lVar17 + 0x161] = cVar24;
            lVar17 = lVar17 + 2;
          }
          lVar17 = lVar17 + 1;
LAB_1800016a0:
          pcVar42[lVar17 + lVar19 * 0x228 + 0x10560] = '\0';
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800016c4;
        FUN_180006ee0(pcVar21,0x40,"\"%s\":\"","mount");
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800016cf;
        pcVar16 = strstr(pcVar42,pcVar21);
        if (pcVar16 == (char *)0x0) {
          pcVar42[lVar19 * 0x228 + 0x105e0] = '\0';
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800016e3;
          lVar17 = FUN_180006f50((longlong)pcVar21);
          pcVar16 = pcVar16 + lVar17;
          lVar17 = 0;
          while( true ) {
            cVar24 = *pcVar16;
            if ((cVar24 == '\0') || (cVar24 == '\"')) goto LAB_180001780;
            pcVar45 = pcVar16;
            if (cVar24 == '\\') {
              pcVar45 = pcVar16 + 1;
              cVar24 = pcVar16[1];
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar45 = pcVar16;
              }
            }
            puVar35[lVar17 + 0x1e0] = cVar24;
            cVar24 = pcVar45[1];
            if ((cVar24 == '\0') || (cVar24 == '\"')) break;
            if (lVar17 == 0x3e) {
              lVar17 = 0x3f;
              goto LAB_180001780;
            }
            pcVar16 = pcVar45 + 1;
            if (cVar24 == '\\') {
              cVar24 = pcVar45[2];
              pcVar16 = pcVar45 + 2;
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar16 = pcVar45 + 1;
              }
            }
            pcVar16 = pcVar16 + 1;
            puVar35[lVar17 + 0x1e1] = cVar24;
            lVar17 = lVar17 + 2;
          }
          lVar17 = lVar17 + 1;
LAB_180001780:
          pcVar42[lVar17 + lVar19 * 0x228 + 0x105e0] = '\0';
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800017a4;
        FUN_180006ee0(pcVar21,0x40,"\"%s\":","replicas");
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800017af;
        pcVar16 = strstr(pcVar42,pcVar21);
        if (pcVar16 == (char *)0x0) {
          iVar6 = 1;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800017bf;
          lVar17 = FUN_180006f50((longlong)pcVar21);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800017ca;
          iVar6 = atoi(pcVar16 + lVar17);
        }
        *(int *)(pcVar42 + lVar19 * 0x228 + 0x10620) = iVar6;
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800017f8;
        FUN_180006ee0(pcVar21,0x40,"\"%s\":",&DAT_18002b285);
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001803;
        pcVar16 = strstr(pcVar42,pcVar21);
        if (pcVar16 == (char *)0x0) {
          iVar6 = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000109b;
          lVar17 = FUN_180006f50((longlong)pcVar21);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800010a6;
          iVar6 = atoi(pcVar16 + lVar17);
        }
        *(int *)(pcVar42 + lVar19 * 0x228 + 0x10624) = iVar6;
        *(longlong *)(&stack0x000220b0 + lVar5) = *(longlong *)(&stack0x000220b0 + lVar5) + 1;
        puVar35 = puVar35 + 0x228;
      }
      uVar14 = *(ulonglong *)(&stack0x000220b0 + lVar5);
LAB_180001821:
      param_1 = *(char **)(&stack0x000220b8 + lVar5);
    }
  }
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001837;
  pcVar15 = strstr(param_1,"\"edges\":[");
  *(ulonglong *)(&stack0x000220b0 + lVar5) = uVar14;
  if (pcVar15 == (char *)0x0) {
    uVar36 = 0;
  }
  else {
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001857;
    pcVar15 = strchr(pcVar15,0x5b);
    uVar36 = 0;
    if (pcVar15 != (char *)0x0) {
      *(undefined8 *)(&stack0x00022090 + lVar5) = 0;
      pcVar21 = &stack0x00021cf0 + lVar5;
      pcVar16 = pcVar42;
      while ((pcVar15[1] != '\0' && (pcVar15[1] != ']'))) {
        if (*(longlong *)(&stack0x00022090 + lVar5) == 0x100) {
          uVar36 = 0x100;
          goto LAB_180001d45;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800018f8;
        pcVar15 = strchr(pcVar15 + 1,0x7b);
        if (pcVar15 == (char *)0x0) break;
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001911;
        pcVar45 = strchr(pcVar15,0x7d);
        if (pcVar45 == (char *)0x0) break;
        *(char **)(&stack0x000220b8 + lVar5) = pcVar45;
        pcVar45 = pcVar45 + (1 - (longlong)pcVar15);
        if ((char *)0x2fe < pcVar45) {
          pcVar45 = (char *)0x2ff;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001950;
        FUN_180007e80((undefined8 *)(&stack0x00021840 + lVar5),(undefined8 *)pcVar15,
                      (ulonglong)pcVar45);
        (&stack0x00021840)[(longlong)pcVar45 + lVar5] = 0;
        pcVar45 = pcVar42 + *(longlong *)(&stack0x00022090 + lVar5) * 0x104;
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001989;
        FUN_180006ee0(pcVar21,0x40,"\"%s\":\"","source_id");
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001994;
        pcVar15 = strstr(&stack0x00021840 + lVar5,pcVar21);
        if (pcVar15 == (char *)0x0) {
          *pcVar45 = '\0';
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800019a8;
          lVar19 = FUN_180006f50((longlong)pcVar21);
          lVar17 = 1;
          for (pcVar15 = pcVar15 + lVar19; (cVar24 = *pcVar15, cVar24 != '\0' && (cVar24 != '\"'));
              pcVar15 = pcVar15 + 1) {
            pcVar33 = pcVar15;
            if (cVar24 == '\\') {
              pcVar33 = pcVar15 + 1;
              cVar24 = pcVar15[1];
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar33 = pcVar15;
              }
            }
            pcVar16[lVar17 + -1] = cVar24;
            cVar24 = pcVar33[1];
            if ((cVar24 == '\0') || (cVar24 == '\"')) goto LAB_180001a50;
            if (lVar17 == 0x3f) {
              lVar17 = 0x3f;
              goto LAB_180001a50;
            }
            pcVar15 = pcVar33 + 1;
            if (cVar24 == '\\') {
              cVar24 = pcVar33[2];
              pcVar15 = pcVar33 + 2;
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar15 = pcVar33 + 1;
              }
            }
            pcVar16[lVar17] = cVar24;
            lVar17 = lVar17 + 2;
          }
          lVar17 = lVar17 + -1;
LAB_180001a50:
          pcVar45[lVar17] = '\0';
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001a6c;
        FUN_180006ee0(pcVar21,0x40,"\"%s\":\"","target_id");
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001a7b;
        pcVar15 = strstr(&stack0x00021840 + lVar5,pcVar21);
        if (pcVar15 == (char *)0x0) {
          pcVar45[0x40] = '\0';
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001a8f;
          lVar19 = FUN_180006f50((longlong)pcVar21);
          lVar17 = 1;
          for (pcVar15 = pcVar15 + lVar19; (cVar24 = *pcVar15, cVar24 != '\0' && (cVar24 != '\"'));
              pcVar15 = pcVar15 + 1) {
            pcVar33 = pcVar15;
            if (cVar24 == '\\') {
              pcVar33 = pcVar15 + 1;
              cVar24 = pcVar15[1];
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar33 = pcVar15;
              }
            }
            pcVar16[lVar17 + 0x3f] = cVar24;
            cVar24 = pcVar33[1];
            if ((cVar24 == '\0') || (cVar24 == '\"')) goto LAB_180001b30;
            if (lVar17 == 0x3f) {
              lVar17 = 0x3f;
              goto LAB_180001b30;
            }
            pcVar15 = pcVar33 + 1;
            if (cVar24 == '\\') {
              cVar24 = pcVar33[2];
              pcVar15 = pcVar33 + 2;
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar15 = pcVar33 + 1;
              }
            }
            pcVar16[lVar17 + 0x40] = cVar24;
            lVar17 = lVar17 + 2;
          }
          lVar17 = lVar17 + -1;
LAB_180001b30:
          pcVar45[lVar17 + 0x40] = '\0';
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001b4d;
        FUN_180006ee0(pcVar21,0x40,"\"%s\":\"","binding");
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001b5c;
        pcVar15 = strstr(&stack0x00021840 + lVar5,pcVar21);
        if (pcVar15 == (char *)0x0) {
          pcVar45[0x80] = '\0';
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001b70;
          lVar19 = FUN_180006f50((longlong)pcVar21);
          pcVar15 = pcVar15 + lVar19;
          lVar19 = 0;
          while( true ) {
            cVar24 = *pcVar15;
            if ((cVar24 == '\0') || (cVar24 == '\"')) goto LAB_180001c10;
            pcVar33 = pcVar15;
            if (cVar24 == '\\') {
              pcVar33 = pcVar15 + 1;
              cVar24 = pcVar15[1];
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar33 = pcVar15;
              }
            }
            pcVar16[lVar19 + 0x80] = cVar24;
            cVar24 = pcVar33[1];
            if ((cVar24 == '\0') || (cVar24 == '\"')) break;
            if (lVar19 == 0x3e) {
              lVar19 = 0x3f;
              goto LAB_180001c10;
            }
            pcVar15 = pcVar33 + 1;
            if (cVar24 == '\\') {
              cVar24 = pcVar33[2];
              pcVar15 = pcVar33 + 2;
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar15 = pcVar33 + 1;
              }
            }
            pcVar15 = pcVar15 + 1;
            pcVar16[lVar19 + 0x81] = cVar24;
            lVar19 = lVar19 + 2;
          }
          lVar19 = lVar19 + 1;
LAB_180001c10:
          pcVar45[lVar19 + 0x80] = '\0';
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001c30;
        FUN_180006ee0(pcVar21,0x40,"\"%s\":\"",&DAT_18002b2bd);
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001c3f;
        pcVar15 = strstr(&stack0x00021840 + lVar5,pcVar21);
        if (pcVar15 == (char *)0x0) {
          pcVar45[0xc0] = '\0';
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001c53;
          lVar19 = FUN_180006f50((longlong)pcVar21);
          pcVar15 = pcVar15 + lVar19;
          lVar19 = 0;
          while( true ) {
            cVar24 = *pcVar15;
            if ((cVar24 == '\0') || (cVar24 == '\"')) goto LAB_180001cf0;
            pcVar33 = pcVar15;
            if (cVar24 == '\\') {
              pcVar33 = pcVar15 + 1;
              cVar24 = pcVar15[1];
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar33 = pcVar15;
              }
            }
            pcVar16[lVar19 + 0xc0] = cVar24;
            cVar24 = pcVar33[1];
            if ((cVar24 == '\0') || (cVar24 == '\"')) break;
            if (lVar19 == 0x3e) {
              lVar19 = 0x3f;
              goto LAB_180001cf0;
            }
            pcVar15 = pcVar33 + 1;
            if (cVar24 == '\\') {
              cVar24 = pcVar33[2];
              pcVar15 = pcVar33 + 2;
              if (cVar24 == '\0') {
                cVar24 = '\\';
                pcVar15 = pcVar33 + 1;
              }
            }
            pcVar15 = pcVar15 + 1;
            pcVar16[lVar19 + 0xc1] = cVar24;
            lVar19 = lVar19 + 2;
          }
          lVar19 = lVar19 + 1;
LAB_180001cf0:
          pcVar45[lVar19 + 0xc0] = '\0';
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001d14;
        FUN_180006ee0(pcVar21,0x40,"\"%s\":",&DAT_18002b285);
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001d23;
        pcVar15 = strstr(&stack0x00021840 + lVar5,pcVar21);
        if (pcVar15 == (char *)0x0) {
          iVar6 = 0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000189b;
          lVar19 = FUN_180006f50((longlong)pcVar21);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800018a6;
          iVar6 = atoi(pcVar15 + lVar19);
        }
        pcVar15 = *(char **)(&stack0x000220b8 + lVar5);
        *(int *)(pcVar45 + 0x100) = iVar6;
        *(longlong *)(&stack0x00022090 + lVar5) = *(longlong *)(&stack0x00022090 + lVar5) + 1;
        pcVar16 = pcVar16 + 0x104;
      }
      uVar36 = *(ulonglong *)(&stack0x00022090 + lVar5);
LAB_180001d45:
      uVar14 = *(ulonglong *)(&stack0x000220b0 + lVar5);
    }
  }
  *(ulonglong *)(&stack0x00022088 + lVar5) = uVar14 & 0xffffffff;
  *(ulonglong *)(&stack0x00022060 + lVar5) = uVar36 & 0xffffffff;
  *(ulonglong *)(&stack0x00022090 + lVar5) = uVar36;
  if ((int)uVar14 < 1) {
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800026b1;
    qsort(&stack0x00021cf0 + lVar5,(longlong)(int)uVar14,4,FUN_180005ae0);
    uVar30 = 0x345678;
    *(undefined4 *)(&stack0x00021fdc + lVar5) = 0;
    *(undefined4 *)(&stack0x00022054 + lVar5) = 0;
    *(undefined4 *)(&stack0x00021fa0 + lVar5) = 0;
    *(undefined4 *)(&stack0x00022038 + lVar5) = 0;
    *(undefined4 *)(&stack0x00021fa4 + lVar5) = 0;
    *(undefined4 *)(&stack0x00021fa8 + lVar5) = 0;
    *(undefined4 *)(&stack0x00021fac + lVar5) = 0;
    *(undefined4 *)(&stack0x00022034 + lVar5) = 0;
    uVar39 = 0;
    *(undefined8 *)(&stack0x00021fc8 + lVar5) = 0;
    *(undefined4 *)(&stack0x00022030 + lVar5) = 0;
    *(undefined8 *)(&stack0x00021f98 + lVar5) = 0;
    *(undefined8 *)(&stack0x00021fc0 + lVar5) = 0;
    *(undefined8 *)(&stack0x00021f58 + lVar5) = 0;
    *(undefined4 *)(&stack0x0002202c + lVar5) = 0;
  }
  else {
    pbVar37 = &stack0x00010481 + lVar5;
    *(undefined1 **)(&stack0x00022000 + lVar5) = &stack0x000104a1 + lVar5;
    *(undefined1 **)(&stack0x00022040 + lVar5) = &stack0x000104e1 + lVar5;
    *(undefined1 **)(&stack0x00022048 + lVar5) = &stack0x00010521 + lVar5;
    *(undefined1 **)(&stack0x00021fe8 + lVar5) = &stack0x000105a1 + lVar5;
    *(undefined1 **)(&stack0x00022008 + lVar5) = &stack0x00010621 + lVar5;
    lVar19 = 0;
    *(undefined4 *)(&stack0x00021fdc + lVar5) = 0;
    *(undefined4 *)(&stack0x00022054 + lVar5) = 0;
    *(undefined8 *)(&stack0x00021fb8 + lVar5) = 0;
    *(undefined4 *)(&stack0x00022038 + lVar5) = 0;
    *(undefined8 *)(&stack0x00022020 + lVar5) = 0;
    *(undefined8 *)(&stack0x00022018 + lVar5) = 0;
    *(undefined8 *)(&stack0x00022010 + lVar5) = 0;
    *(undefined4 *)(&stack0x00022034 + lVar5) = 0;
    uVar39 = 0;
    *(undefined8 *)(&stack0x00021fc8 + lVar5) = 0;
    *(undefined4 *)(&stack0x00022030 + lVar5) = 0;
    *(undefined8 *)(&stack0x00021f98 + lVar5) = 0;
    *(undefined8 *)(&stack0x00021fc0 + lVar5) = 0;
    uVar46 = 0;
    *(undefined4 *)(&stack0x0002202c + lVar5) = 0;
    do {
      *(ulonglong *)(&stack0x00022058 + lVar5) = uVar46;
      *(int *)(&stack0x00022068 + lVar5) = (int)uVar39;
      *(longlong *)(&stack0x000220a0 + lVar5) = lVar19;
      lVar19 = lVar19 * 0x228;
      bVar52 = (&stack0x00010480)[lVar19 + lVar5];
      uVar14 = 0x11c9dc5;
      if (bVar52 != 0) {
        *(longlong *)(&stack0x000220b8 + lVar5) = lVar19;
        uVar30 = 0x811c9dc5;
        pbVar31 = pbVar37;
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001f28;
          uVar7 = tolower((uint)bVar52);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001f30;
          iVar6 = isalnum((uint)bVar52);
          uVar25 = (uVar7 & 0xff ^ uVar30) * 0x1000193;
          if ((uVar7 & 0xff) == 0x5f) {
            uVar30 = uVar25;
          }
          if ((uVar7 & 0xef) == 0x2d) {
            uVar30 = uVar25;
          }
          if (iVar6 != 0) {
            uVar30 = uVar25;
          }
          bVar52 = *pbVar31;
          pbVar31 = pbVar31 + 1;
        } while (bVar52 != 0);
        uVar14 = (ulonglong)(uVar30 & 0x7fffffff);
        lVar19 = *(longlong *)(&stack0x000220b8 + lVar5);
      }
      uVar36 = 0x11c9dc5;
      *(ulonglong *)(&stack0x00022078 + lVar5) = uVar14;
      pcVar15 = pcVar42 + lVar19 + 0x10400;
      bVar52 = pcVar42[lVar19 + 0x10460];
      *(char **)(&stack0x000220b8 + lVar5) = pcVar15;
      if (bVar52 != 0) {
        uVar30 = 0x811c9dc5;
        pbVar31 = *(byte **)(&stack0x00022000 + lVar5);
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001fc7;
          uVar7 = tolower((uint)bVar52);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180001fcf;
          iVar6 = isalnum((uint)bVar52);
          uVar25 = (uVar7 & 0xff ^ uVar30) * 0x1000193;
          if ((uVar7 & 0xff) == 0x5f) {
            uVar30 = uVar25;
          }
          if ((uVar7 & 0xef) == 0x2d) {
            uVar30 = uVar25;
          }
          if (iVar6 != 0) {
            uVar30 = uVar25;
          }
          bVar52 = *pbVar31;
          pbVar31 = pbVar31 + 1;
        } while (bVar52 != 0);
        uVar36 = (ulonglong)(uVar30 & 0x7fffffff);
        pcVar15 = *(char **)(&stack0x000220b8 + lVar5);
      }
      *(ulonglong *)(&stack0x000220a8 + lVar5) = uVar36;
      *(byte **)(&stack0x00022080 + lVar5) = pbVar37;
      cVar24 = pcVar15[0xa0];
      uVar7 = 0x11c9dc5;
      uVar30 = 0x11c9dc5;
      (&stack0x00022098)[lVar5] = cVar24;
      if (cVar24 != '\0') {
        uVar30 = 0x811c9dc5;
        pbVar37 = *(byte **)(&stack0x00022040 + lVar5);
        bVar52 = (&stack0x00022098)[lVar5];
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002068;
          uVar25 = tolower((uint)bVar52);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002070;
          iVar6 = isalnum((uint)bVar52);
          uVar26 = (uVar25 & 0xff ^ uVar30) * 0x1000193;
          if ((uVar25 & 0xff) == 0x5f) {
            uVar30 = uVar26;
          }
          if ((uVar25 & 0xef) == 0x2d) {
            uVar30 = uVar26;
          }
          if (iVar6 != 0) {
            uVar30 = uVar26;
          }
          bVar52 = *pbVar37;
          pbVar37 = pbVar37 + 1;
        } while (bVar52 != 0);
        uVar30 = uVar30 & 0x7fffffff;
        pcVar15 = *(char **)(&stack0x000220b8 + lVar5);
      }
      bVar52 = pcVar15[0xe0];
      if (bVar52 != 0) {
        uVar7 = 0x811c9dc5;
        pbVar37 = *(byte **)(&stack0x00022048 + lVar5);
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800020e8;
          uVar25 = tolower((uint)bVar52);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800020f0;
          iVar6 = isalnum((uint)bVar52);
          uVar26 = (uVar25 & 0xff ^ uVar7) * 0x1000193;
          if ((uVar25 & 0xff) == 0x5f) {
            uVar7 = uVar26;
          }
          if ((uVar25 & 0xef) == 0x2d) {
            uVar7 = uVar26;
          }
          if (iVar6 != 0) {
            uVar7 = uVar26;
          }
          bVar52 = *pbVar37;
          pbVar37 = pbVar37 + 1;
        } while (bVar52 != 0);
        uVar7 = uVar7 & 0x7fffffff;
        pcVar15 = *(char **)(&stack0x000220b8 + lVar5);
      }
      bVar52 = pcVar15[0x160];
      uVar26 = 0x11c9dc5;
      uVar25 = 0x11c9dc5;
      if (bVar52 != 0) {
        uVar25 = 0x811c9dc5;
        pbVar37 = *(byte **)(&stack0x00021fe8 + lVar5);
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000216b;
          uVar8 = tolower((uint)bVar52);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002176;
          iVar6 = isalnum((uint)bVar52);
          uVar27 = (uVar8 & 0xff ^ uVar25) * 0x1000193;
          if ((uVar8 & 0xff) == 0x5f) {
            uVar25 = uVar27;
          }
          if ((uVar8 & 0xef) == 0x2d) {
            uVar25 = uVar27;
          }
          if (iVar6 != 0) {
            uVar25 = uVar27;
          }
          bVar52 = *pbVar37;
          pbVar37 = pbVar37 + 1;
        } while (bVar52 != 0);
        uVar25 = uVar25 & 0x7fffffff;
        pcVar15 = *(char **)(&stack0x000220b8 + lVar5);
      }
      bVar52 = pcVar15[0x1e0];
      if (bVar52 != 0) {
        uVar26 = 0x811c9dc5;
        pbVar37 = *(byte **)(&stack0x00022008 + lVar5);
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800021db;
          uVar8 = tolower((uint)bVar52);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800021e6;
          iVar6 = isalnum((uint)bVar52);
          uVar27 = (uVar8 & 0xff ^ uVar26) * 0x1000193;
          if ((uVar8 & 0xff) == 0x5f) {
            uVar26 = uVar27;
          }
          if ((uVar8 & 0xef) == 0x2d) {
            uVar26 = uVar27;
          }
          if (iVar6 != 0) {
            uVar26 = uVar27;
          }
          bVar52 = *pbVar37;
          pbVar37 = pbVar37 + 1;
        } while (bVar52 != 0);
        uVar26 = uVar26 & 0x7fffffff;
        pcVar15 = *(char **)(&stack0x000220b8 + lVar5);
      }
      *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002237;
      uVar8 = FUN_180005900(pcVar15 + 0xe0);
      uVar14 = *(ulonglong *)(&stack0x00022078 + lVar5);
      iVar6 = (int)uVar14;
      if (iVar6 < 0x45334cec) {
        lVar19 = *(longlong *)(&stack0x000220a0 + lVar5);
        if (iVar6 < 0x251b4cfe) {
          if (iVar6 == 0x133c1bd8) {
            *(ulonglong *)(&stack0x00022018 + lVar5) =
                 (ulonglong)((int)*(undefined8 *)(&stack0x00022018 + lVar5) + 1);
          }
          else if (iVar6 == 0x2047d5a7) {
            *(int *)(&stack0x00022034 + lVar5) = *(int *)(&stack0x00022034 + lVar5) + 1;
          }
        }
        else if (iVar6 == 0x251b4cfe) {
          *(ulonglong *)(&stack0x00021fb8 + lVar5) =
               (ulonglong)((int)*(undefined8 *)(&stack0x00021fb8 + lVar5) + 1);
        }
        else if (iVar6 == 0x31c14e0d) {
          *(int *)(&stack0x00022054 + lVar5) = *(int *)(&stack0x00022054 + lVar5) + 1;
        }
      }
      else {
        lVar19 = *(longlong *)(&stack0x000220a0 + lVar5);
        if (iVar6 < 0x56dfde64) {
          if (iVar6 == 0x45334cec) {
            *(int *)(&stack0x00022038 + lVar5) = *(int *)(&stack0x00022038 + lVar5) + 1;
          }
          else if (iVar6 == 0x4ace7aa0) {
            *(int *)(&stack0x00021fdc + lVar5) = *(int *)(&stack0x00021fdc + lVar5) + 1;
          }
        }
        else if (iVar6 == 0x56dfde64) {
          *(ulonglong *)(&stack0x00022020 + lVar5) =
               (ulonglong)((int)*(undefined8 *)(&stack0x00022020 + lVar5) + 1);
        }
        else if (iVar6 == 0x667c6911) {
          *(ulonglong *)(&stack0x00022010 + lVar5) =
               (ulonglong)((int)*(undefined8 *)(&stack0x00022010 + lVar5) + 1);
        }
      }
      iVar9 = *(int *)(pcVar15 + 0x220);
      lVar17 = (longlong)*(int *)(pcVar15 + 0x224);
      uVar36 = *(ulonglong *)(&stack0x000220a8 + lVar5);
      *(uint *)(&stack0x00021cf0 + lVar19 * 4 + lVar5) =
           (*(int *)(pcVar15 + 0x224) << 6 ^
            iVar9 << 5 ^ uVar25 * 8 ^ uVar7 * 4 ^ uVar30 * 2 ^ iVar6 * 0x4e67c6a7 ^ uVar26 << 4) &
           0x7fffffff ^ (uint)uVar36;
      uVar36 = uVar36 & 0xffffffff;
      *(longlong *)(&stack0x00021fe0 + lVar5) = (longlong)iVar9;
      if (iVar6 == 0x45334cec) {
        *(longlong *)(&stack0x00021fd0 + lVar5) = lVar17;
        *(ulonglong *)(&stack0x00021fb0 + lVar5) = uVar36;
        *(ulonglong *)(&stack0x00021ff0 + lVar5) = (ulonglong)uVar8;
        lVar19 = *(longlong *)(&stack0x00022060 + lVar5);
        if (*(int *)(&stack0x00022090 + lVar5) < 1) {
          iVar6 = 0;
        }
        else {
          iVar6 = 0;
          pcVar15 = &stack0x00000080 + lVar5;
          do {
            *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800023ff;
            iVar9 = strcmp(pcVar15,*(char **)(&stack0x000220b8 + lVar5));
            iVar6 = iVar6 + (uint)(iVar9 == 0);
            pcVar15 = pcVar15 + 0x104;
            lVar19 = lVar19 + -1;
          } while (lVar19 != 0);
        }
        *(ulonglong *)(&stack0x00021fc8 + lVar5) =
             (ulonglong)
             ((uint)((int)*(undefined8 *)(&stack0x00021fc8 + lVar5) +
                    (int)*(undefined8 *)(&stack0x000220a8 + lVar5)) % 0xf4243);
        *(uint *)(&stack0x00022030 + lVar5) =
             (uint)((int)*(undefined8 *)(&stack0x00021ff0 + lVar5) +
                   *(int *)(&stack0x00022030 + lVar5)) % 0xf4243;
        uVar36 = *(ulonglong *)(&stack0x00021fb0 + lVar5);
        *(uint *)(&stack0x0002202c + lVar5) =
             (((uint)(uVar36 * 0x151d07eb >> 0x23) * -0x61 +
               (int)*(undefined8 *)(&stack0x000220a8 + lVar5) + 1) * iVar6 +
             *(int *)(&stack0x0002202c + lVar5)) % 0xf4243;
        if (uVar26 != 0) {
          *(ulonglong *)(&stack0x00021f98 + lVar5) =
               (ulonglong)(((int)*(undefined8 *)(&stack0x00021f98 + lVar5) + uVar26) % 0xf4243);
        }
        uVar14 = *(ulonglong *)(&stack0x00022078 + lVar5);
        iVar6 = *(int *)(&stack0x00022068 + lVar5);
        lVar17 = *(longlong *)(&stack0x00021fd0 + lVar5);
      }
      else {
        iVar6 = *(int *)(&stack0x00022068 + lVar5);
      }
      uVar8 = (uint)*(undefined8 *)(&stack0x000220a8 + lVar5) ^ (uint)uVar14;
      if ((&stack0x00022098)[lVar5] != '\0') {
        uVar14 = (ulonglong)
                 ((uint)*(undefined8 *)(&stack0x000220a8 + lVar5) +
                 (uint)(uVar36 * 0x837765f1 >> 0x29) * -0x3e5) +
                 (ulonglong)uVar30 *
                 (ulonglong)
                 ((uint)((uVar14 & 0xffffffff) * 0x84210843 >> 0x24) * -0x1f + (uint)uVar14 + 1);
        auVar54._8_8_ = 0;
        auVar54._0_8_ = uVar14;
        *(ulonglong *)(&stack0x00021fc0 + lVar5) =
             (ulonglong)
             ((uint)((int)*(undefined8 *)(&stack0x00021fc0 + lVar5) +
                    (int)uVar14 + SUB164(auVar54 * ZEXT816(0x10c6f45449cc),8) * -0xf4243) % 0xf4243)
        ;
      }
      uVar36 = *(ulonglong *)(&stack0x00022090 + lVar5);
      uVar14 = *(ulonglong *)(&stack0x000220b0 + lVar5);
      uVar39 = (ulonglong)
               ((uVar8 + (uint)((ulonglong)uVar8 * 0x8637a2a3 >> 0x33) * -0xf4243 + iVar6) % 0xf4243
               );
      uVar46 = (ulonglong)uVar7 * 5 +
               (ulonglong)uVar30 * 3 + *(longlong *)(&stack0x00022058 + lVar5) +
               (ulonglong)uVar25 * 7 + *(longlong *)(&stack0x00021fe0 + lVar5) * 0xd + lVar17 * 0x11
               + (ulonglong)uVar26 * 0xb;
      lVar19 = *(longlong *)(&stack0x000220a0 + lVar5) + 1;
      pbVar37 = (byte *)(*(longlong *)(&stack0x00022080 + lVar5) + 0x228);
      *(longlong *)(&stack0x00022000 + lVar5) = *(longlong *)(&stack0x00022000 + lVar5) + 0x228;
      *(longlong *)(&stack0x00022040 + lVar5) = *(longlong *)(&stack0x00022040 + lVar5) + 0x228;
      *(longlong *)(&stack0x00022048 + lVar5) = *(longlong *)(&stack0x00022048 + lVar5) + 0x228;
      *(longlong *)(&stack0x00021fe8 + lVar5) = *(longlong *)(&stack0x00021fe8 + lVar5) + 0x228;
      *(longlong *)(&stack0x00022008 + lVar5) = *(longlong *)(&stack0x00022008 + lVar5) + 0x228;
    } while (lVar19 != *(longlong *)(&stack0x00022088 + lVar5));
    sVar3 = *(size_t *)(&stack0x00022088 + lVar5);
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002676;
    qsort(&stack0x00021cf0 + lVar5,sVar3,4,FUN_180005ae0);
    uVar20 = (ulonglong)((uint)sVar3 & 3);
    if ((int)uVar14 - 1U < 3) {
      uVar30 = 0x345678;
      uVar23 = 0;
    }
    else {
      uVar30 = 0x345678;
      uVar23 = 0;
      do {
        uVar30 = ((((uVar30 * 0xf4243 ^ *(uint *)(&stack0x00021cf0 + uVar23 * 4 + lVar5)) * 0xf4243
                   ^ *(uint *)(&stack0x00021cf4 + uVar23 * 4 + lVar5)) * 0xf4243 ^
                  *(uint *)(&stack0x00021cf8 + uVar23 * 4 + lVar5)) * 0xf4243 ^
                 *(uint *)(&stack0x00021cfc + uVar23 * 4 + lVar5)) & 0x7fffffff;
        uVar23 = uVar23 + 4;
      } while (((uint)*(undefined8 *)(&stack0x00022088 + lVar5) & 0x7ffffffc) != uVar23);
    }
    if (uVar20 != 0) {
      uVar28 = 0;
      do {
        uVar30 = (uVar30 * 0xf4243 ^ *(uint *)(pcVar42 + uVar28 * 4 + uVar23 * 4 + 0x21cb0)) &
                 0x7fffffff;
        uVar28 = uVar28 + 1;
      } while (uVar20 != uVar28);
    }
    *(int *)(&stack0x00022054 + lVar5) = *(int *)(&stack0x00022054 + lVar5) * 2;
    *(int *)(&stack0x00021fa0 + lVar5) = (int)*(undefined8 *)(&stack0x00021fb8 + lVar5) * 3;
    *(int *)(&stack0x00022038 + lVar5) = *(int *)(&stack0x00022038 + lVar5) << 2;
    *(int *)(&stack0x00021fa4 + lVar5) = (int)*(undefined8 *)(&stack0x00022020 + lVar5) * 5;
    *(int *)(&stack0x00021fa8 + lVar5) = (int)*(undefined8 *)(&stack0x00022018 + lVar5) * 6;
    *(int *)(&stack0x00021fac + lVar5) = (int)*(undefined8 *)(&stack0x00022010 + lVar5) * 7;
    *(int *)(&stack0x00022034 + lVar5) = *(int *)(&stack0x00022034 + lVar5) << 3;
    *(ulonglong *)(&stack0x00021f58 + lVar5) =
         (ulonglong)(uint)((int)uVar46 + (int)(uVar46 / 0x7fffffff) * -0x7fffffff);
  }
  iVar6 = (int)uVar14;
  *(ulonglong *)(&stack0x00021e88 + lVar5) = uVar39;
  *(uint *)(&stack0x00021f94 + lVar5) = uVar30;
  *(uint *)(&stack0x00021ee8 + lVar5) = uVar30;
  if ((int)uVar36 < 1) {
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003501;
    qsort(&stack0x00021840 + lVar5,(longlong)(int)uVar36,4,FUN_180005ae0);
    uVar7 = 0x1234ab;
    *(undefined4 *)(&stack0x00021fb0 + lVar5) = 0;
    *(undefined4 *)(&stack0x00021fd0 + lVar5) = 0;
    *(undefined8 *)(&stack0x00022080 + lVar5) = 0;
    *(undefined8 *)(&stack0x00022058 + lVar5) = 0;
    *(undefined4 *)(&stack0x0002203c + lVar5) = 0;
    *(undefined4 *)(&stack0x00022010 + lVar5) = 0;
    *(undefined4 *)(&stack0x00022018 + lVar5) = 0;
    *(undefined4 *)(&stack0x00022020 + lVar5) = 0;
    *(undefined8 *)(&stack0x00021ff8 + lVar5) = 0;
    *(undefined4 *)(&stack0x00021ff0 + lVar5) = 0;
  }
  else {
    *(undefined1 **)(&stack0x00022058 + lVar5) = &stack0x000000c1 + lVar5;
    *(undefined1 **)(&stack0x00022078 + lVar5) = &stack0x00000101 + lVar5;
    lVar19 = 0;
    *(undefined4 *)(&stack0x00021fb0 + lVar5) = 0;
    *(undefined4 *)(&stack0x00021fd0 + lVar5) = 0;
    *(undefined8 *)(&stack0x00022040 + lVar5) = 0;
    *(undefined8 *)(&stack0x00022048 + lVar5) = 0;
    *(undefined4 *)(&stack0x0002203c + lVar5) = 0;
    *(undefined4 *)(&stack0x00022010 + lVar5) = 0;
    *(undefined4 *)(&stack0x00022018 + lVar5) = 0;
    *(undefined4 *)(&stack0x00022020 + lVar5) = 0;
    *(undefined8 *)(&stack0x00021ff8 + lVar5) = 0;
    *(undefined4 *)(&stack0x00021ff0 + lVar5) = 0;
    do {
      if (0 < (int)uVar14) {
        pcVar21 = pcVar42 + lVar19 * 0x104;
        pcVar15 = &stack0x00010440 + lVar5;
        lVar17 = *(longlong *)(&stack0x00022088 + lVar5);
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000299b;
          iVar6 = strcmp(pcVar15,pcVar21);
          if (iVar6 == 0) {
            *(char **)(&stack0x000220a0 + lVar5) = pcVar15;
            goto LAB_1800029c7;
          }
          pcVar15 = pcVar15 + 0x228;
          lVar17 = lVar17 + -1;
        } while (lVar17 != 0);
        *(undefined8 *)(&stack0x000220a0 + lVar5) = 0;
LAB_1800029c7:
        *(char **)(&stack0x00022080 + lVar5) = pcVar21;
        puVar35 = &stack0x000104e1 + lVar5;
        puVar29 = &stack0x00010621 + lVar5;
        pbVar37 = &stack0x000104a1 + lVar5;
        pbVar31 = &stack0x00010481 + lVar5;
        pcVar15 = &stack0x00010440 + lVar5;
        lVar17 = *(longlong *)(&stack0x00022088 + lVar5);
LAB_180002a00:
        *(undefined1 **)(&stack0x000220b8 + lVar5) = puVar29;
        *(undefined1 **)(&stack0x000220a8 + lVar5) = puVar35;
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002a19;
        iVar6 = strcmp(pcVar15,pcVar21 + 0x40);
        if (iVar6 != 0) goto code_r0x000180002a1d;
        if (*(longlong *)(&stack0x000220a0 + lVar5) != 0) {
          *(char **)(&stack0x00022068 + lVar5) = pcVar15;
          lVar17 = *(longlong *)(&stack0x000220a0 + lVar5);
          bVar52 = *(byte *)(lVar17 + 0x40);
          *(undefined8 *)(&stack0x00021fe0 + lVar5) = 0x11c9dc5;
          uVar30 = 0x11c9dc5;
          *(longlong *)(&stack0x00022098 + lVar5) = lVar19;
          if (bVar52 != 0) {
            pbVar38 = (byte *)(lVar17 + 0x41);
            uVar30 = 0x811c9dc5;
            do {
              *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002abd;
              uVar7 = tolower((uint)bVar52);
              *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002ac6;
              iVar6 = isalnum((uint)bVar52);
              uVar25 = (uVar7 & 0xff ^ uVar30) * 0x1000193;
              if ((uVar7 & 0xff) == 0x5f) {
                uVar30 = uVar25;
              }
              if ((uVar7 & 0xef) == 0x2d) {
                uVar30 = uVar25;
              }
              if (iVar6 != 0) {
                uVar30 = uVar25;
              }
              bVar52 = *pbVar38;
              pbVar38 = pbVar38 + 1;
            } while (bVar52 != 0);
            uVar30 = uVar30 & 0x7fffffff;
            lVar19 = *(longlong *)(&stack0x00022098 + lVar5);
            lVar17 = *(longlong *)(&stack0x000220a0 + lVar5);
          }
          cVar24 = *(char *)(lVar17 + 0x60);
          (&stack0x00021fe8)[lVar5] = cVar24;
          if (cVar24 != '\0') {
            pbVar38 = (byte *)(*(longlong *)(&stack0x000220a0 + lVar5) + 0x61);
            uVar7 = 0x811c9dc5;
            bVar52 = (&stack0x00021fe8)[lVar5];
            do {
              *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002b4d;
              uVar25 = tolower((uint)bVar52);
              *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002b59;
              iVar6 = isalnum((uint)bVar52);
              uVar26 = (uVar25 & 0xff ^ uVar7) * 0x1000193;
              if ((uVar25 & 0xff) == 0x5f) {
                uVar7 = uVar26;
              }
              if ((uVar25 & 0xef) == 0x2d) {
                uVar7 = uVar26;
              }
              if (iVar6 != 0) {
                uVar7 = uVar26;
              }
              bVar52 = *pbVar38;
              pbVar38 = pbVar38 + 1;
            } while (bVar52 != 0);
            *(ulonglong *)(&stack0x00021fe0 + lVar5) = (ulonglong)(uVar7 & 0x7fffffff);
            lVar19 = *(longlong *)(&stack0x00022098 + lVar5);
          }
          bVar52 = *(byte *)(*(longlong *)(&stack0x00022068 + lVar5) + 0x40);
          *(undefined4 *)(&stack0x00022000 + lVar5) = 0x11c9dc5;
          uVar7 = 0x11c9dc5;
          if (bVar52 != 0) {
            uVar7 = 0x811c9dc5;
            do {
              *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002bdd;
              uVar25 = tolower((uint)bVar52);
              *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002be6;
              iVar6 = isalnum((uint)bVar52);
              uVar26 = (uVar25 & 0xff ^ uVar7) * 0x1000193;
              if ((uVar25 & 0xff) == 0x5f) {
                uVar7 = uVar26;
              }
              if ((uVar25 & 0xef) == 0x2d) {
                uVar7 = uVar26;
              }
              if (iVar6 != 0) {
                uVar7 = uVar26;
              }
              bVar52 = *pbVar31;
              pbVar31 = pbVar31 + 1;
            } while (bVar52 != 0);
            uVar7 = uVar7 & 0x7fffffff;
            lVar19 = *(longlong *)(&stack0x00022098 + lVar5);
          }
          bVar52 = *(byte *)(*(longlong *)(&stack0x00022068 + lVar5) + 0x60);
          if (bVar52 != 0) {
            uVar25 = 0x811c9dc5;
            do {
              *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002c5d;
              uVar26 = tolower((uint)bVar52);
              *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002c66;
              iVar6 = isalnum((uint)bVar52);
              uVar8 = (uVar26 & 0xff ^ uVar25) * 0x1000193;
              if ((uVar26 & 0xff) == 0x5f) {
                uVar25 = uVar8;
              }
              if ((uVar26 & 0xef) == 0x2d) {
                uVar25 = uVar8;
              }
              if (iVar6 != 0) {
                uVar25 = uVar8;
              }
              bVar52 = *pbVar37;
              pbVar37 = pbVar37 + 1;
            } while (bVar52 != 0);
            *(uint *)(&stack0x00022000 + lVar5) = uVar25 & 0x7fffffff;
            lVar19 = *(longlong *)(&stack0x00022098 + lVar5);
          }
          lVar17 = *(longlong *)(&stack0x00022080 + lVar5);
          bVar52 = *(byte *)(lVar17 + 0x80);
          uVar25 = 0x11c9dc5;
          if (bVar52 != 0) {
            uVar25 = 0x811c9dc5;
            pbVar37 = *(byte **)(&stack0x00022058 + lVar5);
            do {
              *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002cfa;
              uVar26 = tolower((uint)bVar52);
              *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002d06;
              iVar6 = isalnum((uint)bVar52);
              uVar8 = (uVar26 & 0xff ^ uVar25) * 0x1000193;
              if ((uVar26 & 0xff) == 0x5f) {
                uVar25 = uVar8;
              }
              if ((uVar26 & 0xef) == 0x2d) {
                uVar25 = uVar8;
              }
              if (iVar6 != 0) {
                uVar25 = uVar8;
              }
              bVar52 = *pbVar37;
              pbVar37 = pbVar37 + 1;
            } while (bVar52 != 0);
            uVar25 = uVar25 & 0x7fffffff;
            lVar19 = *(longlong *)(&stack0x00022098 + lVar5);
            lVar17 = *(longlong *)(&stack0x00022080 + lVar5);
          }
          uVar26 = 0x11c9dc5;
          bVar52 = *(byte *)(lVar17 + 0xc0);
          (&stack0x00021fb8)[lVar5] = bVar52;
          if (bVar52 != 0) {
            uVar26 = 0x811c9dc5;
            pbVar37 = *(byte **)(&stack0x00022078 + lVar5);
            do {
              *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002d90;
              uVar8 = tolower((uint)bVar52);
              *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002d9c;
              iVar6 = isalnum((uint)bVar52);
              uVar27 = (uVar8 & 0xff ^ uVar26) * 0x1000193;
              if ((uVar8 & 0xff) == 0x5f) {
                uVar26 = uVar27;
              }
              if ((uVar8 & 0xef) == 0x2d) {
                uVar26 = uVar27;
              }
              if (iVar6 != 0) {
                uVar26 = uVar27;
              }
              bVar52 = *pbVar37;
              pbVar37 = pbVar37 + 1;
            } while (bVar52 != 0);
            uVar26 = uVar26 & 0x7fffffff;
            lVar19 = *(longlong *)(&stack0x00022098 + lVar5);
            lVar17 = *(longlong *)(&stack0x00022080 + lVar5);
          }
          bVar52 = uVar25 == 0x6ccaf138;
          (&stack0x00022008)[lVar5] = !(bool)bVar52;
          uVar49 = *(undefined8 *)(&stack0x00021fe0 + lVar5);
          uVar8 = *(uint *)(&stack0x00022000 + lVar5);
          lVar18 = (longlong)*(int *)(lVar17 + 0x100);
          *(uint *)(&stack0x00021840 + lVar19 * 4 + lVar5) =
               (*(int *)(lVar17 + 0x100) << 7 ^
                uVar25 << 5 ^ uVar8 << 4 ^ uVar7 * 8 ^ (uint)uVar49 * 4 ^ uVar30 * 2 ^ uVar26 << 6)
               & 0x7fffffff;
          uVar8 = uVar8 ^ (uint)uVar49;
          *(longlong *)(&stack0x00022080 + lVar5) = lVar18;
          if ((uVar30 == 0x56dfde64) && (uVar7 == 0x45334cec)) {
            iVar6 = *(int *)(&stack0x00021ff0 + lVar5);
            *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002edb;
            uVar27 = FUN_180005900((char *)(*(longlong *)(&stack0x00022068 + lVar5) + 0xe0));
            lVar18 = *(longlong *)(&stack0x00022080 + lVar5);
            uVar27 = uVar27 ^ uVar25 ^ uVar26;
            lVar19 = *(longlong *)(&stack0x00022098 + lVar5);
            *(uint *)(&stack0x00021ff0 + lVar5) =
                 ((uVar26 ^ uVar8) +
                  (uint)((ulonglong)(uVar26 ^ uVar8) * 0x8637a2a3 >> 0x33) * -0xf4243 + iVar6) %
                 0xf4243;
            *(uint *)(&stack0x00022010 + lVar5) =
                 (uVar27 + (uint)((ulonglong)uVar27 * 0x8637a2a3 >> 0x33) * -0xf4243 +
                 *(int *)(&stack0x00022010 + lVar5)) % 0xf4243;
          }
          uVar27 = uVar25 ^ uVar8 ^ uVar26;
          uVar40 = uVar27 ^ (uint)lVar18;
          uVar14 = (ulonglong)uVar40;
          *(ulonglong *)(&stack0x00021e78 + lVar5) = (ulonglong)uVar8;
          *(ulonglong *)(&stack0x00021e70 + lVar5) = (ulonglong)uVar27;
          if ((uVar30 == 0x667c6911 || uVar30 == 0x2047d5a7) && (uVar7 == 0x45334cec)) {
            *(ulonglong *)(&stack0x00021e80 + lVar5) = uVar14;
            (&stack0x00022077)[lVar5] = bVar52;
            uVar7 = 0x11c9dc5;
            uVar30 = 0x11c9dc5;
            bVar52 = (&stack0x00021fe8)[lVar5];
            *(uint *)(&stack0x00021fd8 + lVar5) = uVar26;
            if (bVar52 != 0) {
              pbVar37 = (byte *)(*(longlong *)(&stack0x000220a0 + lVar5) + 0x61);
              uVar30 = 0x811c9dc5;
              do {
                *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002fd8;
                uVar26 = tolower((uint)bVar52);
                *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180002fe3;
                iVar6 = isalnum((uint)bVar52);
                uVar8 = (uVar26 & 0xff ^ uVar30) * 0x1000193;
                if ((uVar26 & 0xff) == 0x5f) {
                  uVar30 = uVar8;
                }
                if ((uVar26 & 0xef) == 0x2d) {
                  uVar30 = uVar8;
                }
                if (iVar6 != 0) {
                  uVar30 = uVar8;
                }
                bVar52 = *pbVar37;
                pbVar37 = pbVar37 + 1;
              } while (bVar52 != 0);
              uVar30 = uVar30 & 0x7fffffff;
              lVar19 = *(longlong *)(&stack0x00022098 + lVar5);
              uVar26 = *(uint *)(&stack0x00021fd8 + lVar5);
              lVar18 = *(longlong *)(&stack0x00022080 + lVar5);
            }
            bVar52 = *(byte *)(*(longlong *)(&stack0x00022068 + lVar5) + 0x1e0);
            if (bVar52 != 0) {
              uVar7 = 0x811c9dc5;
              pbVar37 = *(byte **)(&stack0x000220b8 + lVar5);
              do {
                *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000306a;
                uVar26 = tolower((uint)bVar52);
                *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003075;
                iVar6 = isalnum((uint)bVar52);
                uVar8 = (uVar26 & 0xff ^ uVar7) * 0x1000193;
                if ((uVar26 & 0xff) == 0x5f) {
                  uVar7 = uVar8;
                }
                if ((uVar26 & 0xef) == 0x2d) {
                  uVar7 = uVar8;
                }
                if (iVar6 != 0) {
                  uVar7 = uVar8;
                }
                bVar52 = *pbVar37;
                pbVar37 = pbVar37 + 1;
              } while (bVar52 != 0);
              uVar7 = uVar7 & 0x7fffffff;
              lVar19 = *(longlong *)(&stack0x00022098 + lVar5);
              uVar26 = *(uint *)(&stack0x00021fd8 + lVar5);
              lVar18 = *(longlong *)(&stack0x00022080 + lVar5);
            }
            bVar52 = (&stack0x00021fb8)[lVar5];
            if (bVar52 == 0) {
              uVar8 = 0x11c9dc5;
            }
            else {
              uVar8 = 0x811c9dc5;
              pbVar37 = *(byte **)(&stack0x00022078 + lVar5);
              do {
                *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800030fb;
                uVar26 = tolower((uint)bVar52);
                *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003106;
                iVar6 = isalnum((uint)bVar52);
                uVar27 = (uVar26 & 0xff ^ uVar8) * 0x1000193;
                if ((uVar26 & 0xff) == 0x5f) {
                  uVar8 = uVar27;
                }
                if ((uVar26 & 0xef) == 0x2d) {
                  uVar8 = uVar27;
                }
                if (iVar6 != 0) {
                  uVar8 = uVar27;
                }
                bVar52 = *pbVar37;
                pbVar37 = pbVar37 + 1;
              } while (bVar52 != 0);
              uVar8 = uVar8 & 0x7fffffff;
              lVar19 = *(longlong *)(&stack0x00022098 + lVar5);
              uVar26 = *(uint *)(&stack0x00021fd8 + lVar5);
              lVar18 = *(longlong *)(&stack0x00022080 + lVar5);
            }
            *(uint *)(&stack0x00022018 + lVar5) =
                 ((uVar7 ^ uVar30 ^ uVar8) % 0xf4243 + *(int *)(&stack0x00022018 + lVar5)) % 0xf4243
            ;
            lVar17 = *(longlong *)(&stack0x00022040 + lVar5);
            lVar41 = *(longlong *)(&stack0x00022048 + lVar5);
            bVar52 = (&stack0x00022077)[lVar5];
            bVar32 = (&stack0x00022008)[lVar5];
            uVar14 = *(ulonglong *)(&stack0x00021e80 + lVar5);
          }
          else if (uVar30 == 0x133c1bd8) {
            lVar17 = *(longlong *)(&stack0x00022040 + lVar5);
            lVar41 = *(longlong *)(&stack0x00022048 + lVar5);
            bVar32 = (&stack0x00022008)[lVar5];
            if (uVar7 == 0x56dfde64) {
              *(ulonglong *)(&stack0x00021ff8 + lVar5) =
                   (ulonglong)((uVar40 % 0xf4243 + *(int *)(&stack0x00021ff8 + lVar5)) % 0xf4243);
            }
          }
          else {
            lVar17 = *(longlong *)(&stack0x00022040 + lVar5);
            lVar41 = *(longlong *)(&stack0x00022048 + lVar5);
            bVar32 = (&stack0x00022008)[lVar5];
          }
          if ((*(int *)(&stack0x00021fe0 + lVar5) == 0x8bb40c5) ||
             (*(int *)(&stack0x00022000 + lVar5) == 0x8bb40c5)) {
            *(uint *)(&stack0x00022020 + lVar5) =
                 ((int)*(ulonglong *)(&stack0x00021e70 + lVar5) +
                  (uint)((*(ulonglong *)(&stack0x00021e70 + lVar5) & 0xffffffff) * 0x8637a2a3 >>
                        0x33) * -0xf4243 + *(int *)(&stack0x00022020 + lVar5)) % 0xf4243;
          }
          *(ulonglong *)(&stack0x00022048 + lVar5) =
               (ulonglong)uVar25 * 3 + lVar41 + (ulonglong)uVar26 * 5 + lVar18 * 7;
          *(uint *)(&stack0x00021fd0 + lVar5) = *(int *)(&stack0x00021fd0 + lVar5) + (uint)bVar32;
          *(uint *)(&stack0x00021fb0 + lVar5) = *(int *)(&stack0x00021fb0 + lVar5) + (uint)bVar52;
          *(ulonglong *)(&stack0x00022040 + lVar5) = lVar17 + uVar14;
          bVar52 = *(byte *)(*(longlong *)(&stack0x000220a0 + lVar5) + 0xa0);
          if (bVar52 == 0) {
LAB_180003471:
            lVar17 = *(longlong *)(&stack0x00022060 + lVar5);
          }
          else {
            bVar32 = *(byte *)(*(longlong *)(&stack0x00022068 + lVar5) + 0xa0);
            if (bVar32 == 0) goto LAB_180003471;
            lVar17 = *(longlong *)(&stack0x000220a0 + lVar5);
            *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000333a;
            iVar6 = strcmp((char *)(lVar17 + 0xa0),
                           (char *)(*(longlong *)(&stack0x00022068 + lVar5) + 0xa0));
            if (iVar6 == 0) goto LAB_180003471;
            pbVar37 = (byte *)(lVar17 + 0xa1);
            uVar30 = 0x811c9dc5;
            do {
              *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003369;
              uVar7 = tolower((uint)bVar52);
              *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003371;
              iVar6 = isalnum((uint)bVar52);
              uVar25 = (uVar7 & 0xff ^ uVar30) * 0x1000193;
              if ((uVar7 & 0xff) == 0x5f) {
                uVar30 = uVar25;
              }
              if ((uVar7 & 0xef) == 0x2d) {
                uVar30 = uVar25;
              }
              if (iVar6 != 0) {
                uVar30 = uVar25;
              }
              bVar52 = *pbVar37;
              pbVar37 = pbVar37 + 1;
            } while (bVar52 != 0);
            uVar7 = 0x811c9dc5;
            pbVar37 = *(byte **)(&stack0x000220a8 + lVar5);
            do {
              *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800033cb;
              uVar25 = tolower((uint)bVar32);
              *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800033d3;
              iVar6 = isalnum((uint)bVar32);
              uVar26 = (uVar25 & 0xff ^ uVar7) * 0x1000193;
              if ((uVar25 & 0xff) == 0x5f) {
                uVar7 = uVar26;
              }
              if ((uVar25 & 0xef) == 0x2d) {
                uVar7 = uVar26;
              }
              if (iVar6 != 0) {
                uVar7 = uVar26;
              }
              bVar32 = *pbVar37;
              pbVar37 = pbVar37 + 1;
            } while (bVar32 != 0);
            uVar30 = (uint)*(undefined8 *)(&stack0x00021e78 + lVar5) ^ (uVar7 ^ uVar30) & 0x7fffffff
            ;
            *(uint *)(&stack0x0002203c + lVar5) =
                 (uVar30 + (uint)((ulonglong)uVar30 * 0x8637a2a3 >> 0x33) * -0xf4243 +
                 *(int *)(&stack0x0002203c + lVar5)) % 0xf4243;
            lVar17 = *(longlong *)(&stack0x00022060 + lVar5);
            lVar19 = *(longlong *)(&stack0x00022098 + lVar5);
          }
          uVar14 = *(ulonglong *)(&stack0x000220b0 + lVar5);
          goto LAB_18000294a;
        }
      }
LAB_180002930:
      *(undefined4 *)(&stack0x00021840 + lVar19 * 4 + lVar5) = 0;
      uVar14 = *(ulonglong *)(&stack0x000220b0 + lVar5);
      lVar17 = *(longlong *)(&stack0x00022060 + lVar5);
LAB_18000294a:
      iVar6 = (int)uVar14;
      lVar19 = lVar19 + 1;
      *(longlong *)(&stack0x00022058 + lVar5) = *(longlong *)(&stack0x00022058 + lVar5) + 0x104;
      *(longlong *)(&stack0x00022078 + lVar5) = *(longlong *)(&stack0x00022078 + lVar5) + 0x104;
    } while (lVar19 != lVar17);
    sVar3 = *(size_t *)(&stack0x00022060 + lVar5);
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800034c1;
    qsort(&stack0x00021840 + lVar5,sVar3,4,FUN_180005ae0);
    uVar30 = (uint)sVar3;
    uVar14 = (ulonglong)(uVar30 & 3);
    if ((int)*(undefined8 *)(&stack0x00022090 + lVar5) - 1U < 3) {
      uVar7 = 0x1234ab;
      uVar36 = 0;
    }
    else {
      uVar7 = 0x1234ab;
      uVar36 = 0;
      do {
        uVar7 = ((((uVar7 * 0x1000193 ^ *(uint *)(&stack0x00021840 + uVar36 * 4 + lVar5)) *
                   0x1000193 ^ *(uint *)(&stack0x00021844 + uVar36 * 4 + lVar5)) * 0x1000193 ^
                 *(uint *)(&stack0x00021848 + uVar36 * 4 + lVar5)) * 0x1000193 ^
                *(uint *)(&stack0x0002184c + uVar36 * 4 + lVar5)) & 0x7fffffff;
        uVar36 = uVar36 + 4;
      } while ((uVar30 & 0x7ffffffc) != uVar36);
    }
    if (uVar14 != 0) {
      uVar39 = 0;
      do {
        uVar7 = (uVar7 * 0x1000193 ^ *(uint *)(pcVar42 + uVar39 * 4 + uVar36 * 4 + 0x21800)) &
                0x7fffffff;
        uVar39 = uVar39 + 1;
      } while (uVar14 != uVar39);
    }
    *(ulonglong *)(&stack0x00022058 + lVar5) =
         (ulonglong)
         (uint)((int)*(ulonglong *)(&stack0x00022048 + lVar5) +
               (int)(*(ulonglong *)(&stack0x00022048 + lVar5) / 0x7fffffff) * -0x7fffffff);
    *(ulonglong *)(&stack0x00022080 + lVar5) =
         (ulonglong)
         (uint)((int)*(ulonglong *)(&stack0x00022040 + lVar5) +
               (int)(*(ulonglong *)(&stack0x00022040 + lVar5) / 0x7fffffff) * -0x7fffffff);
  }
  *(uint *)(&stack0x00021eec + lVar5) = uVar7;
  if (iVar6 < 1) {
    uVar30 = 0;
  }
  else {
    pbVar37 = &stack0x000104a1 + lVar5;
    lVar19 = 0;
    *(undefined1 **)(&stack0x00022098 + lVar5) = &stack0x00010481 + lVar5;
    uVar30 = 0;
    do {
      *(uint *)(&stack0x000220a0 + lVar5) = uVar30;
      uVar7 = 0;
      uVar30 = 0;
      if (0 < *(int *)(&stack0x00022090 + lVar5)) {
        uVar30 = 0;
        lVar17 = *(longlong *)(&stack0x00022060 + lVar5);
        iVar6 = 0;
        pcVar15 = pcVar42;
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000377b;
          iVar9 = strcmp(pcVar15,pcVar42 + lVar19 * 0x228 + 0x10400);
          iVar6 = iVar6 + (uint)(iVar9 == 0);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000378e;
          iVar9 = strcmp(pcVar15 + 0x40,pcVar42 + lVar19 * 0x228 + 0x10400);
          uVar30 = uVar30 + (iVar9 == 0);
          pcVar15 = pcVar15 + 0x104;
          lVar17 = lVar17 + -1;
        } while (lVar17 != 0);
        uVar7 = iVar6 * 0x100;
      }
      lVar17 = lVar19 * 0x228;
      bVar52 = (&stack0x000104a0)[lVar17 + lVar5];
      uVar26 = 0x11c9dc5;
      uVar25 = 0x11c9dc5;
      *(byte **)(&stack0x000220b8 + lVar5) = pbVar37;
      *(longlong *)(&stack0x000220a8 + lVar5) = lVar19;
      if (bVar52 != 0) {
        *(longlong *)(&stack0x00022078 + lVar5) = lVar17;
        uVar25 = 0x811c9dc5;
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800037eb;
          uVar8 = tolower((uint)bVar52);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800037f6;
          iVar6 = isalnum((uint)bVar52);
          uVar27 = (uVar8 & 0xff ^ uVar25) * 0x1000193;
          if ((uVar8 & 0xff) == 0x5f) {
            uVar25 = uVar27;
          }
          if ((uVar8 & 0xef) == 0x2d) {
            uVar25 = uVar27;
          }
          if (iVar6 != 0) {
            uVar25 = uVar27;
          }
          bVar52 = *pbVar37;
          pbVar37 = pbVar37 + 1;
        } while (bVar52 != 0);
        uVar25 = uVar25 & 0x7fffffff;
        pbVar37 = *(byte **)(&stack0x000220b8 + lVar5);
        lVar19 = *(longlong *)(&stack0x000220a8 + lVar5);
        lVar17 = *(longlong *)(&stack0x00022078 + lVar5);
      }
      bVar52 = pcVar42[lVar17 + 0x10440];
      if (bVar52 != 0) {
        uVar26 = 0x811c9dc5;
        pbVar37 = *(byte **)(&stack0x00022098 + lVar5);
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000387b;
          uVar8 = tolower((uint)bVar52);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003886;
          iVar6 = isalnum((uint)bVar52);
          uVar27 = (uVar8 & 0xff ^ uVar26) * 0x1000193;
          if ((uVar8 & 0xff) == 0x5f) {
            uVar26 = uVar27;
          }
          if ((uVar8 & 0xef) == 0x2d) {
            uVar26 = uVar27;
          }
          if (iVar6 != 0) {
            uVar26 = uVar27;
          }
          bVar52 = *pbVar37;
          pbVar37 = pbVar37 + 1;
        } while (bVar52 != 0);
        uVar26 = uVar26 & 0x7fffffff;
        pbVar37 = *(byte **)(&stack0x000220b8 + lVar5);
        lVar19 = *(longlong *)(&stack0x000220a8 + lVar5);
      }
      uVar30 = ((uVar25 ^ (uVar30 | uVar7) ^ uVar26) % 0xf4243 + *(int *)(&stack0x000220a0 + lVar5))
               % 0xf4243;
      lVar19 = lVar19 + 1;
      pbVar37 = pbVar37 + 0x228;
      *(longlong *)(&stack0x00022098 + lVar5) = *(longlong *)(&stack0x00022098 + lVar5) + 0x228;
    } while (lVar19 != *(longlong *)(&stack0x00022088 + lVar5));
  }
  uVar7 = 0x1a2b3c4d;
  lVar19 = 0;
  puVar35 = &stack0x00010440 + lVar5;
  uVar49 = *(undefined8 *)(&stack0x000220b0 + lVar5);
  do {
    uVar25 = *(uint *)((longlong)&DAT_18002b788 + lVar19);
    uVar26 = (uint)uVar49;
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003906;
    iVar6 = FUN_180005b00((longlong)puVar35,uVar26,uVar25,0x2047d5a7);
    if (0 < iVar6) {
      uVar7 = uVar7 ^ uVar25 ^ iVar6 << 0xb ^ 0x2047d5a7;
      uVar7 = (uVar7 << 5 | uVar7 >> 0x1b) * -0x61c8864f + 0x1020304;
    }
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000393b;
    iVar6 = FUN_180005b00((longlong)puVar35,uVar26,uVar25,0x251b4cfe);
    if (0 < iVar6) {
      uVar7 = uVar7 ^ uVar25 ^ iVar6 << 0xb ^ 0x251b4cfe;
      uVar7 = (uVar7 << 5 | uVar7 >> 0x1b) * -0x61c8864f + 0x1020304;
    }
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003970;
    iVar6 = FUN_180005b00((longlong)puVar35,uVar26,uVar25,0x133c1bd8);
    if (0 < iVar6) {
      uVar7 = uVar7 ^ uVar25 ^ iVar6 << 0xb ^ 0x133c1bd8;
      uVar7 = (uVar7 << 5 | uVar7 >> 0x1b) * -0x61c8864f + 0x1020304;
    }
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800039a5;
    iVar6 = FUN_180005b00((longlong)puVar35,uVar26,uVar25,0x45334cec);
    if (0 < iVar6) {
      uVar7 = uVar7 ^ uVar25 ^ iVar6 << 0xb ^ 0x45334cec;
      uVar7 = (uVar7 << 5 | uVar7 >> 0x1b) * -0x61c8864f + 0x1020304;
    }
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800039da;
    iVar6 = FUN_180005b00((longlong)puVar35,uVar26,uVar25,0x667c6911);
    if (0 < iVar6) {
      uVar7 = uVar7 ^ uVar25 ^ iVar6 << 0xb ^ 0x667c6911;
      uVar7 = (uVar7 << 5 | uVar7 >> 0x1b) * -0x61c8864f + 0x1020304;
    }
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003a0f;
    iVar6 = FUN_180005b00((longlong)puVar35,uVar26,uVar25,0x56dfde64);
    if (0 < iVar6) {
      uVar7 = uVar7 ^ uVar25 ^ iVar6 << 0xb ^ 0x56dfde64;
      uVar7 = (uVar7 << 5 | uVar7 >> 0x1b) * -0x61c8864f + 0x1020304;
    }
    lVar19 = lVar19 + 4;
  } while (lVar19 != 0xc);
  *(uint *)(&stack0x00021f2c + lVar5) = uVar7 & 0x7fffffff;
  *(uint *)(&stack0x00021ed0 + lVar5) = uVar26;
  *(int *)(&stack0x00021ed4 + lVar5) = (int)*(undefined8 *)(&stack0x00022090 + lVar5);
  *(int *)(&stack0x00021ed8 + lVar5) =
       *(int *)(&stack0x00021fa4 + lVar5) + *(int *)(&stack0x00021fa8 + lVar5) +
       *(int *)(&stack0x00021fac + lVar5) +
       *(int *)(&stack0x00021fa0 + lVar5) + *(int *)(&stack0x00022038 + lVar5) +
       *(int *)(&stack0x00022054 + lVar5) + *(int *)(&stack0x00021fdc + lVar5) +
       *(int *)(&stack0x00022034 + lVar5);
  *(int *)(&stack0x00021edc + lVar5) = (int)*(undefined8 *)(&stack0x00021e88 + lVar5);
  *(int *)(&stack0x00021ee0 + lVar5) = (int)*(undefined8 *)(&stack0x00021f58 + lVar5);
  *(int *)(&stack0x00021ee4 + lVar5) = (int)*(undefined8 *)(&stack0x00022058 + lVar5);
  *(int *)(&stack0x00021ef0 + lVar5) = (int)*(undefined8 *)(&stack0x00021fc8 + lVar5);
  *(undefined4 *)(&stack0x00021ef4 + lVar5) = *(undefined4 *)(&stack0x00022030 + lVar5);
  *(int *)(&stack0x00021ef8 + lVar5) = (int)*(undefined8 *)(&stack0x00021f98 + lVar5);
  *(undefined4 *)(&stack0x00021efc + lVar5) = *(undefined4 *)(&stack0x00021fb0 + lVar5);
  *(undefined4 *)(&stack0x00021f00 + lVar5) = *(undefined4 *)(&stack0x00021fd0 + lVar5);
  *(int *)(&stack0x00021f04 + lVar5) = (int)*(undefined8 *)(&stack0x00022080 + lVar5);
  *(int *)(&stack0x00021f08 + lVar5) = (int)*(undefined8 *)(&stack0x00021fc0 + lVar5);
  puVar35 = &stack0x00021edc + lVar5;
  *(uint *)(&stack0x00021f0c + lVar5) = uVar30;
  *(undefined4 *)(&stack0x00021f10 + lVar5) = *(undefined4 *)(&stack0x00021ff0 + lVar5);
  *(undefined4 *)(&stack0x00021f14 + lVar5) = *(undefined4 *)(&stack0x0002202c + lVar5);
  *(int *)(&stack0x00021f18 + lVar5) = (int)*(undefined8 *)(&stack0x00021ff8 + lVar5);
  *(undefined4 *)(&stack0x00021f1c + lVar5) = *(undefined4 *)(&stack0x00022020 + lVar5);
  *(undefined4 *)(&stack0x00021f20 + lVar5) = *(undefined4 *)(&stack0x00022018 + lVar5);
  *(undefined4 *)(&stack0x00021f24 + lVar5) = *(undefined4 *)(&stack0x00022010 + lVar5);
  *(undefined4 *)(&stack0x00021f28 + lVar5) = *(undefined4 *)(&stack0x0002203c + lVar5);
  uVar30 = 0x6d2b79f5;
  uVar14 = 3;
  iVar9 = 0x3c6ef35f;
  iVar6 = 0;
  uVar36 = 0;
  do {
    auVar57._8_8_ = 0;
    auVar57._0_8_ = uVar14;
    uVar25 = *(uint *)(&stack0x00021ed0 + uVar36 * 4 + lVar5);
    uVar7 = iVar6 + uVar25;
    bVar52 = (byte)uVar36;
    if (0x10 < uVar36) {
      bVar52 = (byte)uVar36 - 0x11;
    }
    uVar26 = uVar7 << (bVar52 & 0x1f) | uVar7 >> 0x20 - (bVar52 & 0x1f);
    if ((bVar52 & 0x1f) == 0) {
      uVar26 = uVar7;
    }
    uVar30 = (uVar26 ^ uVar30) * 0x19660d + iVar9;
    iVar10 = (int)uVar36 + -0xd;
    if (uVar36 < 0xd) {
      iVar10 = (int)uVar36;
    }
    bVar52 = (byte)(iVar10 + 1U) & 0x1f;
    uVar7 = uVar25 << bVar52 | uVar25 >> 0x20 - bVar52;
    if ((iVar10 + 1U & 0x1f) == 0) {
      uVar7 = uVar25;
    }
    *(uint *)(&stack0x00021cf0 + uVar36 * 4 + lVar5) =
         (uVar7 ^ *(uint *)(puVar35 +
                           (SUB168(auVar57 * ZEXT816(0xaaaaaaaaaaaaaaab),8) * 2 &
                           0xffffffffffffffe0U) * -3) ^ uVar30) & 0x7fffffff;
    puVar35 = puVar35 + 0x1c;
    uVar14 = uVar14 + 7;
    iVar9 = iVar9 + 0x61;
    iVar6 = iVar6 + 0x9e37;
    uVar36 = uVar36 + 1;
  } while (uVar36 != 0x18);
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x56dfde64;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x4af021b;
  pcVar15 = &stack0x00010440 + lVar5;
  uVar49 = *(undefined8 *)(&stack0x000220b0 + lVar5);
  uVar26 = (uint)uVar49;
  uVar7 = (uint)*(undefined8 *)(&stack0x00022090 + lVar5);
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003c95;
  iVar6 = FUN_180005cd0(pcVar15,uVar26,(longlong)pcVar42,uVar7,
                        *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                        *(uint *)(&stack0xffffffffffffffe8 + lVar5));
  *(ulonglong *)(&stack0x00022068 + lVar5) = CONCAT44(extraout_var,iVar6);
  uVar30 = iVar6 + 0x3b54aU ^ 0xbaeb1811;
  uVar30 = (uVar30 << 7 | uVar30 >> 0x19) * -0x61c8864f + 0x3165b;
  *(uint *)(&stack0x000220b8 + lVar5) = uVar30;
  uVar30 = uVar30 & 0x7fffffff;
  *(ulonglong *)(&stack0x000220a8 + lVar5) = (ulonglong)uVar30;
  *(uint *)(&stack0x00021e90 + lVar5) = uVar30;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x251b4cfe;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x9bdb79f;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003cef;
  iVar6 = FUN_180005cd0(pcVar15,uVar26,(longlong)pcVar42,uVar7,
                        *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                        *(uint *)(&stack0xffffffffffffffe8 + lVar5));
  *(ulonglong *)(&stack0x00022000 + lVar5) = CONCAT44(extraout_var_00,iVar6);
  uVar30 = iVar6 + 0x3b54aU ^ 0x38399c13;
  uVar27 = (uVar30 << 7 | uVar30 >> 0x19) * 0x1e3779b1 + 0x3165b & 0x7fffffff;
  *(uint *)(&stack0x00021e94 + lVar5) = uVar27;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x56dfde64;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x6994bce3;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003d3c;
  iVar6 = FUN_180005cd0(pcVar15,uVar26,(longlong)pcVar42,uVar7,
                        *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                        *(uint *)(&stack0xffffffffffffffe8 + lVar5));
  *(ulonglong *)(&stack0x00022080 + lVar5) = CONCAT44(extraout_var_01,iVar6);
  uVar30 = iVar6 + 0x3b54aU ^ 0x49818ea;
  uVar30 = (uVar30 << 7 | uVar30 >> 0x19) * 0x1e3779b1 + 0x3165b & 0x7fffffff;
  *(ulonglong *)(&stack0x00022088 + lVar5) = (ulonglong)uVar30;
  *(uint *)(&stack0x00021e98 + lVar5) = uVar30;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x56dfde64;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x5e098a07;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003d90;
  iVar6 = FUN_180005cd0(pcVar15,uVar26,(longlong)pcVar42,uVar7,
                        *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                        *(uint *)(&stack0xffffffffffffffe8 + lVar5));
  *(ulonglong *)(&stack0x00022058 + lVar5) = CONCAT44(extraout_var_02,iVar6);
  uVar30 = iVar6 + 0x31713U ^ 0x45ae65cf;
  uVar51 = (uVar30 << 6 | uVar30 >> 0x1a) * 0x1e3779b1 + 0x315fa & 0x7fffffff;
  *(uint *)(&stack0x00021e9c + lVar5) = uVar51;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x31c14e0d;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x23f97dbd;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003de3;
  uVar30 = FUN_180005cd0(pcVar15,uVar26,(longlong)pcVar42,uVar7,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar5));
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x31c14e0d;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x20f97904;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003e06;
  uVar7 = FUN_180005cd0(pcVar15,uVar26,(longlong)pcVar42,uVar7,
                        *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                        *(uint *)(&stack0xffffffffffffffe8 + lVar5));
  *(ulonglong *)(&stack0x00021fe8 + lVar5) = (ulonglong)uVar30;
  uVar30 = uVar30 + 0x13c6e ^ 0xf579efe6;
  uVar30 = (uVar30 << 3 | uVar30 >> 0x1d) * -0x61c8864f + 0x314d7 ^ 0x20fb53a9;
  *(ulonglong *)(&stack0x00022008 + lVar5) = (ulonglong)uVar7;
  uVar30 = uVar7 + 0x278dc ^ (uVar30 << 4 | uVar30 >> 0x1c) * -0x61c8864f + 0x31538;
  uVar30 = (uVar30 << 5 | uVar30 >> 0x1b) * -0x61c8864f + 0x31599 ^ 0x554bd1c0;
  uVar30 = (uVar30 << 6 | uVar30 >> 0x1a) * -0x61c8864f + 0x315fa ^ 0x524c6b3e;
  uVar43 = (uVar30 << 7 | uVar30 >> 0x19) * 0x1e3779b1 + 0x3165b;
  uVar44 = uVar43 & 0x7fffffff;
  *(uint *)(&stack0x00021ea0 + lVar5) = uVar44;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003ea9;
  uVar30 = FUN_180005b00((longlong)pcVar15,uVar26,0x8bb40c5,0x45334cec);
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003ec2;
  uVar7 = FUN_180005b00((longlong)pcVar15,uVar26,0x8bb40c5,0x56dfde64);
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003edc;
  uVar25 = FUN_180005b00((longlong)pcVar15,uVar26,0x8bb40c5,0x667c6911);
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180003ef9;
  iVar6 = FUN_180005b00((longlong)(&stack0x00010440 + lVar5),uVar26,0x8bb40c5,0x251b4cfe);
  *(ulonglong *)(&stack0x00021fc0 + lVar5) = (ulonglong)uVar30;
  uVar30 = uVar30 + 0x13c6e ^ 0xfc57e5c6;
  *(ulonglong *)(&stack0x00021fc8 + lVar5) = (ulonglong)uVar7;
  uVar30 = uVar7 + 0x1daa5 ^ (uVar30 << 3 | uVar30 >> 0x1d) * -0x61c8864f + 0x314d7;
  *(ulonglong *)(&stack0x00022040 + lVar5) = (ulonglong)uVar25;
  uVar30 = uVar25 + 0x278dc ^ (uVar30 << 4 | uVar30 >> 0x1c) * -0x61c8864f + 0x31538;
  *(ulonglong *)(&stack0x00022048 + lVar5) = CONCAT44(extraout_var_03,iVar6);
  uVar30 = iVar6 + 0x31713U ^ (uVar30 << 5 | uVar30 >> 0x1b) * -0x61c8864f + 0x31599;
  uVar7 = (uVar30 << 6 | uVar30 >> 0x1a) * 0x1e3779b1 + 0x315fa & 0x7fffffff;
  *(uint *)(&stack0x00021ea4 + lVar5) = uVar7;
  uVar30 = (int)*(undefined8 *)(&stack0x00022068 + lVar5) + 0x278dcU ^ 0x2d6c918a;
  uVar30 = (int)*(undefined8 *)(&stack0x00022080 + lVar5) + 0x31713U ^
           (uVar30 << 5 | uVar30 >> 0x1b) * -0x61c8864f + 0x31599;
  uVar30 = (int)*(undefined8 *)(&stack0x00022058 + lVar5) + 0x3b54aU ^
           (uVar30 << 6 | uVar30 >> 0x1a) * -0x61c8864f + 0x315fa;
  *(undefined4 *)(&stack0x00021ea8 + lVar5) = 0x1a81f089;
  uVar25 = (uVar30 << 7 | uVar30 >> 0x19) * 0x1e3779b1 + 0x3165b & 0x7fffffff;
  *(uint *)(&stack0x00021eac + lVar5) = uVar25;
  *(undefined4 *)(&stack0x00021eb0 + lVar5) = 0x5fc13cc7;
  uVar30 = (uint)*(undefined8 *)(&stack0x000220a8 + lVar5) + 0x9e37;
  uVar26 = uVar27 + 0x13c6e ^ ((uVar30 ^ 0x13572468) << 2 | uVar30 >> 0x1e) * -0x61c8864f + 0x31476;
  uVar30 = (uint)*(undefined8 *)(&stack0x00022088 + lVar5);
  uVar26 = uVar30 + 0x1daa5 ^ (uVar26 << 3 | uVar26 >> 0x1d) * -0x61c8864f + 0x314d7;
  uVar26 = uVar51 + 0x278dc ^ (uVar26 << 4 | uVar26 >> 0x1c) * -0x61c8864f + 0x31538;
  uVar26 = uVar44 + 0x31713 ^ (uVar26 << 5 | uVar26 >> 0x1b) * -0x61c8864f + 0x31599;
  uVar26 = uVar7 + 0x3b54a ^ (uVar26 << 6 | uVar26 >> 0x1a) * -0x61c8864f + 0x315fa;
  uVar26 = (uVar26 << 7 | uVar26 >> 0x19) * 0x1e3779b1 + 0x3165b & 0x7fffffff;
  uVar8 = uVar25 + 0x13c6e ^ 0x91f4ad16;
  uVar8 = (uVar8 << 3 | uVar8 >> 0x1d) * -0x61c8864f + 0x314d7 ^ 0x5fc3176c;
  *(uint *)(&stack0x00021eb4 + lVar5) = uVar26;
  uVar26 = uVar26 + 0x278dc ^ (uVar8 << 4 | uVar8 >> 0x1c) * -0x61c8864f + 0x31538;
  uVar26 = (uVar26 << 5 | uVar26 >> 0x1b) * -0x61c8864f + 0x31599 ^ 0x6cce084b;
  uVar26 = (uVar26 << 6 | uVar26 >> 0x1a) * -0x61c8864f + 0x315fa ^ 0x6c1a2004;
  uVar26 = (uVar26 << 7 | uVar26 >> 0x19) * 0x1e3779b1 + 0x3165b;
  uVar8 = uVar26 & 0x7fffffff;
  uVar40 = ((uint)*(undefined8 *)(&stack0x000220a8 + lVar5) ^ uVar51) + 0x9e37;
  uVar40 = (uVar44 ^ uVar27) + 0x13c6e ^
           ((uVar40 ^ 0x13572468) << 2 | uVar40 >> 0x1e) * -0x61c8864f + 0x31476;
  uVar7 = (uVar7 ^ uVar30) + 0x1daa5 ^ (uVar40 << 3 | uVar40 >> 0x1d) * -0x61c8864f + 0x314d7;
  uVar7 = (uVar25 ^ 0x1a81f089) + 0x278dc ^ (uVar7 << 4 | uVar7 >> 0x1c) * -0x61c8864f + 0x31538;
  *(uint *)(&stack0x00021eb8 + lVar5) = uVar8;
  *(uint *)(&stack0x00021ebc + lVar5) =
       (uVar7 << 5 | uVar7 >> 0x1b) * 0x1e3779b1 + 0x31599 & 0x7fffffff;
  uVar7 = uVar51 + 0x13c6e ^
          ((uVar27 + 0x9e37 ^ 0x13572468) << 2 | uVar27 + 0x9e37 >> 0x1e) * -0x61c8864f + 0x31476;
  *(undefined8 *)(&stack0x00021ec0 + lVar5) = 0x2bbfb29d1c645cb4;
  uVar7 = (uVar7 << 3 | uVar7 >> 0x1d) * -0x61c8864f + 0x314d7 ^ 0x1a83cb2e;
  uVar7 = (uVar7 << 4 | uVar7 >> 0x1c) * -0x61c8864f + 0x31538 ^ 0x1866d590;
  *(uint *)(&stack0x00021ec8 + lVar5) =
       (uVar7 << 5 | uVar7 >> 0x1b) * 0x1e3779b1 + 0x31599 & 0x7fffffff;
  uVar30 = ((uVar43 * 0x80 | uVar44 >> 0x19) ^ (uVar30 << 3 | uVar30 >> 0x1d) ^
            *(uint *)(&stack0x000220b8 + lVar5) ^ (uVar26 * 0x800 | uVar8 >> 0x15)) & 0x7fffffff ^
           0x6a09e667;
  *(ulonglong *)(&stack0x00021fe0 + lVar5) = (ulonglong)uVar30;
  *(uint *)(&stack0x00021ecc + lVar5) = uVar30;
  iVar6 = 0;
  lVar19 = 0;
  pcVar47 = isalnum_exref;
  do {
    uVar30 = (&DAT_18002b7a0)[lVar19 * 9];
    uVar7 = (&DAT_18002b7a4)[lVar19 * 9];
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800042da;
    lVar17 = FUN_180005e70((longlong)(&stack0x00010440 + lVar5),(uint)uVar49,uVar30 ^ 0x4a3b29c1,
                           uVar7 ^ 0x13579bdf);
    if (lVar17 != 0) {
      *(int *)(&stack0x00022098 + lVar5) = iVar6;
      puVar34 = &DAT_18002b7a0 + lVar19 * 9;
      uVar30 = (&DAT_18002b7b8)[lVar19 * 9];
      uVar7 = 1;
      *(longlong *)(&stack0x000220b8 + lVar5) = lVar17;
      *(undefined4 **)(&stack0x000220a8 + lVar5) = puVar34;
      *(uint *)(&stack0x00022088 + lVar5) = uVar30;
      if ((uVar30 & 1) == 0) {
        if ((uVar30 & 2) == 0) goto LAB_180004318;
LAB_1800043f7:
        bVar52 = *(byte *)(lVar17 + 0xa0);
        if (bVar52 == 0) {
          uVar25 = 0x11c9dc5;
        }
        else {
          *(uint *)(&stack0x000220a0 + lVar5) = uVar7;
          pbVar37 = (byte *)(lVar17 + 0xa1);
          uVar25 = 0x811c9dc5;
          do {
            *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004438;
            uVar30 = tolower((uint)bVar52);
            *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004440;
            iVar6 = (*pcVar47)(bVar52);
            uVar7 = (uVar30 & 0xff ^ uVar25) * 0x1000193;
            if ((uVar30 & 0xff) == 0x5f) {
              uVar25 = uVar7;
            }
            if ((uVar30 & 0xef) == 0x2d) {
              uVar25 = uVar7;
            }
            if (iVar6 != 0) {
              uVar25 = uVar7;
            }
            bVar52 = *pbVar37;
            pbVar37 = pbVar37 + 1;
          } while (bVar52 != 0);
          uVar25 = uVar25 & 0x7fffffff;
          lVar17 = *(longlong *)(&stack0x000220b8 + lVar5);
          puVar34 = *(undefined4 **)(&stack0x000220a8 + lVar5);
          uVar30 = *(uint *)(&stack0x00022088 + lVar5);
          uVar7 = *(uint *)(&stack0x000220a0 + lVar5);
        }
        if ((uVar25 ^ puVar34[2]) != 0x2468ace1) {
          uVar7 = 0;
        }
        if ((uVar30 & 4) != 0) goto LAB_1800044be;
joined_r0x00018000489b:
        uVar25 = uVar7;
        if ((uVar30 & 8) == 0) goto LAB_18000432c;
LAB_18000469d:
        uVar7 = uVar25;
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800046ac;
        uVar25 = FUN_180005900((char *)(lVar17 + 0xe0));
        if ((uVar25 ^ puVar34[3]) != 0x4a3b29c1) {
          uVar7 = 0;
        }
        if ((char)uVar30 < '\0') goto LAB_1800046c4;
LAB_180004335:
        lVar17 = *(longlong *)(&stack0x000220b8 + lVar5);
      }
      else {
        bVar52 = *(byte *)(lVar17 + 0xa0);
        if (bVar52 == 0) {
          uVar7 = 0x11c9dc5;
        }
        else {
          pbVar37 = (byte *)(lVar17 + 0xa1);
          uVar7 = 0x811c9dc5;
          do {
            *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004378;
            uVar30 = tolower((uint)bVar52);
            *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004380;
            iVar6 = (*pcVar47)(bVar52);
            uVar25 = (uVar30 & 0xff ^ uVar7) * 0x1000193;
            if ((uVar30 & 0xff) == 0x5f) {
              uVar7 = uVar25;
            }
            if ((uVar30 & 0xef) == 0x2d) {
              uVar7 = uVar25;
            }
            if (iVar6 != 0) {
              uVar7 = uVar25;
            }
            bVar52 = *pbVar37;
            pbVar37 = pbVar37 + 1;
          } while (bVar52 != 0);
          uVar7 = uVar7 & 0x7fffffff;
          lVar17 = *(longlong *)(&stack0x000220b8 + lVar5);
          puVar34 = *(undefined4 **)(&stack0x000220a8 + lVar5);
          uVar30 = *(uint *)(&stack0x00022088 + lVar5);
        }
        uVar7 = (uint)((uVar7 ^ puVar34[2]) == 0x2468ace1);
        if ((uVar30 & 2) != 0) goto LAB_1800043f7;
LAB_180004318:
        if ((uVar30 & 4) == 0) goto joined_r0x00018000489b;
LAB_1800044be:
        cVar24 = *(char *)(lVar17 + 0xe0);
        if (cVar24 != '\0') {
          *(uint *)(&stack0x000220a0 + lVar5) = uVar7;
          pcVar15 = (char *)(lVar17 + 0xe0);
          do {
            while ((cVar24 == ' ' || (cVar24 == ','))) {
              pcVar21 = pcVar15 + 1;
              pcVar15 = pcVar15 + 1;
              cVar24 = *pcVar21;
            }
            if (cVar24 == '\0') break;
            lVar18 = 0;
            while ((cVar24 != '\0' && (cVar24 != ','))) {
              (&stack0x00021840)[lVar18 + lVar5] = cVar24;
              cVar24 = pcVar15[lVar18 + 1];
              if ((cVar24 == '\0') || (cVar24 == ',')) {
                pcVar21 = pcVar15 + lVar18 + 1;
                lVar18 = lVar18 + 1;
                goto LAB_1800045aa;
              }
              (&stack0x00021841)[lVar18 + lVar5] = cVar24;
              cVar24 = pcVar15[lVar18 + 2];
              if ((cVar24 == '\0') || (cVar24 == ',')) {
                pcVar21 = pcVar15 + lVar18 + 2;
                lVar18 = lVar18 + 2;
                goto LAB_1800045aa;
              }
              (&stack0x00021842)[lVar18 + lVar5] = cVar24;
              cVar24 = pcVar15[lVar18 + 3];
              if ((cVar24 == '\0') || (cVar24 == ',')) {
                pcVar21 = pcVar15 + lVar18 + 3;
                lVar18 = lVar18 + 3;
                goto LAB_1800045aa;
              }
              if (lVar18 == 0x7c) {
                pcVar21 = pcVar15 + 0x7f;
                lVar18 = 0x7f;
                goto LAB_1800045aa;
              }
              (&stack0x00021843)[lVar18 + lVar5] = cVar24;
              lVar41 = lVar18 + 4;
              lVar18 = lVar18 + 4;
              cVar24 = pcVar15[lVar41];
            }
            pcVar21 = pcVar15 + lVar18;
LAB_1800045aa:
            (&stack0x00021840)[lVar18 + lVar5] = 0;
            bVar52 = (&stack0x00021840)[lVar5];
            if (bVar52 != 0) {
              *(char **)(&stack0x00022078 + lVar5) = pcVar21;
              uVar7 = 0x811c9dc5;
              pbVar37 = &stack0x00021841 + lVar5;
              do {
                *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800045f8;
                uVar30 = tolower((uint)bVar52);
                *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004600;
                iVar6 = isalnum((uint)bVar52);
                uVar25 = (uVar30 & 0xff ^ uVar7) * 0x1000193;
                if ((uVar30 & 0xff) == 0x5f) {
                  uVar7 = uVar25;
                }
                if ((uVar30 & 0xef) == 0x2d) {
                  uVar7 = uVar25;
                }
                if (iVar6 != 0) {
                  uVar7 = uVar25;
                }
                bVar52 = *pbVar37;
                pbVar37 = pbVar37 + 1;
              } while (bVar52 != 0);
              lVar17 = *(longlong *)(&stack0x000220b8 + lVar5);
              puVar34 = *(undefined4 **)(&stack0x000220a8 + lVar5);
              uVar30 = *(uint *)(&stack0x00022088 + lVar5);
              pcVar21 = *(char **)(&stack0x00022078 + lVar5);
              if ((uVar7 & 0x7fffffff) == 0x307c6f61) {
                uVar7 = *(uint *)(&stack0x000220a0 + lVar5);
                pcVar47 = isalnum_exref;
                goto joined_r0x00018000489b;
              }
            }
            pcVar15 = pcVar21 + (*pcVar21 == ',');
            cVar24 = pcVar21[*pcVar21 == ','];
            pcVar47 = isalnum_exref;
          } while (cVar24 != '\0');
        }
        uVar7 = 0;
        uVar25 = 0;
        if ((uVar30 & 8) != 0) goto LAB_18000469d;
LAB_18000432c:
        if (-1 < (char)uVar30) goto LAB_180004335;
LAB_1800046c4:
        lVar17 = *(longlong *)(&stack0x000220b8 + lVar5);
        bVar52 = *(byte *)(lVar17 + 0x160);
        if (bVar52 == 0) {
          uVar25 = 0x11c9dc5;
        }
        else {
          *(uint *)(&stack0x000220a0 + lVar5) = uVar7;
          pbVar37 = (byte *)(lVar17 + 0x161);
          uVar25 = 0x811c9dc5;
          do {
            *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004708;
            uVar30 = tolower((uint)bVar52);
            *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004710;
            iVar6 = (*pcVar47)(bVar52);
            uVar7 = (uVar30 & 0xff ^ uVar25) * 0x1000193;
            if ((uVar30 & 0xff) == 0x5f) {
              uVar25 = uVar7;
            }
            if ((uVar30 & 0xef) == 0x2d) {
              uVar25 = uVar7;
            }
            if (iVar6 != 0) {
              uVar25 = uVar7;
            }
            bVar52 = *pbVar37;
            pbVar37 = pbVar37 + 1;
          } while (bVar52 != 0);
          uVar25 = uVar25 & 0x7fffffff;
          lVar17 = *(longlong *)(&stack0x000220b8 + lVar5);
          puVar34 = *(undefined4 **)(&stack0x000220a8 + lVar5);
          uVar30 = *(uint *)(&stack0x00022088 + lVar5);
          uVar7 = *(uint *)(&stack0x000220a0 + lVar5);
        }
        if ((uVar25 ^ puVar34[4]) != 0x13579bdf) {
          uVar7 = 0;
        }
      }
      if ((uVar30 & 0x10) != 0) {
        bVar52 = *(byte *)(lVar17 + 0x1e0);
        if (bVar52 == 0) {
          uVar25 = 0x11c9dc5;
        }
        else {
          *(uint *)(&stack0x000220a0 + lVar5) = uVar7;
          pbVar37 = (byte *)(lVar17 + 0x1e1);
          uVar25 = 0x811c9dc5;
          do {
            *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800047c8;
            uVar30 = tolower((uint)bVar52);
            *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800047d0;
            iVar6 = (*pcVar47)(bVar52);
            uVar7 = (uVar30 & 0xff ^ uVar25) * 0x1000193;
            if ((uVar30 & 0xff) == 0x5f) {
              uVar25 = uVar7;
            }
            if ((uVar30 & 0xef) == 0x2d) {
              uVar25 = uVar7;
            }
            if (iVar6 != 0) {
              uVar25 = uVar7;
            }
            bVar52 = *pbVar37;
            pbVar37 = pbVar37 + 1;
          } while (bVar52 != 0);
          uVar25 = uVar25 & 0x7fffffff;
          lVar17 = *(longlong *)(&stack0x000220b8 + lVar5);
          puVar34 = *(undefined4 **)(&stack0x000220a8 + lVar5);
          uVar30 = *(uint *)(&stack0x00022088 + lVar5);
          uVar7 = *(uint *)(&stack0x000220a0 + lVar5);
        }
        if ((uVar25 ^ puVar34[5]) != 0x2468ace1) {
          uVar7 = 0;
        }
      }
      if (((uVar30 & 0x20) != 0) && (*(int *)(lVar17 + 0x224) != puVar34[8])) {
        uVar7 = 0;
      }
      if (((uVar30 & 0x40) != 0) && (*(int *)(lVar17 + 0x220) != puVar34[7])) {
        uVar7 = 0;
      }
      iVar6 = *(int *)(&stack0x00022098 + lVar5) + uVar7;
      uVar49 = *(undefined8 *)(&stack0x000220b0 + lVar5);
    }
    lVar19 = lVar19 + 1;
  } while (lVar19 != 0x15);
  *(int *)(&stack0x00022098 + lVar5) = iVar6;
  *(int *)(&stack0x00021f60 + lVar5) = iVar6;
  *(undefined8 *)(&stack0x00022088 + lVar5) = 0;
  lVar19 = 0;
  do {
    *(longlong *)(&stack0x000220b8 + lVar5) = lVar19;
    uVar30 = (&DAT_18002baa0)[lVar19 * 7];
    uVar7 = (&DAT_18002baa4)[lVar19 * 7];
    uVar25 = (&DAT_18002baa8)[lVar19 * 7];
    uVar26 = (&DAT_18002baac)[lVar19 * 7];
    uVar49 = *(undefined8 *)(&stack0x000220b0 + lVar5);
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004979;
    pcVar15 = (char *)FUN_180005e70((longlong)(&stack0x00010440 + lVar5),(uint)uVar49,
                                    uVar7 ^ 0x13579bdf,uVar30 ^ 0x4a3b29c1);
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000498c;
    pcVar21 = (char *)FUN_180005e70((longlong)(&stack0x00010440 + lVar5),(uint)uVar49,
                                    uVar26 ^ 0x4a3b29c1,uVar25 ^ 0x2468ace1);
    if (((0 < *(int *)(&stack0x00022090 + lVar5)) && (pcVar15 != (char *)0x0)) &&
       (pcVar21 != (char *)0x0)) {
      pbVar37 = &stack0x00000101 + lVar5;
      pbVar31 = &stack0x000000c1 + lVar5;
      lVar17 = *(longlong *)(&stack0x00022060 + lVar5);
      pcVar16 = pcVar42;
LAB_1800049ef:
      *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800049fa;
      iVar6 = strcmp(pcVar16,pcVar15);
      if (iVar6 != 0) goto LAB_1800049d0;
      *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004a0b;
      iVar6 = strcmp(pcVar16 + 0x40,pcVar21);
      if (iVar6 != 0) goto LAB_1800049d0;
      *(undefined4 **)(&stack0x000220a8 + lVar5) = &DAT_18002baa0 + lVar19 * 7;
      bVar52 = pcVar16[0x80];
      uVar7 = 0x11c9dc5;
      uVar30 = 0x11c9dc5;
      if (bVar52 != 0) {
        uVar30 = 0x811c9dc5;
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004a4d;
          uVar25 = tolower((uint)bVar52);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004a59;
          iVar6 = isalnum((uint)bVar52);
          uVar26 = (uVar25 & 0xff ^ uVar30) * 0x1000193;
          if ((uVar25 & 0xff) == 0x5f) {
            uVar30 = uVar26;
          }
          if ((uVar25 & 0xef) == 0x2d) {
            uVar30 = uVar26;
          }
          if (iVar6 != 0) {
            uVar30 = uVar26;
          }
          bVar52 = *pbVar31;
          pbVar31 = pbVar31 + 1;
        } while (bVar52 != 0);
        uVar30 = uVar30 & 0x7fffffff;
      }
      uVar25 = *(uint *)(*(longlong *)(&stack0x000220a8 + lVar5) + 0x10);
      bVar52 = pcVar16[0xc0];
      if (bVar52 != 0) {
        uVar7 = 0x811c9dc5;
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004acd;
          uVar26 = tolower((uint)bVar52);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004ad6;
          iVar6 = isalnum((uint)bVar52);
          uVar8 = (uVar26 & 0xff ^ uVar7) * 0x1000193;
          if ((uVar26 & 0xff) == 0x5f) {
            uVar7 = uVar8;
          }
          if ((uVar26 & 0xef) == 0x2d) {
            uVar7 = uVar8;
          }
          if (iVar6 != 0) {
            uVar7 = uVar8;
          }
          bVar52 = *pbVar37;
          pbVar37 = pbVar37 + 1;
        } while (bVar52 != 0);
        uVar7 = uVar7 & 0x7fffffff;
      }
      *(ulonglong *)(&stack0x00022088 + lVar5) =
           (ulonglong)
           ((int)*(undefined8 *)(&stack0x00022088 + lVar5) +
           (uint)((*(int *)(pcVar16 + 0x100) ==
                   *(int *)(*(longlong *)(&stack0x000220a8 + lVar5) + 0x18) &&
                  (uVar7 ^ *(uint *)(*(longlong *)(&stack0x000220a8 + lVar5) + 0x14)) == 0x2468ace1)
                 && (uVar30 ^ uVar25) == 0x13579bdf));
    }
LAB_180004909:
    lVar19 = *(longlong *)(&stack0x000220b8 + lVar5) + 1;
  } while (lVar19 != 0x28);
  *(int *)(&stack0x00021f64 + lVar5) = (int)*(undefined8 *)(&stack0x00022088 + lVar5);
  uVar30 = (uint)(*(int *)(&stack0x00022068 + lVar5) == 3);
  *(ulonglong *)(&stack0x000220a0 + lVar5) = (ulonglong)uVar30;
  uVar7 = uVar30 + 1;
  if (*(int *)(&stack0x00022080 + lVar5) != 2) {
    uVar7 = uVar30;
  }
  *(uint *)(&stack0x000220b8 + lVar5) = uVar7;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x667c6911;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x4ba70f9b;
  pcVar15 = &stack0x00010440 + lVar5;
  uVar49 = *(undefined8 *)(&stack0x000220b0 + lVar5);
  uVar7 = (uint)uVar49;
  uVar30 = (uint)*(undefined8 *)(&stack0x00022090 + lVar5);
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004b7e;
  iVar6 = FUN_180005cd0(pcVar15,uVar7,(longlong)pcVar42,uVar30,
                        *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                        *(uint *)(&stack0xffffffffffffffe8 + lVar5));
  *(int *)(&stack0x000220a8 + lVar5) = iVar6;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x2047d5a7;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x7af2841;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004ba4;
  iVar6 = FUN_180005cd0(pcVar15,uVar7,(longlong)pcVar42,uVar30,
                        *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                        *(uint *)(&stack0xffffffffffffffe8 + lVar5));
  *(int *)(&stack0x00022078 + lVar5) = iVar6;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x667c6911;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x7af4527a;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004bca;
  iVar6 = FUN_180005cd0(pcVar15,uVar7,(longlong)pcVar42,uVar30,
                        *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                        *(uint *)(&stack0xffffffffffffffe8 + lVar5));
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004be3;
  iVar9 = FUN_180005b00((longlong)pcVar15,uVar7,0x6369e029,0x45334cec);
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004bfb;
  iVar10 = FUN_180005b00((longlong)pcVar15,uVar7,0x7c3044e6,0x45334cec);
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004c14;
  iVar11 = FUN_180005b00((longlong)pcVar15,uVar7,0x6369e029,0x56dfde64);
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004c2d;
  iVar12 = FUN_180005b00((longlong)pcVar15,uVar7,0x7c3044e6,0x56dfde64);
  auVar53._0_4_ = -(uint)(iVar9 == _DAT_18002b000);
  auVar53._4_4_ = -(uint)(iVar10 == _UNK_18002b004);
  auVar53._8_4_ = -(uint)(iVar11 == _UNK_18002b008);
  auVar53._12_4_ = -(uint)(iVar12 == _UNK_18002b00c);
  auVar54 = packssdw(auVar53,auVar53);
  auVar55._0_4_ = -(uint)(*(int *)(&stack0x00021fc8 + lVar5) == _DAT_18002b010);
  auVar55._4_4_ = -(uint)(*(int *)(&stack0x000220a8 + lVar5) == _UNK_18002b014);
  auVar55._8_4_ = -(uint)(*(int *)(&stack0x00022078 + lVar5) == _UNK_18002b018);
  auVar55._12_4_ = -(uint)(iVar6 == _UNK_18002b01c);
  auVar56._0_4_ = -(uint)(*(int *)(&stack0x00022058 + lVar5) == _DAT_18002b020);
  auVar56._4_4_ = -(uint)(*(int *)(&stack0x00021fe8 + lVar5) == _UNK_18002b024);
  auVar56._8_4_ = -(uint)(*(int *)(&stack0x00022008 + lVar5) == _UNK_18002b028);
  auVar56._12_4_ = -(uint)(*(int *)(&stack0x00021fc0 + lVar5) == _UNK_18002b02c);
  auVar57 = packssdw(auVar56,auVar55);
  auVar54 = packsswb(auVar57,auVar54);
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x56dfde64;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x1569150b;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004ceb;
  iVar6 = FUN_180006040(pcVar15,uVar7,(longlong)pcVar42,uVar30,
                        *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                        *(uint *)(&stack0xffffffffffffffe8 + lVar5));
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x56dfde64;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x3b781dbf;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004d15;
  iVar9 = FUN_180006040(pcVar15,uVar7,(longlong)pcVar42,uVar30,
                        *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                        *(uint *)(&stack0xffffffffffffffe8 + lVar5));
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x667c6911;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x171f0b09;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004d43;
  iVar10 = FUN_180006040(pcVar15,uVar7,(longlong)pcVar42,
                         (uint)*(undefined8 *)(&stack0x00022090 + lVar5),
                         *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar5));
  uVar4 = (ushort)(SUB161(auVar54 >> 7,0) & 1) | (ushort)(SUB161(auVar54 >> 0xf,0) & 1) << 1 |
          (ushort)(SUB161(auVar54 >> 0x17,0) & 1) << 2 |
          (ushort)(SUB161(auVar54 >> 0x1f,0) & 1) << 3 |
          (ushort)(SUB161(auVar54 >> 0x27,0) & 1) << 4 |
          (ushort)(SUB161(auVar54 >> 0x2f,0) & 1) << 5 |
          (ushort)(SUB161(auVar54 >> 0x37,0) & 1) << 6 |
          (ushort)(SUB161(auVar54 >> 0x3f,0) & 1) << 7 |
          (ushort)(SUB161(auVar54 >> 0x47,0) & 1) << 8 |
          (ushort)(SUB161(auVar54 >> 0x4f,0) & 1) << 9 |
          (ushort)(SUB161(auVar54 >> 0x57,0) & 1) << 10 |
          (ushort)(SUB161(auVar54 >> 0x5f,0) & 1) << 0xb;
  uVar30 = (uint)uVar4 - (uVar4 >> 1 & 0x555);
  uVar30 = (uVar30 >> 2 & 0x33333333) + (uVar30 & 0x33333333);
  iVar6 = (((uVar30 >> 4) + uVar30 & 0xf0f0f0f) * 0x1010101 >> 0x18) +
          (uint)(iVar10 == 1) + (uint)(iVar9 == 1) + (uint)(iVar6 == 1) +
          *(int *)(&stack0x000220b8 + lVar5);
  uVar30 = (uint)*(undefined8 *)(&stack0x00022090 + lVar5);
  if (0 < (int)uVar30) {
    *(int *)(&stack0x00022078 + lVar5) = iVar6;
    lVar17 = 0;
    pbVar37 = &stack0x000000c1 + lVar5;
    iVar6 = 0;
    lVar19 = *(longlong *)(&stack0x00022060 + lVar5);
    do {
      bVar52 = (&stack0x000000c0)[lVar17 * 0x104 + lVar5];
      if (bVar52 != 0) {
        *(int *)(&stack0x000220a8 + lVar5) = iVar6;
        uVar30 = 0x811c9dc5;
        *(byte **)(&stack0x000220b8 + lVar5) = pbVar37;
        do {
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004e48;
          uVar7 = tolower((uint)bVar52);
          *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004e50;
          iVar6 = isalnum((uint)bVar52);
          uVar25 = (uVar7 & 0xff ^ uVar30) * 0x1000193;
          if ((uVar7 & 0xff) == 0x5f) {
            uVar30 = uVar25;
          }
          if ((uVar7 & 0xef) == 0x2d) {
            uVar30 = uVar25;
          }
          if (iVar6 != 0) {
            uVar30 = uVar25;
          }
          bVar52 = *pbVar37;
          pbVar37 = pbVar37 + 1;
        } while (bVar52 != 0);
        iVar6 = *(int *)(&stack0x000220a8 + lVar5) + (uint)((uVar30 & 0x7fffffff) == 0x6ccaf138);
        uVar49 = *(undefined8 *)(&stack0x000220b0 + lVar5);
        lVar19 = *(longlong *)(&stack0x00022060 + lVar5);
        pbVar37 = *(byte **)(&stack0x000220b8 + lVar5);
      }
      uVar7 = (uint)uVar49;
      lVar17 = lVar17 + 1;
      pbVar37 = pbVar37 + 0x104;
    } while (lVar17 != lVar19);
    iVar6 = *(int *)(&stack0x00022078 + lVar5) + (uint)(iVar6 == 0x10);
    uVar30 = (uint)*(undefined8 *)(&stack0x00022090 + lVar5);
  }
  *(int *)(&stack0x00021f68 + lVar5) = iVar6;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x251b4cfe;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x67ca41f9;
  pcVar15 = &stack0x00010440 + lVar5;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004ed8;
  iVar9 = FUN_180005cd0(pcVar15,uVar7,(longlong)pcVar42,uVar30,
                        *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                        *(uint *)(&stack0xffffffffffffffe8 + lVar5));
  *(int *)(&stack0x000220a8 + lVar5) = iVar9;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x251b4cfe;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x183d8b67;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004eff;
  iVar9 = FUN_180005cd0(pcVar15,uVar7,(longlong)pcVar42,uVar30,
                        *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                        *(uint *)(&stack0xffffffffffffffe8 + lVar5));
  *(int *)(&stack0x000220b0 + lVar5) = iVar9;
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar5) = 0x5548baad;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar5) = 0x29ddeb14;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x31c14e0d;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x23f97dbd;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004f36;
  iVar9 = FUN_1800061f0((longlong)pcVar15,uVar7,(longlong)pcVar42,uVar30,
                        *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                        *(uint *)(&stack0xffffffffffffffe8 + lVar5),
                        *(uint *)(&stack0xfffffffffffffff0 + lVar5),
                        *(uint *)(&stack0xfffffffffffffff8 + lVar5));
  *(int *)(&stack0x000220b8 + lVar5) = iVar9;
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar5) = 0x5248b5f4;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar5) = 0x29ddeb14;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x31c14e0d;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x20f97904;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004f6d;
  iVar9 = FUN_1800061f0((longlong)pcVar15,uVar7,(longlong)pcVar42,uVar30,
                        *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                        *(uint *)(&stack0xffffffffffffffe8 + lVar5),
                        *(uint *)(&stack0xfffffffffffffff0 + lVar5),
                        *(uint *)(&stack0xfffffffffffffff8 + lVar5));
  *(int *)(&stack0x00022078 + lVar5) = iVar9;
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar5) = 0x4ba70f9b;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar5) = 0x6c166aba;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x667c6911;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x4ba70f9b;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004fa4;
  iVar10 = FUN_1800061f0((longlong)pcVar15,uVar7,(longlong)pcVar42,uVar30,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar5),
                         *(uint *)(&stack0xfffffffffffffff0 + lVar5),
                         *(uint *)(&stack0xfffffffffffffff8 + lVar5));
  *(undefined4 *)(&stack0xfffffffffffffff8 + lVar5) = 0x7af4527a;
  *(undefined4 *)(&stack0xfffffffffffffff0 + lVar5) = 0x6c166aba;
  *(undefined4 *)(&stack0xffffffffffffffe8 + lVar5) = 0x667c6911;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x7af4527a;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004fd8;
  iVar11 = FUN_1800061f0((longlong)pcVar15,uVar7,(longlong)pcVar42,uVar30,
                         *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                         *(uint *)(&stack0xffffffffffffffe8 + lVar5),
                         *(uint *)(&stack0xfffffffffffffff0 + lVar5),
                         *(uint *)(&stack0xfffffffffffffff8 + lVar5));
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180004ff1;
  pcVar21 = (char *)FUN_180005e70((longlong)pcVar15,uVar7,0x133c1bd8,0x22dcd889);
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000500b;
  pcVar15 = (char *)FUN_180005e70((longlong)pcVar15,uVar7,0x56dfde64,0x4af021b);
  iVar9 = 0;
  if ((0 < (int)uVar30) && (iVar9 = 0, pcVar16 = pcVar15, pcVar21 != (char *)0x0)) {
    while (iVar9 = 0, pcVar16 != (char *)0x0) {
      *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000504c;
      iVar9 = strcmp(pcVar42,pcVar21);
      if (iVar9 == 0) {
        *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000505c;
        iVar9 = strcmp(pcVar42 + 0x40,pcVar15);
        if (iVar9 == 0) {
          iVar9 = 1;
          break;
        }
      }
      pcVar42 = pcVar42 + 0x104;
      plVar1 = (longlong *)(&stack0x00022060 + lVar5);
      *plVar1 = *plVar1 + -1;
      pcVar16 = (char *)*plVar1;
    }
  }
  uVar30 = (*(int *)(&stack0x00022000 + lVar5) == 3) + 1;
  if (*(int *)(&stack0x000220a8 + lVar5) != 2) {
    uVar30 = (uint)(*(int *)(&stack0x00022000 + lVar5) == 3);
  }
  iVar9 = (uint)(*(int *)(&stack0x00022078 + lVar5) == 3) +
          (uint)(*(int *)(&stack0x000220b8 + lVar5) == 3) + (uint)(iVar10 == 2) +
          (uint)(iVar11 == 1) + iVar9 +
          (*(int *)(&stack0x000220b0 + lVar5) == 1) + uVar30 +
          (-(uint)(*(int *)(&stack0x00022058 + lVar5) == 1) & 1) +
          (uint)(*(int *)(&stack0x00022080 + lVar5) == 2) + *(int *)(&stack0x000220a0 + lVar5) +
          (uint)((int)*(undefined8 *)(&stack0x00022048 + lVar5) == 1 &&
                (int)*(undefined8 *)(&stack0x00022040 + lVar5) == 1);
  *(int *)(&stack0x00021f6c + lVar5) = iVar9;
  *(int *)(&stack0x00021f70 + lVar5) =
       (int)*(undefined8 *)(&stack0x00022088 + lVar5) + *(int *)(&stack0x00022098 + lVar5) + iVar6 +
       iVar9;
  *(undefined1 **)(&stack0xfffffffffffffff0 + lVar5) = &stack0x00021f80 + lVar5;
  *(undefined1 **)(&stack0xffffffffffffffe8 + lVar5) = &stack0x00021f74 + lVar5;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x71c2e3a5;
  puVar35 = &stack0x00021ed0 + lVar5;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180005188;
  FUN_180005710((longlong)puVar35,0x18,0x18002b2d0,0x72,*(uint *)(&stack0xffffffffffffffe0 + lVar5),
                *(int **)(&stack0xffffffffffffffe8 + lVar5),
                *(uint **)(&stack0xfffffffffffffff0 + lVar5));
  *(undefined1 **)(&stack0xfffffffffffffff0 + lVar5) = &stack0x00021f84 + lVar5;
  *(undefined1 **)(&stack0xffffffffffffffe8 + lVar5) = &stack0x00021f78 + lVar5;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x39a4f17c;
  puVar29 = &stack0x00021cf0 + lVar5;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800051c9;
  FUN_180005710((longlong)puVar29,0x18,0x18002b4a0,100,*(uint *)(&stack0xffffffffffffffe0 + lVar5),
                *(int **)(&stack0xffffffffffffffe8 + lVar5),
                *(uint **)(&stack0xfffffffffffffff0 + lVar5));
  *(undefined1 **)(&stack0xfffffffffffffff0 + lVar5) = &stack0x00021f88 + lVar5;
  *(undefined1 **)(&stack0xffffffffffffffe8 + lVar5) = &stack0x00021f7c + lVar5;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = 0x5c31d98e;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180005207;
  FUN_180005710((longlong)(&stack0x00021e90 + lVar5),0x10,0x18002b630,0x56,
                *(uint *)(&stack0xffffffffffffffe0 + lVar5),
                *(int **)(&stack0xffffffffffffffe8 + lVar5),
                *(uint **)(&stack0xfffffffffffffff0 + lVar5));
  uVar30 = ((uint)*(undefined8 *)(&stack0x00021ff8 + lVar5) ^ *(uint *)(&stack0x00021ff0 + lVar5) ^
            *(uint *)(&stack0x00021fe0 + lVar5) ^
           *(uint *)(&stack0x00021f94 + lVar5) ^ *(uint *)(&stack0x00021d14 + lVar5)) % 0xf4243;
  iVar11 = *(int *)(&stack0x00021f60 + lVar5);
  iVar12 = *(int *)(&stack0x00021f64 + lVar5);
  iVar6 = *(int *)(&stack0x00021f68 + lVar5);
  iVar9 = *(int *)(&stack0x00021f6c + lVar5);
  iVar48 = *(int *)(&stack0x00021f74 + lVar5);
  iVar10 = *(int *)(&stack0x00021f78 + lVar5);
  iVar50 = *(int *)(&stack0x00021f7c + lVar5);
  if (((iVar11 == 0x15) && (iVar12 == 0x28)) &&
     ((iVar6 == 0x12 &&
      ((((iVar9 == 0xc && (iVar48 == 8)) && (iVar10 == 7)) &&
       ((iVar50 == 6 &&
        (((*(uint *)(&stack0x00021f84 + lVar5) << 7 | *(uint *)(&stack0x00021f84 + lVar5) >> 0x19) ^
          *(uint *)(&stack0x00021f80 + lVar5) ^
         (*(uint *)(&stack0x00021f88 + lVar5) << 0xd | *(uint *)(&stack0x00021f88 + lVar5) >> 0x13))
         == 0x9d3daf88)))))))) {
    *(undefined1 (*) [16])(&stack0x00021f40 + lVar5) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x00021f30 + lVar5) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x00021f20 + lVar5) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x00021f10 + lVar5) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x00021f00 + lVar5) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x00021ef0 + lVar5) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x00021ee0 + lVar5) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x00021ed0 + lVar5) = (undefined1  [16])0x0;
    if (uVar30 == 0x2f8f6) {
      *(undefined4 *)(&stack0x00022090 + lVar5) = 6;
      *(undefined4 *)(&stack0x000220b0 + lVar5) = 8;
      *(undefined4 *)(&stack0x000220a8 + lVar5) = 0x28;
      *(undefined4 *)(&stack0x000220b8 + lVar5) = 0x15;
      *(undefined8 *)(&stack0x00021ff8 + lVar5) = 0x2f8f6;
      iVar11 = -0x8cbb611;
      bVar52 = 0x49;
      iVar50 = 0x47502943;
      lVar19 = 1;
      iVar12 = 0x47502932;
      iVar48 = 0x3c6ef35f;
      uVar30 = 0;
      do {
        iVar13 = iVar11 * 0x19660d + iVar48;
        (&stack0x00021ecf)[lVar19 + lVar5] =
             (&UNK_18002beff)[lVar19] ^ bVar52 + 0xb7 ^ (byte)((uint)iVar13 >> 0x10) ^ (byte)iVar13;
        iVar13 = iVar11 * 0x17385ca9;
        iVar11 = uVar30 + 1 + (uVar30 | 1) * 0x10 + iVar12 + iVar13;
        iVar13 = iVar13 + iVar50;
        (&stack0x00021ed0)[lVar19 + lVar5] =
             (byte)((uint)iVar13 >> 0x10) ^ bVar52 ^ (&DAT_18002bf00)[lVar19] ^ (byte)iVar13;
        uVar30 = uVar30 + 2;
        bVar52 = bVar52 + 0x92;
        iVar50 = iVar50 + 0x35f8ddc;
        lVar19 = lVar19 + 2;
        iVar12 = iVar12 + 0x35f8dba;
        iVar48 = iVar48 + 0x22;
      } while (lVar19 != 0x2f);
      (&stack0x00021efe)[lVar5] = 0;
      *(undefined8 *)(&stack0x00021cf0 + lVar5) = s_Shadow_control_plane_reconciled__18002b050._0_8_
      ;
      *(undefined8 *)(&stack0x00021cf8 + lVar5) = s_Shadow_control_plane_reconciled__18002b050._8_8_
      ;
      *(undefined8 *)(&stack0x00021d00 + lVar5) =
           s_Shadow_control_plane_reconciled__18002b050._16_8_;
      *(undefined8 *)(&stack0x00021d08 + lVar5) =
           s_Shadow_control_plane_reconciled__18002b050._24_8_;
      *(undefined8 *)(&stack0x00021d10 + lVar5) =
           s_Shadow_control_plane_reconciled__18002b050._32_8_;
      *(ulonglong *)(&stack0x00021d18 + lVar5) =
           CONCAT62(s_Shadow_control_plane_reconciled__18002b050._42_6_,
                    s_Shadow_control_plane_reconciled__18002b050._40_2_);
      *(ulonglong *)(&stack0x00021d1a + lVar5) =
           CONCAT26(s_Shadow_control_plane_reconciled__18002b050._48_2_,
                    s_Shadow_control_plane_reconciled__18002b050._42_6_);
      *(undefined8 *)(&stack0x00021d22 + lVar5) =
           s_Shadow_control_plane_reconciled__18002b050._50_8_;
      pcVar42 = "true";
      uVar30 = (uint)*(undefined8 *)(&stack0x00021ff8 + lVar5);
      puVar35 = &stack0x00021ed0 + lVar5;
      puVar29 = &stack0x00021cf0 + lVar5;
      iVar11 = *(int *)(&stack0x000220b8 + lVar5);
      iVar12 = *(int *)(&stack0x000220a8 + lVar5);
      iVar48 = *(int *)(&stack0x000220b0 + lVar5);
      iVar50 = *(int *)(&stack0x00022090 + lVar5);
      goto LAB_18000563d;
    }
  }
  else {
    *(undefined1 (*) [16])(&stack0x00021f40 + lVar5) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x00021f30 + lVar5) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x00021f20 + lVar5) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x00021f10 + lVar5) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x00021f00 + lVar5) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x00021ef0 + lVar5) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x00021ee0 + lVar5) = (undefined1  [16])0x0;
    *(undefined1 (*) [16])(&stack0x00021ed0 + lVar5) = (undefined1  [16])0x0;
  }
  if (iVar10 < 5 || iVar9 < 10) {
    if (iVar6 < 0xe || iVar12 < 0x22) {
      if (iVar11 < 0x12) {
        *(undefined8 *)(&stack0x00021d20 + lVar5) =
             s_Shadow_control_plane_unstable__C_18002b16f._48_8_;
        *(undefined8 *)(&stack0x00021d28 + lVar5) =
             s_Shadow_control_plane_unstable__C_18002b16f._56_8_;
        *(undefined8 *)(&stack0x00021d10 + lVar5) =
             s_Shadow_control_plane_unstable__C_18002b16f._32_8_;
        *(undefined8 *)(&stack0x00021d18 + lVar5) =
             s_Shadow_control_plane_unstable__C_18002b16f._40_8_;
        *(undefined8 *)(&stack0x00021d00 + lVar5) =
             s_Shadow_control_plane_unstable__C_18002b16f._16_8_;
        *(undefined8 *)(&stack0x00021d08 + lVar5) =
             s_Shadow_control_plane_unstable__C_18002b16f._24_8_;
        *(undefined8 *)(&stack0x00021cf0 + lVar5) =
             s_Shadow_control_plane_unstable__C_18002b16f._0_8_;
        *(undefined8 *)(&stack0x00021cf8 + lVar5) =
             s_Shadow_control_plane_unstable__C_18002b16f._8_8_;
        *(undefined4 *)(&stack0x00021d2f + lVar5) = 0x2e6574;
      }
      else {
        *(undefined8 *)(&stack0x00021d30 + lVar5) =
             s_Manifest_is_close__but_service_l_18002b11c._64_8_;
        *(undefined8 *)(&stack0x00021d38 + lVar5) =
             s_Manifest_is_close__but_service_l_18002b11c._72_8_;
        *(undefined8 *)(&stack0x00021d20 + lVar5) =
             s_Manifest_is_close__but_service_l_18002b11c._48_8_;
        *(undefined8 *)(&stack0x00021d28 + lVar5) =
             s_Manifest_is_close__but_service_l_18002b11c._56_8_;
        *(undefined8 *)(&stack0x00021d10 + lVar5) =
             s_Manifest_is_close__but_service_l_18002b11c._32_8_;
        *(undefined8 *)(&stack0x00021d18 + lVar5) =
             s_Manifest_is_close__but_service_l_18002b11c._40_8_;
        *(undefined8 *)(&stack0x00021d00 + lVar5) =
             s_Manifest_is_close__but_service_l_18002b11c._16_8_;
        *(undefined8 *)(&stack0x00021d08 + lVar5) =
             s_Manifest_is_close__but_service_l_18002b11c._24_8_;
        *(undefined8 *)(&stack0x00021cf0 + lVar5) =
             s_Manifest_is_close__but_service_l_18002b11c._0_8_;
        *(undefined8 *)(&stack0x00021cf8 + lVar5) =
             s_Manifest_is_close__but_service_l_18002b11c._8_8_;
        *(undefined4 *)(&stack0x00021d3f + lVar5) = 0x2e6574;
      }
    }
    else {
      *(ulonglong *)(&stack0x00021d2b + lVar5) =
           CONCAT35(s_Control_plane_is_almost_stable__N_18002b0d1._64_3_,
                    s_Control_plane_is_almost_stable__N_18002b0d1._59_5_);
      *(undefined8 *)(&stack0x00021d33 + lVar5) =
           s_Control_plane_is_almost_stable__N_18002b0d1._67_8_;
      *(undefined8 *)(&stack0x00021d20 + lVar5) =
           s_Control_plane_is_almost_stable__N_18002b0d1._48_8_;
      *(ulonglong *)(&stack0x00021d28 + lVar5) =
           CONCAT53(s_Control_plane_is_almost_stable__N_18002b0d1._59_5_,
                    s_Control_plane_is_almost_stable__N_18002b0d1._56_3_);
      *(undefined8 *)(&stack0x00021d10 + lVar5) =
           s_Control_plane_is_almost_stable__N_18002b0d1._32_8_;
      *(undefined8 *)(&stack0x00021d18 + lVar5) =
           s_Control_plane_is_almost_stable__N_18002b0d1._40_8_;
      *(undefined8 *)(&stack0x00021d00 + lVar5) =
           s_Control_plane_is_almost_stable__N_18002b0d1._16_8_;
      *(undefined8 *)(&stack0x00021d08 + lVar5) =
           s_Control_plane_is_almost_stable__N_18002b0d1._24_8_;
      *(undefined8 *)(&stack0x00021cf0 + lVar5) =
           s_Control_plane_is_almost_stable__N_18002b0d1._0_8_;
      *(undefined8 *)(&stack0x00021cf8 + lVar5) =
           s_Control_plane_is_almost_stable__N_18002b0d1._8_8_;
    }
  }
  else {
    *(undefined8 *)(&stack0x00021d20 + lVar5) = s_Visible_topology_converges__but_s_18002b08a._48_8_
    ;
    *(undefined8 *)(&stack0x00021d28 + lVar5) = s_Visible_topology_converges__but_s_18002b08a._56_8_
    ;
    *(undefined8 *)(&stack0x00021d10 + lVar5) = s_Visible_topology_converges__but_s_18002b08a._32_8_
    ;
    *(undefined8 *)(&stack0x00021d18 + lVar5) = s_Visible_topology_converges__but_s_18002b08a._40_8_
    ;
    *(undefined8 *)(&stack0x00021d00 + lVar5) = s_Visible_topology_converges__but_s_18002b08a._16_8_
    ;
    *(undefined8 *)(&stack0x00021d08 + lVar5) = s_Visible_topology_converges__but_s_18002b08a._24_8_
    ;
    *(undefined8 *)(&stack0x00021cf0 + lVar5) = s_Visible_topology_converges__but_s_18002b08a._0_8_;
    *(undefined8 *)(&stack0x00021cf8 + lVar5) = s_Visible_topology_converges__but_s_18002b08a._8_8_;
    *(undefined8 *)(&stack0x00021d2f + lVar5) = 0x2e737466697264;
  }
  pcVar42 = "false";
LAB_18000563d:
  uVar2 = *(undefined4 *)(&stack0x00021f70 + lVar5);
  *(int *)(&stack0x00000030 + lVar5) = iVar50;
  *(int *)(&stack0x00000028 + lVar5) = iVar10;
  *(int *)((longlong)aiStackX_8 + lVar5 + 0x18) = iVar48;
  *(int *)((longlong)aiStackX_8 + lVar5 + 0x10) = iVar9;
  *(int *)((longlong)aiStackX_8 + lVar5 + 8) = iVar6;
  *(int *)((longlong)aiStackX_8 + lVar5) = iVar12;
  *(int *)((longlong)aiStackX_8 + lVar5 + -8) = iVar11;
  *(undefined1 **)(&stack0xfffffffffffffff8 + lVar5) = puVar35;
  *(undefined1 **)(&stack0xfffffffffffffff0 + lVar5) = puVar29;
  *(uint *)(&stack0xffffffffffffffe8 + lVar5) = uVar30;
  *(undefined4 *)(&stack0xffffffffffffffe0 + lVar5) = uVar2;
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x180005693;
  FUN_180006ee0(&stack0x00021840 + lVar5,0x4b0,
                "{\"ok\":%s,\"score\":%d,\"signature\":%d,\"summary\":\"%s\",\"flag\":\"%s\",\"manifest\":%d,\"edges\":%d,\"meta\":%d,\"shadow\":%d,\"vm\":%d,\"vm2\":%d,\"vm3\":%d}"
                ,pcVar42);
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x18000569b;
  lVar19 = FUN_180006f50((longlong)(&stack0x00021840 + lVar5));
  *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800056aa;
  puVar22 = malloc(lVar19 + 1U);
  if (puVar22 != (undefined8 *)0x0) {
    *(undefined8 *)((longlong)&uStack_48 + lVar5) = 0x1800056c4;
    FUN_180007e80(puVar22,(undefined8 *)(&stack0x00021840 + lVar5),lVar19 + 1U);
  }
  return puVar22;
code_r0x000180002a1d:
  pcVar15 = pcVar15 + 0x228;
  pbVar31 = pbVar31 + 0x228;
  pbVar37 = pbVar37 + 0x228;
  puVar29 = (undefined1 *)(*(longlong *)(&stack0x000220b8 + lVar5) + 0x228);
  puVar35 = (undefined1 *)(*(longlong *)(&stack0x000220a8 + lVar5) + 0x228);
  lVar17 = lVar17 + -1;
  if (lVar17 == 0) goto LAB_180002930;
  goto LAB_180002a00;
LAB_1800049d0:
  pcVar16 = pcVar16 + 0x104;
  pbVar31 = pbVar31 + 0x104;
  pbVar37 = pbVar37 + 0x104;
  lVar17 = lVar17 + -1;
  if (lVar17 == 0) goto LAB_180004909;
  goto LAB_1800049ef;
}
