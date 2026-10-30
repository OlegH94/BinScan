/* Esempio sintetico in stile pseudocodice Ghidra, per validare le regole. */

undefined4 vulnerable_copy(char *param_1)
{
  char local_28 [32];
  strcpy(local_28,param_1);
  return 0;
}

undefined4 vulnerable_network_read(int param_1)
{
  char local_40 [16];
  int iVar1;
  iVar1 = recv(param_1,local_40,0x400,0);
  return iVar1;
}

undefined4 safe_copy(char *param_1)
{
  char local_20 [16];
  if (strlen(param_1) < 0x10) {
    strncpy(local_20,param_1,0x10);
  }
  return 0;
}

void vulnerable_gets(void)
{
  char local_18 [24];
  gets(local_18);
  return;
}

void vulnerable_format(char *param_1)
{
  printf(param_1);
  return;
}

undefined4 vulnerable_taint_chain(int param_1)
{
  char local_50 [64];
  char local_10 [64];
  int iVar1;
  iVar1 = recv(param_1,local_50,0x400,0);
  strcpy(local_10,local_50);
  return iVar1;
}
