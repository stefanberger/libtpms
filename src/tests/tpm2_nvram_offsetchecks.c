#include <stdio.h>
#include <assert.h>

#define NV_C
#include "Tpm.h"

#define CHECK_OFFSET(structure, field, expoffset) \
  if (offsetof(structure, field) != expoffset) { \
    printf(">>> Expected offset of field %s in %s to be %u but is %zu\n", \
           #field, #structure, (unsigned int)expoffset, \
           offsetof(structure, field)); \
    ret |= 1; \
  }

#define CHECK_SIZE(structure, expsize) \
  if (sizeof(structure) != expsize) { \
    printf(">>> Expected size of %s to be %u but is %zu\n", \
           #structure, (unsigned int)expsize, sizeof(structure)); \
    ret |= 1; \
  }

int privateExponent_check_offsets(void)
{
  int ret = 0;

  CHECK_OFFSET(privateExponent_t, Q, 0);
  CHECK_OFFSET(privateExponent_t, dP, 152);
  CHECK_OFFSET(privateExponent_t, dQ, 304);
  CHECK_OFFSET(privateExponent_t, qInv, 456);

  CHECK_SIZE(privateExponent_t, 608);

  return ret;
}

int TPMT_PUBLIC_check_offsets(void)
{
  int ret = 0;

  CHECK_OFFSET(TPMT_PUBLIC, type, 0);
  CHECK_OFFSET(TPMT_PUBLIC, nameAlg, 2);
  CHECK_OFFSET(TPMT_PUBLIC, objectAttributes, 4);
  CHECK_OFFSET(TPMT_PUBLIC, authPolicy, 8);
  CHECK_OFFSET(TPMT_PUBLIC, parameters, 60);
  CHECK_OFFSET(TPMT_PUBLIC, unique, 80);

  CHECK_SIZE(TPMT_PUBLIC, 340);

  return ret;
}

int OBJECT_check_offsets(void)
{
  int ret = 0;

  CHECK_OFFSET(OBJECT, attributes, 0);
  CHECK_OFFSET(OBJECT, publicArea, 4);
  CHECK_OFFSET(OBJECT, sensitive, 344);
  CHECK_OFFSET(OBJECT, privateExponent, 1088);
  CHECK_OFFSET(OBJECT, qualifiedName, 1696);
  CHECK_OFFSET(OBJECT, evictHandle, 1752);
  CHECK_OFFSET(OBJECT, name, 1756);

  CHECK_SIZE(OBJECT, 1816);

  return ret;
}

int DRBG_STATE_check_offsets(void)
{
  int ret = 0;

  CHECK_OFFSET(DRBG_STATE, reseedCounter, 0);
  CHECK_OFFSET(DRBG_STATE, magic, 8);
  CHECK_OFFSET(DRBG_STATE, seed, 16);
  CHECK_OFFSET(DRBG_STATE, lastValue, 64);

  CHECK_SIZE(DRBG_STATE, 80);

  return ret;
}

int persistent_data_check_offsets(void)
{
  int ret = 0;

  CHECK_OFFSET(PERSISTENT_DATA, disableClear, 8);
  CHECK_OFFSET(PERSISTENT_DATA, ownerAlg, 12);
  CHECK_OFFSET(PERSISTENT_DATA, endorsementAlg, 14);
  CHECK_OFFSET(PERSISTENT_DATA, ownerPolicy, 18);
  CHECK_OFFSET(PERSISTENT_DATA, endorsementPolicy, 68);
  CHECK_OFFSET(PERSISTENT_DATA, lockoutPolicy, 118);
  CHECK_OFFSET(PERSISTENT_DATA, ownerAuth, 168);
  CHECK_OFFSET(PERSISTENT_DATA, endorsementAuth, 218);
  CHECK_OFFSET(PERSISTENT_DATA, lockoutAuth, 268);
  CHECK_OFFSET(PERSISTENT_DATA, EPSeed, 318);
  CHECK_OFFSET(PERSISTENT_DATA, SPSeed, 384);
  CHECK_OFFSET(PERSISTENT_DATA, PPSeed, 450);
  CHECK_OFFSET(PERSISTENT_DATA, phProof, 516);
  CHECK_OFFSET(PERSISTENT_DATA, shProof, 582);
  CHECK_OFFSET(PERSISTENT_DATA, ehProof, 648);
  CHECK_OFFSET(PERSISTENT_DATA, totalResetCount, 720);
  CHECK_OFFSET(PERSISTENT_DATA, resetCount, 728);
  CHECK_OFFSET(PERSISTENT_DATA, pcrPolicies, 732);
  CHECK_OFFSET(PERSISTENT_DATA, pcrAllocated, 784);
  CHECK_OFFSET(PERSISTENT_DATA, ppList, 808);
  CHECK_OFFSET(PERSISTENT_DATA, failedTries, 824);
  CHECK_OFFSET(PERSISTENT_DATA, recoveryTime, 832);
  CHECK_OFFSET(PERSISTENT_DATA, lockoutRecovery, 836);
  CHECK_OFFSET(PERSISTENT_DATA, lockOutAuthEnabled, 840);
  CHECK_OFFSET(PERSISTENT_DATA, orderlyState, 844);
  CHECK_OFFSET(PERSISTENT_DATA, auditCommands, 846);
  CHECK_OFFSET(PERSISTENT_DATA, auditHashAlg, 860);
  CHECK_OFFSET(PERSISTENT_DATA, auditCounter, 864);
  CHECK_OFFSET(PERSISTENT_DATA, algorithmSet, 872);
  CHECK_OFFSET(PERSISTENT_DATA, firmwareV1, 876);
  CHECK_OFFSET(PERSISTENT_DATA, firmwareV2, 880);
  CHECK_OFFSET(PERSISTENT_DATA, timeEpoch, 884);

  CHECK_SIZE(PERSISTENT_DATA, 888);

  return ret;
}

int state_reset_data_check_offsets(void)
{
  int ret = 0;

  CHECK_OFFSET(STATE_RESET_DATA, nullProof, 8);
  CHECK_OFFSET(STATE_RESET_DATA, nullSeed, 74);
  CHECK_OFFSET(STATE_RESET_DATA, clearCount, 140);
  CHECK_OFFSET(STATE_RESET_DATA, objectContextID, 144);
  CHECK_OFFSET(STATE_RESET_DATA, contextArray, 152);
  CHECK_OFFSET(STATE_RESET_DATA, contextCounter, 216);
  CHECK_OFFSET(STATE_RESET_DATA, commandAuditDigest, 224);
  CHECK_OFFSET(STATE_RESET_DATA, restartCount, 276);
  CHECK_OFFSET(STATE_RESET_DATA, pcrCounter, 280);
  CHECK_OFFSET(STATE_RESET_DATA, commitCounter, 288);
  CHECK_OFFSET(STATE_RESET_DATA, commitNonce, 296);
  CHECK_OFFSET(STATE_RESET_DATA, commitArray, 346);

  CHECK_SIZE(STATE_RESET_DATA, 368);

  return ret;
}

int state_clear_data_check_offsets(void)
{
  int ret = 0;

  CHECK_OFFSET(STATE_CLEAR_DATA, shEnable, 8);
  CHECK_OFFSET(STATE_CLEAR_DATA, ehEnable, 12);
  CHECK_OFFSET(STATE_CLEAR_DATA, phEnableNV, 16);
  CHECK_OFFSET(STATE_CLEAR_DATA, platformAlg, 20);
  CHECK_OFFSET(STATE_CLEAR_DATA, platformPolicy, 22);
  CHECK_OFFSET(STATE_CLEAR_DATA, platformAuth, 72);
  CHECK_OFFSET(STATE_CLEAR_DATA, pcrSave, 124);
  CHECK_OFFSET(STATE_CLEAR_DATA, pcrAuthValues, 1728);

  CHECK_SIZE(STATE_CLEAR_DATA, 1780);

  return ret;
}

int orderly_data_check_offsets(void)
{
  int ret = 0;

  CHECK_OFFSET(ORDERLY_DATA, clock, 8);
  CHECK_OFFSET(ORDERLY_DATA, clockSafe, 16);
  CHECK_OFFSET(ORDERLY_DATA, drbgState, 24);
  CHECK_OFFSET(ORDERLY_DATA, selfHealTimer, 104);
  CHECK_OFFSET(ORDERLY_DATA, lockoutTimer, 112);
  CHECK_OFFSET(ORDERLY_DATA, time, 120);

  CHECK_SIZE(ORDERLY_DATA, 128);

  return ret;
}

int main(void)
{
  assert(privateExponent_check_offsets() == 0);
  assert(TPMT_PUBLIC_check_offsets() == 0);
  assert(OBJECT_check_offsets() == 0);
  assert(DRBG_STATE_check_offsets() == 0);
  assert(persistent_data_check_offsets() == 0);

  printf("sizeof(PERSISTENT_DATA) = %zd\n", sizeof(PERSISTENT_DATA));
  printf("available space = %ld\n",
         NV_STATE_RESET_DATA - sizeof(PERSISTENT_DATA));
  printf("--------------\n");

  assert(state_reset_data_check_offsets() == 0);

  printf("NV_STATE_RESET_DATA = %lu (0x%lx)\n",
         NV_STATE_RESET_DATA,
         NV_STATE_RESET_DATA);
  assert(NV_STATE_RESET_DATA == 0x600);
  printf("sizeof(STATE_RESET_DATA) = %zd\n", sizeof(STATE_RESET_DATA));
  printf("available space = %ld\n",
         NV_STATE_CLEAR_DATA - sizeof(STATE_RESET_DATA) - NV_STATE_RESET_DATA);
  printf("--------------\n");

  assert(state_clear_data_check_offsets() == 0);

  printf("NV_STATE_CLEAR_DATA = %lu (0x%lx)\n",
         NV_STATE_CLEAR_DATA,
         NV_STATE_CLEAR_DATA);
  assert(NV_STATE_CLEAR_DATA == 0xa00);
  printf("sizeof(STATE_CLEAR_DATA) = %zd\n", sizeof(STATE_CLEAR_DATA));
  printf("available space = %ld\n",
         NV_ORDERLY_DATA - sizeof(STATE_CLEAR_DATA) - NV_STATE_CLEAR_DATA);
  printf("--------------\n");

  assert(orderly_data_check_offsets() == 0);

  printf("NV_ORDERLY_DATA = %lu (0x%lx)\n",
         NV_ORDERLY_DATA,
         NV_ORDERLY_DATA);
  assert(NV_ORDERLY_DATA == 0x1200);
  printf("sizeof(ORDERLY_DATA) = %zd\n", sizeof(ORDERLY_DATA));
  printf("available space = %ld\n",
         NV_INDEX_RAM_DATA - sizeof(ORDERLY_DATA) - NV_ORDERLY_DATA);
  printf("--------------\n");

  printf("NV_INDEX_RAM_DATA = %lu (0x%lx)\n",
         NV_INDEX_RAM_DATA,
         NV_INDEX_RAM_DATA);
  printf("sizeof(s_indexOrderlyRam) = %zd\n", sizeof(s_indexOrderlyRam));
  printf("available space = %ld\n",
         NV_USER_DYNAMIC - NV_INDEX_RAM_DATA);
  assert(NV_INDEX_RAM_DATA == 0x1400);
  printf("--------------\n");

  printf("NV_USER_DYNAMIC = %lu (0x%lx)\n",
         NV_USER_DYNAMIC,
         NV_USER_DYNAMIC);
  printf("available space = %ld\n",
         NV_USER_DYNAMIC_END - NV_USER_DYNAMIC);
  assert(NV_USER_DYNAMIC == 0x1600);

  return 0;
}
