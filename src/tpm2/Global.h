/********************************************************************************/
/*										*/
/*			Internal Global Type Definitions			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2016 - 2024				*/
/*										*/
/********************************************************************************/

//** Description

// This file contains internal global type definitions and data declarations that
// are need between subsystems. The instantiation of global data is in Global.c.
// The initialization of global data is in the subsystem that is the primary owner
// of the data.
//
// The first part of this file has the 'typedefs' for structures and other defines
// used in many portions of the code. After the 'typedef' section, is a section that
// defines global values that are only present in RAM. The next three sections
// define the structures for the NV data areas: persistent, orderly, and state
// save. Additional sections define the data that is used in specific modules. That
// data is private to the module but is collected here to simplify the management
// of the instance data.
//
// All the data is instanced in Global.c.
#if !defined _TPM_H_
#  error "Should only be instanced in TPM.h"
#endif

//** Includes

#ifndef GLOBAL_H
#  define GLOBAL_H

_REDUCE_WARNING_LEVEL_(2)
#  include <string.h>
#  include <stddef.h>
_NORMAL_WARNING_LEVEL_
#include "BackwardsCompatibility.h" // libtpms added

#  include "GpMacros.h"
#  include "Capabilities.h"
#  include "TpmTypes.h"  // requires GpMacros & Capabilities
#  include "CommandAttributes.h"
#  include "CryptTest.h"

#  ifndef MATH_LIB
#    error MATH_LIB required
#  endif
#  include LIB_INCLUDE(TpmTo, MATH_LIB, Math)

#  include "CryptHash.h"
#  include "CryptSym.h"
#  include "CryptRand.h"
#  include "CryptEcc.h"
#  include "CryptRsa.h"
#  include "CryptTest.h"
#  include "NV.h"
#  include "ACT.h"
#  include "Utils.h"		    // libtpms added

//** Defines and Types

//*** Other Types
// An AUTH_VALUE is a BYTE array containing a digest (TPMU_HA)
typedef BYTE AUTH_VALUE[sizeof(TPMU_HA)];

// A TIME_INFO is a BYTE array that can contain a TPMS_TIME_INFO
typedef BYTE TIME_INFO[sizeof(TPMS_TIME_INFO)];

// A NAME is a BYTE array that can contain a TPMU_NAME
typedef BYTE NAME[sizeof(TPMU_NAME)];

// Definition for a PROOF value
TPM2B_TYPE(PROOF, PROOF_SIZE);

// Definition for a Primary Seed value
TPM2B_TYPE(SEED, PRIMARY_SEED_SIZE);

// A CLOCK_NONCE is used to tag the time value in the authorization session and
// in the ticket computation so that the ticket expires when there is a time
// discontinuity. When the clock stops during normal operation, the nonce is
// 64-bit value kept in RAM but it is a 32-bit counter when the clock only stops
// during power events.
#  if CLOCK_STOPS
typedef UINT64 CLOCK_NONCE;
#  else
typedef UINT32 CLOCK_NONCE;
#  endif

//** Loaded Object Structures
//*** Description
// The structures in this section define the object layout as it exists in TPM
// memory.
//
// Two types of objects are defined: an ordinary object such as a key, and a
// sequence object that may be a hash, HMAC, or event.
//
//*** OBJECT_ATTRIBUTES
// An OBJECT_ATTRIBUTES structure contains the variable attributes of an object.
// These properties are not part of the public properties but are used by the
// TPM in managing the object. An OBJECT_ATTRIBUTES is used in the definition of
// the OBJECT data type.

typedef struct
{
#if LITTLE_ENDIAN_TPM == YES                          /* libtpms added */
    unsigned publicOnly : 1;    //0) SET if only the public portion of
    //   an object is loaded
    unsigned epsHierarchy : 1;  //1) SET if the object belongs to EPS
    //   Hierarchy
    unsigned ppsHierarchy : 1;  //2) SET if the object belongs to PPS
    //   Hierarchy
    unsigned spsHierarchy : 1;  //3) SET f the object belongs to SPS
    //   Hierarchy
    unsigned evict : 1;         //4) SET if the object is a platform or
    //   owner evict object.  Platform-
    //   evict object belongs to PPS
    //   hierarchy, owner-evict object
    //   belongs to SPS or EPS hierarchy.
    //   This bit is also used to mark a
    //   completed sequence object so it
    //   will be flush when the
    //   SequenceComplete command succeeds.
    unsigned primary   : 1;     //5) SET for a primary object
    unsigned temporary : 1;     //6) SET for a temporary object
    unsigned stClear   : 1;     //7) SET for an stClear object
    unsigned hmacSeq   : 1;     //8) SET for an HMAC or MAC sequence
    //   object
    unsigned hashSeq    : 1;    //9) SET for a hash sequence object
    unsigned eventSeq   : 1;    //10) SET for an event sequence object
    unsigned ticketSafe : 1;    //11) SET if a ticket is safe to create
    //    for hash sequence object
    unsigned firstBlock : 1;    //12) SET if the first block of hash
    //    data has been received.  It
    //    works with ticketSafe bit
    unsigned isParent : 1;      //13) SET if the key has the proper
    //    attributes to be a parent key
    unsigned privateExp : 1;    //14) SET when the private exponent  	// libtpms: keep
    //                                          //    of an RSA key has been validated.
#if 0									// lbtpms added
    unsigned not_used_14 : 1;
#endif									// libtpms added
    unsigned occupied    : 1;  //15) SET when the slot is occupied.
    unsigned derivation  : 1;  //16) SET when the key is a derivation
    //        parent
    unsigned external : 1;     //17) SET when the object is loaded with
    //    TPM2_LoadExternal();
    unsigned reserved : 14;    //18-31)			/* libtpms added */
#endif							/* libtpms added */
#if BIG_ENDIAN_TPM == YES				/* libtpms added begin */
    unsigned reserved : 14;      //18-31)
    unsigned external : 1;       //17) SET when the object is loaded with
    unsigned derivation : 1;     //16) SET when the key is a derivation
    unsigned occupied : 1;       //15) SET when the slot is occupied.
    unsigned privateExp : 1;     //14) SET when the private exponent  // libtpms: keep
    unsigned isParent : 1;       //13) SET if the key has the proper
    unsigned firstBlock : 1;     //12) SET if the first block of hash
    unsigned ticketSafe : 1;     //11) SET if a ticket is safe to create
    unsigned eventSeq : 1;       //10) SET for an event sequence object
    unsigned hashSeq : 1;        //9) SET for a hash sequence object
    unsigned hmacSeq : 1;        //8) SET for an HMAC sequence object
    unsigned stClear : 1;        //7) SET for an stClear object
    unsigned temporary : 1;      //6) SET for a temporary object
    unsigned primary : 1;        //5) SET for a primary object

    unsigned evict : 1;          //4) SET if the object is a platform or
    unsigned spsHierarchy : 1;   //3) SET f the object belongs to SPS
    unsigned ppsHierarchy : 1;   //2) SET if the object belongs to PPS
    unsigned epsHierarchy : 1;   //1) SET if the object belongs to EPS
    unsigned publicOnly : 1;     //0) SET if only the public portion of
#endif                                                /* libtpms added end */
} OBJECT_ATTRIBUTES;

#  if ALG_RSA
// There is an overload of the sensitive.rsa.t.size field of a TPMT_SENSITIVE when an
// RSA key is loaded. When the sensitive->sensitive contains an RSA key with all of
// the CRT values, then the MSB of the size field will be set to indicate that the
// buffer contains all 5 of the CRT private key values.
#    define RSA_prime_flag 0x8000
#  endif

//*** OBJECT Structure
// An OBJECT structure holds the object public, sensitive, and meta-data
// associated. This structure is implementation dependent. For this
// implementation, the structure is not optimized for space but rather
// for clarity of the reference implementation. Other implementations
// may choose to overlap portions of the structure that are not used
// simultaneously. These changes would necessitate changes to the source
// code but those changes would be compatible with the reference
// implementation.

typedef struct OBJECT
{
    // The attributes field is required to be first followed by the publicArea.
    // This allows the overlay of the object structure and a sequence structure
    OBJECT_ATTRIBUTES attributes;     // object attributes
    TPMT_PUBLIC       publicArea;     // public area of an object
    TPMT_SENSITIVE    sensitive;      // sensitive area of an object
#if ALG_RSA				// libtpms added begin: keep
    privateExponent_t   privateExponent;    // Additional field for the private
#endif					// libtpms added end
    TPM2B_NAME        qualifiedName;  // object qualified name
    TPMI_DH_OBJECT    evictHandle;    // if the object is an evict object,
    // the original handle is kept here.
    // The 'working' handle will be the
    // handle of an object slot.
    TPM2B_NAME name;                  // Name of the object name. Kept here
    // to avoid repeatedly computing it.
    TPMI_RH_HIERARCHY hierarchy;      // Hierarchy for the object. While the
    // base hierarchy can be deduced from
    // 'attributes', if the hierarchy is
    // firmware-bound or SVN-bound then
    // this field carries additional metadata
    // needed to derive the proof value for
    // the object.

    // libtpms added: SEED_COMPAT_LEVEL to use for deriving child keys
    SEED_COMPAT_LEVEL   seedCompatLevel;
    // libtpms added: OBJECT lies in NVRAM; to avoid that it needs different number
    // of bytes on 32 bit and 64 bit architectures, we need to make sure it's the
    // same size; simple padding at the end works here
    UINT8               _pad[3];
} OBJECT;

//*** HASH_OBJECT Structure
// This structure holds a hash sequence object or an event sequence object.
//
// The first four components of this structure are manually set to be the same as
// the first four components of the object structure. This prevents the object
// from being inadvertently misused as sequence objects occupy the same memory as
// a regular object. A debug check is present to make sure that the offsets are
// what they are supposed to be.
// NOTE: In a future version, this will probably be renamed as SEQUENCE_OBJECT
typedef struct HASH_OBJECT
{
    OBJECT_ATTRIBUTES attributes;        // The attributes of the HASH object
    TPMI_ALG_PUBLIC   type;              // algorithm
    TPMI_ALG_HASH     nameAlg;           // name algorithm
    TPMA_OBJECT       objectAttributes;  // object attributes
    
    // The data below is unique to a sequence object
    TPM2B_AUTH auth;  // authorization for use of sequence
    union
    {
	HASH_STATE hashState[HASH_COUNT];
	HMAC_STATE hmacState;
    } state;
} HASH_OBJECT;

typedef BYTE HASH_OBJECT_BUFFER[sizeof(HASH_OBJECT)];

//*** ANY_OBJECT
// This is the union for holding either a sequence object or a regular object
// for ContextSave and ContextLoad.
typedef union ANY_OBJECT
{
    OBJECT      entity;
    HASH_OBJECT hash;
} ANY_OBJECT;

typedef BYTE ANY_OBJECT_BUFFER[sizeof(ANY_OBJECT)];

//**AUTH_DUP Types
// These values are used in the authorization processing.

typedef UINT32 AUTH_ROLE;
#  define AUTH_NONE  ((AUTH_ROLE)(0))
#  define AUTH_USER  ((AUTH_ROLE)(1))
#  define AUTH_ADMIN ((AUTH_ROLE)(2))
#  define AUTH_DUP   ((AUTH_ROLE)(3))

//** Active Session Context
//*** Description
// The structures in this section define the internal structure of a session
// context.
//
//*** SESSION_ATTRIBUTES
// The attributes in the SESSION_ATTRIBUTES structure track the various properties
// of the session. It maintains most of the tracking state information for the
// policy session. It is used within the SESSION structure.

typedef struct SESSION_ATTRIBUTES
{
#if LITTLE_ENDIAN_TPM == YES                     /* libtpms added */
    // SET if the session may only be used for policy
    unsigned isPolicy : 1;
    // SET if the session is used for audit
    unsigned isAudit : 1;
    // SET if the session is bound to an entity. This attribute will be CLEAR if
    // either isPolicy or isAudit is SET.
    unsigned isBound : 1;
    // SET if the cpHash has been defined. This attribute is not SET unless
    // 'isPolicy' is SET.
    unsigned isCpHashDefined : 1;
#if 0						// libtpms: added; see further below
    // SET if the nameHash has been defined. This attribute is not SET unless
    // 'isPolicy' is SET.
    unsigned isNameHashDefined : 1;
    // SET if the pHash has been defined. This attribute is not SET unless
    // 'isPolicy' is SET.
    unsigned isParametersHashDefined : 1;
    // SET if the templateHash needs to be checked for Create, CreatePrimary, or
    // CreateLoaded.
    unsigned isTemplateHashDefined : 1;    // SET if the authValue is required for computing the session HMAC. This
#endif						// libtpms: added
    // SET if the authValue is required for computing the session HMAC. This
    // attribute is not SET unless 'isPolicy' is SET.
    unsigned isAuthValueNeeded : 1;
    // SET if a password authValue is required for authorization This attribute
    // is not SET unless 'isPolicy' is SET.
    unsigned isPasswordNeeded : 1;
    // SET if physical presence is required to be asserted when the
    // authorization is checked. This attribute is not SET unless 'isPolicy' is
    // SET.
    unsigned isPPRequired : 1;
    // SET if the policy session is created for trial of the policy's policyHash
    // generation. This attribute is not SET unless 'isPolicy' is SET.
    unsigned isTrialPolicy : 1;
    // SET if the bind entity had noDA CLEAR. If this is SET, then an
    // authorization failure using this session will count against lockout even
    // if the object being authorized is exempt from DA.
    unsigned isDaBound : 1;
    // SET if the session is bound to lockoutAuth.
    unsigned isLockoutBound : 1;
    // This attribute is SET when the authValue of an object is to be included
    // in the computation of the HMAC key for the command and response
    // computations. (was 'requestWasBound')
    unsigned includeAuth : 1;
    // SET if the TPMA_NV_WRITTEN attribute needs to be checked when the policy
    // is used for authorization for NV access. If this is SET for any other
    // type, the policy will fail.
    unsigned checkNvWritten : 1;
    // SET if TPMA_NV_WRITTEN is required to be SET. Used when 'checkNvWritten'
    // is SET
    unsigned nvWrittenState : 1;
    // SET if the templateHash needs to be checked for Create, CreatePrimary, or
    // CreateLoaded.
    unsigned    isTemplateHashDefined : 1;	// libtpms: keep here
    // SET if the nameHash has been defined. This attribute is not SET unless
    // 'isPolicy' is SET.
    unsigned    isNameHashDefined : 1;		 /* libtpms added: for rev180; @stateFormatLevel 4 */
    // SET if the pHash has been defined. This attribute is not SET unless
    // 'isPolicy' is SET.
    unsigned    isParametersHashDefined : 1;     /* libtpms added: for rev180; @stateFormatLevel 4 */
    unsigned    _reserved : 16;         //17-32  /* libtpms added */
#endif                                           /* libtpms added */
#if BIG_ENDIAN_TPM == YES                        /* libtpms added begin */
    unsigned    _reserved : 16;         //17-32
    unsigned    isParametersHashDefined : 1; //16
    unsigned    isNameHashDefined : 1;       //15
    unsigned    isTemplateHashDefined : 1;   //14) SET if the templateHash needs to be
    unsigned    nvWrittenState : 1;     //13) SET if TPMA_NV_WRITTEN is required to
    unsigned    checkNvWritten : 1;     //12) SET if the TPMA_NV_WRITTEN attribute
    unsigned    includeAuth : 1;        //11) This attribute is SET when the
    unsigned    isLockoutBound : 1;     //10) SET if the session is bound to
    unsigned    isDaBound : 1;          //9) SET if the bind entity had noDA CLEAR.
    unsigned    isTrialPolicy : 1;      //8) SET if the policy session is created
    unsigned    isPPRequired : 1;       //7) SET if physical presence is required to
    unsigned    isPasswordNeeded : 1;   //6) SET if a password authValue is required
    unsigned    isAuthValueNeeded : 1;  //5) SET if the authValue is required for
    unsigned    isCpHashDefined : 1;    //4) SET if the cpHash has been defined
    unsigned    isBound : 1;            //3) SET if the session is bound to with an
    unsigned    isAudit : 1;            //2) SET if the session is used for audit
    unsigned    isPolicy : 1;           //1) SET if the session may only be used
#endif                                           /* libtpms added end */
} SESSION_ATTRIBUTES;

//*** IsCpHashUnionOccupied()
// This function indicates whether the session attributes indicate that one of
// the members of the union containing `cpHash` are set.
BOOL IsCpHashUnionOccupied(SESSION_ATTRIBUTES attrs);

//*** SESSION Structure
// The SESSION structure contains all the context of a session except for the
// associated contextID.
//
// Note: The contextID of a session is only relevant when the session context
// is stored off the TPM.

typedef struct SESSION
{
    SESSION_ATTRIBUTES attributes;  // session attributes
    UINT32             pcrCounter;  // PCR counter value when PCR is
    // included (policy session)
    // If no PCR is included, this
    // value is 0.
    UINT64 startTime;               // The value in g_time when the session
    // was started (policy session)
    UINT64 timeout;                 // The timeout relative to g_time
    // There is no timeout if this value
    // is 0.
    CLOCK_NONCE epoch;              // The g_clockEpoch value when the
    // session was started. If g_clockEpoch
    // does not match this value when the
    // timeout is used, then
    // then the command will fail.
    TPM_CC        commandCode;      // command code (policy session)
    TPM_ALG_ID    authHashAlg;      // session hash algorithm
    TPMA_LOCALITY commandLocality;  // command locality (policy session)
    TPMT_SYM_DEF  symmetric;        // session symmetric algorithm (if any)
    TPM2B_AUTH    sessionKey;       // session secret value used for
    // this session
    TPM2B_NONCE nonceTPM;           // last TPM-generated nonce for
    // generating HMAC and encryption keys
    union
    {
	TPM2B_NAME boundEntity;  // value used to track the entity to
	// which the session is bound
	
	TPM2B_DIGEST cpHash;        // the required cpHash value for the
	// command being authorized
	TPM2B_DIGEST nameHash;      // the required nameHash
	TPM2B_DIGEST templateHash;  // the required template for creation
	TPM2B_DIGEST pHash;         // the required parameter hash value for the
	// command being authorized
    } u1;
    
    union
    {
	TPM2B_DIGEST auditDigest;   // audit session digest
	TPM2B_DIGEST policyDigest;  // policyHash
    } u2;                           // audit log and policyHash may
    // share space to save memory
} SESSION;

#  define EXPIRES_ON_RESET   INT32_MIN
#  define TIMEOUT_ON_RESET   UINT64_MAX
#  define EXPIRES_ON_RESTART (INT32_MIN + 1)
#  define TIMEOUT_ON_RESTART (UINT64_MAX - 1)

typedef BYTE SESSION_BUF[sizeof(SESSION)];

//*********************************************************************************
//** PCR
//*********************************************************************************
//***PCR_SAVE Structure
// The PCR_SAVE structure type contains the PCR data that are saved across power
// cycles. Only the static PCR are required to be saved across power cycles. The
// DRTM and resettable PCR are not saved. The number of static and resettable PCR
// is determined by the platform-specific specification to which the TPM is built.

#  define PCR_SAVE_SPACE(HASH, Hash) BYTE Hash[NUM_STATIC_PCR][HASH##_DIGEST_SIZE];

typedef struct PCR_SAVE
{
    FOR_EACH_HASH(PCR_SAVE_SPACE)
    
    // This counter increments whenever the PCR are updated.
    // NOTE: A platform-specific specification may designate
    //       certain PCR changes as not causing this counter
    //       to increment.
    UINT32 pcrCounter;
} PCR_SAVE;

//***PCR_POLICY
#  if defined NUM_POLICY_PCR_GROUP && NUM_POLICY_PCR_GROUP > 0
// This structure holds the PCR policies, one for each group of PCR controlled
// by policy.
typedef struct PCR_POLICY
{
    TPMI_ALG_HASH hashAlg[NUM_POLICY_PCR_GROUP];
    TPM2B_DIGEST  a_unused; /* libtpms: renamed field since not used and not initialized */
    TPM2B_DIGEST  policy[NUM_POLICY_PCR_GROUP];
} PCR_POLICY;
#  endif

//***PCR_AUTHVALUE
// This structure holds the PCR policies, one for each group of PCR controlled
// by policy.
typedef struct PCR_AUTH_VALUE
{
    TPM2B_DIGEST auth[NUM_AUTHVALUE_PCR_GROUP];
} PCR_AUTHVALUE;

//**STARTUP_TYPE
// This enumeration is the possible startup types. The type is determined
// by the combination of TPM2_ShutDown and TPM2_Startup.
typedef enum
    {
	SU_RESET,
	SU_RESTART,
	SU_RESUME
    } STARTUP_TYPE;

//**NV

//***NV_INDEX
// The NV_INDEX structure defines the internal format for an NV index.
// The 'indexData' size varies according to the type of the index.
// In this implementation, all of the index is manipulated as a unit.
// NOTE: In this implementation of the TPM, the extended bits are always 0.
// Therefore, they are stored in the NV subsystem as legacy structures,
// even when the handle type indicates that the index can have extended
// attributes.
typedef struct NV_INDEX
{
    TPMS_NV_PUBLIC publicArea;
    TPM2B_AUTH     authValue;
} NV_INDEX;

//*** NV_REF
// An NV_REF is an opaque value returned by the NV subsystem. It is used to
// reference and NV Index in a relatively efficient way. Rather than having to
// continually search for an Index, its reference value may be used. In this
// implementation, an NV_REF is a byte pointer that points to the copy of the
// NV memory that is kept in RAM.
typedef UINT32 NV_REF;

typedef BYTE*  NV_RAM_REF;
//***NV_PIN
// This structure deals with the possible endianess differences between the
// canonical form of the TPMS_NV_PIN_COUNTER_PARAMETERS structure and the internal
// value. The structures allow the data in a PIN index to be read as an 8-octet
// value using NvReadUINT64Data(). That function will byte swap all the values on a
// little endian system. This will put the bytes with the 4-octet values in the
// correct order but will swap the pinLimit and pinCount values. When written, the
// PIN index is simply handled as a normal index with the octets in canonical order.
#  if BIG_ENDIAN_TPM
typedef struct
{
    UINT32 pinCount;
    UINT32 pinLimit;
} PIN_DATA;
#  else
typedef struct
{
    UINT32 pinLimit;
    UINT32 pinCount;
} PIN_DATA;
#  endif

typedef union
{
    UINT64   intVal;
    PIN_DATA pin;
} NV_PIN;

//**COMMIT_INDEX_MASK
// This is the define for the mask value that is used when manipulating
// the bits in the commit bit array. The commit counter is a 64-bit
// value and the low order bits are used to index the commitArray.
// This mask value is applied to the commit counter to extract the
// bit number in the array.
#  if ALG_ECC

#    define COMMIT_INDEX_MASK ((UINT16)((sizeof(gr.commitArray) * 8) - 1))

#  endif

//*****************************************************************************
//*****************************************************************************
//** RAM Global Values
//*****************************************************************************
//*****************************************************************************
//*** Description
// The values in this section are only extant in RAM or ROM as constant values.

//*** Crypto Self-Test Values
EXTERN ALGORITHM_VECTOR g_implementedAlgorithms;
EXTERN ALGORITHM_VECTOR g_toTest;

//*** g_rcIndex[]
// This array is used to contain the array of values that are added to a return
// code when it is a parameter-, handle-, or session-related error.
// This is an implementation choice and the same result can be achieved by using
// a macro.
extern const UINT16 g_rcIndex[15];

//*** g_exclusiveAuditSession
// This location holds the session handle for the current exclusive audit
// session. If there is no exclusive audit session, the location is set to
// TPM_RH_UNASSIGNED.
EXTERN TPM_HANDLE g_exclusiveAuditSession;

//*** g_time
// This is the value in which we keep the current command time. This is initialized
// at the start of each command. The time is the accumulated time since the last
// time that the TPM's timer was last powered up. Clock is the accumulated time
// since the last time that the TPM was cleared. g_time is in mS.
EXTERN UINT64 g_time;

//*** g_timeEpoch
// This value contains the current clock Epoch. It changes when there is a clock
// discontinuity. It may be necessary to place this in NV should the timer be able
// to run across a power down of the TPM but not in all cases (e.g. dead battery).
// If the nonce is placed in NV, it should go in gp because it should be changing
// slowly.
#  if CLOCK_STOPS
EXTERN CLOCK_NONCE g_timeEpoch;
#  else
#    define g_timeEpoch gp.timeEpoch
#  endif

//*** g_phEnable
// This is the platform hierarchy control and determines if the platform hierarchy
// is available. This value is SET on each TPM2_Startup(). The default value is
// SET.
EXTERN BOOL g_phEnable;

//*** g_pcrReConfig
// This value is SET if a TPM2_PCR_Allocate command successfully executed since
// the last TPM2_Startup(). If so, then the next shutdown is required to be
// Shutdown(CLEAR).
EXTERN BOOL g_pcrReConfig;

//*** g_DRTMHandle
// This location indicates the sequence object handle that holds the DRTM
// sequence data. When not used, it is set to TPM_RH_UNASSIGNED. A sequence
// DRTM sequence is started on either _TPM_Init or _TPM_Hash_Start.
EXTERN TPMI_DH_OBJECT g_DRTMHandle;

//*** g_DrtmPreStartup
// This value indicates that an H-CRTM occurred after _TPM_Init but before
// TPM2_Startup(). The define for PRE_STARTUP_FLAG is used to add the
// g_DrtmPreStartup value to gp_orderlyState at shutdown. This hack is to avoid
// adding another NV variable.
EXTERN BOOL g_DrtmPreStartup;

//*** g_StartupLocality3
// This value indicates that a TPM2_Startup() occurred at locality 3. Otherwise, it
// at locality 0. The define for STARTUP_LOCALITY_3 is to
// indicate that the startup was not at locality 0. This hack is to avoid
// adding another NV variable.
EXTERN BOOL g_StartupLocality3;

//***TPM_SU_NONE
// Part 2 defines the two shutdown/startup types that may be used in
// TPM2_Shutdown() and TPM2_Starup(). This additional define is
// used by the TPM to indicate that no shutdown was received.
// NOTE: This is a reserved value.
#  define SU_NONE_VALUE (0xFFFF)
#  define TPM_SU_NONE   (TPM_SU)(SU_NONE_VALUE)

//*** TPM_SU_DA_USED
// As with TPM_SU_NONE, this value is added to allow indication that the shutdown
// was not orderly and that a DA=protected object was reference during the previous
// cycle.
#  define SU_DA_USED_VALUE (SU_NONE_VALUE - 1)
#  define TPM_SU_DA_USED   (TPM_SU)(SU_DA_USED_VALUE)

//*** Startup Flags
// These flags are included in gp.orderlyState. These are hacks and are being
// used to avoid having to change the layout of gp. The PRE_STARTUP_FLAG indicates
// that a _TPM_Hash_Start/_Data/_End sequence was received after _TPM_Init but
// before TPM2_StartUp(). STARTUP_LOCALITY_3 indicates that the last TPM2_Startup()
// was received at locality 3. These flags are only  relevant if after a
// TPM2_Shutdown(STATE).
#  define PRE_STARTUP_FLAG   0x8000
#  define STARTUP_LOCALITY_3 0x4000
#define TPM_SU_STATE_MASK ~(PRE_STARTUP_FLAG | STARTUP_LOCALITY_3) // libtpms added

#  if USE_DA_USED
//*** g_daUsed
// This location indicates if a DA-protected value is accessed during a boot
// cycle. If none has, then there is no need to increment 'failedTries' on the
// next non-orderly startup. This bit is merged with gp.orderlyState when
// gp.orderly is set to SU_NONE_VALUE
EXTERN BOOL g_daUsed;
#  endif

//*** g_updateNV
// This flag indicates if NV should be updated at the end of a command.
// This flag is set to UT_NONE at the beginning of each command in ExecuteCommand().
// This flag is checked in ExecuteCommand() after the detailed actions of a command
// complete. If the command execution was successful and this flag is not UT_NONE,
// any pending NV writes will be committed to NV.
// UT_ORDERLY causes any RAM data to be written to the orderly space for staging
// the write to NV.
typedef BYTE UPDATE_TYPE;
#  define UT_NONE    (UPDATE_TYPE)0
#  define UT_NV      (UPDATE_TYPE)1
#  define UT_ORDERLY (UPDATE_TYPE)(UT_NV + 2)
EXTERN UPDATE_TYPE g_updateNV;

//*** g_powerWasLost
// This flag is used to indicate if the power was lost. It is SET in _TPM__Init.
// This flag is cleared by TPM2_Startup() after all power-lost activities are
// completed.
// Note: When power is applied, this value can come up as anything. However,
// _plat__WasPowerLost() will provide the proper indication in that case. So, when
// power is actually lost, we get the correct answer. When power was not lost, but
// the power-lost processing has not been completed before the next _TPM_Init(),
// then the TPM still does the correct thing.
EXTERN BOOL g_powerWasLost;

//*** g_clearOrderly
// This flag indicates if the execution of a command should cause the orderly
// state to be cleared.  This flag is set to FALSE at the beginning of each
// command in ExecuteCommand() and is checked in ExecuteCommand() after the
// detailed actions of a command complete but before the check of
// 'g_updateNV'. If this flag is TRUE, and the orderly state is not
// SU_NONE_VALUE, then the orderly state in NV memory will be changed to
// SU_NONE_VALUE or SU_DA_USED_VALUE.
EXTERN BOOL g_clearOrderly;

//*** g_prevOrderlyState
// This location indicates how the TPM was shut down before the most recent
// TPM2_Startup(). This value, along with the startup type, determines if
// the TPM should do a TPM Reset, TPM Restart, or TPM Resume.
EXTERN TPM_SU g_prevOrderlyState;

//*** g_nvOk
// This value indicates if the NV integrity check was successful or not. If not and
// the failure was severe, then the TPM would have been put into failure mode after
// it had been re-manufactured. If the NV failure was in the area where the state-save
// data is kept, then this variable will have a value of FALSE indicating that
// a TPM2_Startup(CLEAR) is required.
EXTERN BOOL g_nvOk;
// NV availability is sampled as the start of each command and stored here
// so that its value remains consistent during the command execution
EXTERN TPM_RC g_NvStatus;

//*** g_platformUnique

// This location contains unique value(s) used by the TPM Platform vendor.
// These are loaded on every _TPM2_Startup() using the _plat__GetUnique function.
// The "which" parameter to  _plat__GetUnique indicates the value to return.
// If used, the TPM vendor is expected to use these values for authentication.
#  if VENDOR_PERMANENT_AUTH_ENABLED == YES
// which = 1, the authorization value for VENDOR_PERMANENT_AUTH_HANDLE
EXTERN TPM2B_AUTH g_platformUniqueAuth;
#  endif

//*********************************************************************************
//*********************************************************************************
//** Persistent Global Values
//*********************************************************************************
//*********************************************************************************
//*** Description
// The values in this section are global values that are persistent across power
// events. The lifetime of the values determines the structure in which the value
// is placed.

//*********************************************************************************
//*** PERSISTENT_DATA
//*********************************************************************************
// This structure holds the persistent values that only change as a consequence
// of a specific Protected Capability and are not affected by TPM power events
// (TPM2_Startup() or TPM2_Shutdown().
typedef struct
{
    // data provided by the platform library during manufacturing.
    // Opaque to the TPM Core library, but may be used by the platform library.
    BYTE platformReserved[PERSISTENT_DATA_PLATFORM_SPACE];
    
    //*********************************************************************************
    //          Hierarchy
    //*********************************************************************************
    // The values in this section are related to the hierarchies.
    
    BOOL disableClear;  // TRUE if TPM2_Clear() using
    // lockoutAuth is disabled
    
    // Hierarchy authPolicies
    TPMI_ALG_HASH ownerAlg;
    TPMI_ALG_HASH endorsementAlg;
    TPMI_ALG_HASH lockoutAlg;
    TPM2B_DIGEST  ownerPolicy;
    TPM2B_DIGEST  endorsementPolicy;
    TPM2B_DIGEST  lockoutPolicy;
    
    // Hierarchy authValues
    TPM2B_AUTH ownerAuth;
    TPM2B_AUTH endorsementAuth;
    TPM2B_AUTH lockoutAuth;
    
    // Primary Seeds
    TPM2B_SEED EPSeed;
    TPM2B_SEED SPSeed;
    TPM2B_SEED PPSeed;
    // SEED_COMPAT_LEVELs related to creation time of seeds
    SEED_COMPAT_LEVEL   EPSeedCompatLevel; // libtpms added begin
    SEED_COMPAT_LEVEL   SPSeedCompatLevel;
    SEED_COMPAT_LEVEL   PPSeedCompatLevel; // libtpms added end
    // Note there is a nullSeed in the state_reset memory.
    
    // Hierarchy proofs
    TPM2B_PROOF phProof;
    TPM2B_PROOF shProof;
    TPM2B_PROOF ehProof;
    // Note there is a nullProof in the state_reset memory.
    
    //*********************************************************************************
    //          Reset Events
    //*********************************************************************************
    // A count that increments at each TPM reset and never get reset during the life
    // time of TPM.  The value of this counter is initialized to 1 during TPM
    // manufacture process. It is used to invalidate all saved contexts after a TPM
    // Reset.
    UINT64 totalResetCount;
    
    // This counter increments on each TPM Reset. The counter is reset by
    // TPM2_Clear().
    UINT32 resetCount;
    
    //*********************************************************************************
    //          PCR
    //*********************************************************************************
    // This structure hold the policies for those PCR that have an update policy.
    // This implementation only supports a single group of PCR controlled by
    // policy. If more are required, then this structure would be changed to
    // an array.
#  if defined  NUM_POLICY_PCR_GROUP && NUM_POLICY_PCR_GROUP > 0
    PCR_POLICY pcrPolicies;
#  endif
    
    // This structure indicates the allocation of PCR. The structure contains a
    // list of PCR allocations for each implemented algorithm. If no PCR are
    // allocated for an algorithm, a list entry still exists but the bit map
    // will contain no SET bits.
    TPML_PCR_SELECTION pcrAllocated;
    
    //*********************************************************************************
    //          Physical Presence
    //*********************************************************************************
    // The PP_LIST type contains a bit map of the commands that require physical
    // to be asserted when the authorization is evaluated. Physical presence will be
    // checked if the corresponding bit in the array is SET and if the authorization
    // handle is TPM_RH_PLATFORM.
    //
    // These bits may be changed with TPM2_PP_Commands().
    BYTE ppList[(COMMAND_COUNT + 7) / 8];
    
    //*********************************************************************************
    //          Dictionary attack values
    //*********************************************************************************
    // These values are used for dictionary attack tracking and control.
    UINT32 failedTries;  // the current count of unexpired
    // authorization failures
    
    UINT32 maxTries;  // number of unexpired authorization
    // failures before the TPM is in
    // lockout
    
    UINT32 recoveryTime;  // time between authorization failures
    // before failedTries is decremented
    
    UINT32 lockoutRecovery;  // time that must expire between
    // authorization failures associated
    // with lockoutAuth
    
    BOOL lockOutAuthEnabled;  // TRUE if use of lockoutAuth is
    // allowed
    
    //*****************************************************************************
    //            Orderly State
    //*****************************************************************************
    // The orderly state for current cycle
    TPM_SU orderlyState;
    
    //*****************************************************************************
    //           Command audit values.
    //*****************************************************************************
    BYTE          auditCommands[((COMMAND_COUNT + 1) + 7) / 8];
    TPMI_ALG_HASH auditHashAlg;
    UINT64        auditCounter;
    
    //*****************************************************************************
    //           Algorithm selection
    //*****************************************************************************
    //
    // The 'algorithmSet' value indicates the collection of algorithms that are
    // currently in used on the TPM.  The interpretation of value is vendor dependent.
    UINT32 algorithmSet;
    
    //*****************************************************************************
    //           Firmware version
    //*****************************************************************************
    // The firmwareV1 and firmwareV2 values are instanced in TimeStamp.c. This is
    // a scheme used in development to allow determination of the linker build time
    // of the TPM. An actual implementation would implement these values in a way that
    // is consistent with vendor needs. The values are maintained in RAM for simplified
    // access with a master version in NV.  These values are modified in a
    // vendor-specific way.
    
    // g_firmwareV1 contains the more significant 32-bits of the vendor version number.
    // In the reference implementation, if this value is printed as a hex
    // value, it will have the format of YYYYMMDD
    UINT32 firmwareV1;
    
    // g_firmwareV1 contains the less significant 32-bits of the vendor version number.
    // In the reference implementation, if this value is printed as a hex
    // value, it will have the format of 00 HH MM SS
    UINT32 firmwareV2;
    //*****************************************************************************
    //           Timer Epoch
    //*****************************************************************************
    // timeEpoch contains a nonce that has a vendor=specific size (should not be
    // less than 8 bytes. This nonce changes when the clock epoch changes. The clock
    // epoch changes when there is a discontinuity in the timing of the TPM.
#  if !CLOCK_STOPS
    CLOCK_NONCE timeEpoch;
#  endif
    
} PERSISTENT_DATA;

EXTERN PERSISTENT_DATA gp;

//*********************************************************************************
//*********************************************************************************
//*** ORDERLY_DATA
//*********************************************************************************
//*********************************************************************************
// The data in this structure is saved to NV on each TPM2_Shutdown().
typedef struct orderly_data
{
    //*****************************************************************************
    //           TIME
    //*****************************************************************************
    
    // Clock has two parts. One is the state save part and one is the NV part. The
    // state save version is updated on each command. When the clock rolls over, the
    // NV version is updated. When the TPM starts up, if the TPM was shutdown in and
    // orderly way, then the sClock value is used to initialize the clock. If the
    // TPM shutdown was not orderly, then the persistent value is used and the safe
    // attribute is clear.
    
    UINT64      clock;      // The orderly version of clock
    TPMI_YES_NO clockSafe;  // Indicates if the clock value is
    // safe.
    
    // In many implementations, the quality of the entropy available is not that
    // high. To compensate, the current value of the drbgState can be saved and
    // restored on each power cycle. This prevents the internal state from reverting
    // to the initial state on each power cycle and starting with a limited amount
    // of entropy. By keeping the old state and adding entropy, the entropy will
    // accumulate.
    DRBG_STATE drbgState;
    
    // These values allow the accumulation of self-healing time across orderly shutdown
    // of the TPM.
#  if ACCUMULATE_SELF_HEAL_TIMER
    UINT64 selfHealTimer;  // current value of s_selfHealTimer
    UINT64 lockoutTimer;   // current value of s_lockoutTimer
    UINT64 time;           // current value of g_time at shutdown
#  endif                   // ACCUMULATE_SELF_HEAL_TIMER
    
#ifndef __ACT_DISABLED	// libtpms added
#error ACT not supported in ORDERLY_DATA!
    // These are the ACT Timeout values. They are saved with the other timers
#  define DefineActData(N) ACT_STATE ACT_##N;
    FOR_EACH_ACT(DefineActData)
    
    // this is the 'signaled' attribute data for all the ACT. It is done this way so
    // that they can be manipulated by ACT number rather than having to access a
    // structure.
    UINT16 signaledACT;
    UINT16 preservedSignaled;
    
#  if ORDERLY_DATA_PADDING != 0
    BYTE reserved[ORDERLY_DATA_PADDING];
#  endif
    
#endif			// libtpms added
} ORDERLY_DATA;

#  if ACCUMULATE_SELF_HEAL_TIMER
#    define s_selfHealTimer go.selfHealTimer
#    define s_lockoutTimer  go.lockoutTimer
#  endif  // ACCUMULATE_SELF_HEAL_TIMER

#  define drbgDefault go.drbgState

EXTERN ORDERLY_DATA go;

//*********************************************************************************
//*********************************************************************************
//*** STATE_CLEAR_DATA
//*********************************************************************************
//*********************************************************************************
// This structure contains the data that is saved on Shutdown(STATE)
// and restored on Startup(STATE).  The values are set to their default
// settings on any Startup(Clear). In other words, the data is only persistent
// across TPM Resume.
//
// If the comments associated with a parameter indicate a default reset value, the
// value is applied on each Startup(CLEAR).

typedef struct state_clear_data
{
    //*****************************************************************************
    //           Hierarchy Control
    //*****************************************************************************
    BOOL          shEnable;        // default reset is SET
    BOOL          ehEnable;        // default reset is SET
    BOOL          phEnableNV;      // default reset is SET
    TPMI_ALG_HASH platformAlg;     // default reset is TPM_ALG_NULL
    TPM2B_DIGEST  platformPolicy;  // default reset is an Empty Buffer
    TPM2B_AUTH    platformAuth;    // default reset is an Empty Buffer
    
    //*****************************************************************************
    //           PCR
    //*****************************************************************************
    // The set of PCR to be saved on Shutdown(STATE)
    PCR_SAVE pcrSave;  // default reset is 0...0
    
    // This structure hold the authorization values for those PCR that have an
    // update authorization.
    // This implementation only supports a single group of PCR controlled by
    // authorization. If more are required, then this structure would be changed to
    // an array.
    PCR_AUTHVALUE pcrAuthValues;
    
#ifndef __ACT_DISABLED	// libtpms added
    //*****************************************************************************
    //           ACT
    //*****************************************************************************
#  define DefineActPolicySpace(N) TPMT_HA act_##N;
    FOR_EACH_ACT(DefineActPolicySpace)
    
#  if STATE_CLEAR_DATA_PADDING != 0
    BYTE reserved[STATE_CLEAR_DATA_PADDING];
#  endif
#endif			// libtpms added
} STATE_CLEAR_DATA;

EXTERN STATE_CLEAR_DATA gc;

//*********************************************************************************
//*********************************************************************************
//***  State Reset Data
//*********************************************************************************
//*********************************************************************************
// This structure contains data is that is saved on Shutdown(STATE) and restored on
// the subsequent Startup(ANY). That is, the data is preserved across TPM Resume
// and TPM Restart.
//
// If a default value is specified in the comments this value is applied on
// TPM Reset.

typedef struct state_reset_data
{
    //*****************************************************************************
    //          Hierarchy Control
    //*****************************************************************************
    TPM2B_PROOF nullProof;  // The proof value associated with
    // the TPM_RH_NULL hierarchy. The
    // default reset value is from the RNG.
    
    TPM2B_SEED nullSeed;  // The seed value for the TPM_RN_NULL
    SEED_COMPAT_LEVEL   nullSeedCompatLevel; // libtpms added
    // hierarchy. The default reset value
    // is from the RNG.
    
    //*****************************************************************************
    //           Context
    //*****************************************************************************
    // The 'clearCount' counter is incremented each time the TPM successfully executes
    // a TPM Resume. The counter is included in each saved context that has 'stClear'
    // SET (including descendants of keys that have 'stClear' SET). This prevents these
    // objects from being loaded after a TPM Resume.
    // If 'clearCount' is at its maximum value when the TPM receives a Shutdown(STATE),
    // the TPM will return TPM_RC_RANGE and the TPM will only accept Shutdown(CLEAR).
    UINT32 clearCount;  // The default reset value is 0.
    
    UINT64 objectContextID;  // This is the context ID for a saved
    //  object context. The default reset
    //  value is 0.
    CONTEXT_SLOT contextArray[MAX_ACTIVE_SESSIONS];  // This array contains
    // contains the values used to track
    // the version numbers of saved
    // contexts (see
    // Session.c in for details). The
    // default reset value is {0}.
    
    CONTEXT_COUNTER contextCounter;  // This is the value from which the
    // 'contextID' is derived. The
    // default reset value is {0}.
    
    //*****************************************************************************
    //           Command Audit
    //*****************************************************************************
    // When an audited command completes, ExecuteCommand() checks the return
    // value.  If it is TPM_RC_SUCCESS, and the command is an audited command, the
    // TPM will extend the cpHash and rpHash for the command to this value. If this
    // digest was the Zero Digest before the cpHash was extended, the audit counter
    // is incremented.
    
    TPM2B_DIGEST commandAuditDigest;  // This value is set to an Empty Digest
    // by TPM2_GetCommandAuditDigest() or a
    // TPM Reset.
    
    //*****************************************************************************
    //           Boot counter
    //*****************************************************************************
    
    UINT32 restartCount;  // This counter counts TPM Restarts.
    // The default reset value is 0.
    
    //*********************************************************************************
    //            PCR
    //*********************************************************************************
    // This counter increments whenever the PCR are updated. This counter is preserved
    // across TPM Resume even though the PCR are not preserved. This is because
    // sessions remain active across TPM Restart and the count value in the session
    // is compared to this counter so this counter must have values that are unique
    // as long as the sessions are active.
    // NOTE: A platform-specific specification may designate that certain PCR changes
    //       do not increment this counter to increment.
    UINT32 pcrCounter;  // The default reset value is 0.
    
#  if ALG_ECC
    
    //*****************************************************************************
    //         ECDAA
    //*****************************************************************************
    UINT64 commitCounter;  // This counter increments each time
    // TPM2_Commit() returns
    // TPM_RC_SUCCESS. The default reset
    // value is 0.
    
    TPM2B_NONCE commitNonce;  // This random value is used to compute
    // the commit values. The default reset
    // value is from the RNG.
    
    // This implementation relies on the number of bits in g_commitArray being a
    // power of 2 (8, 16, 32, 64, etc.) and no greater than 64K.
    BYTE commitArray[16];  // The default reset value is {0}.
    
#  endif  // ALG_ECC
#  if STATE_RESET_DATA_PADDING != 0
    BYTE reserved[STATE_RESET_DATA_PADDING];
#  endif
} STATE_RESET_DATA;

EXTERN STATE_RESET_DATA gr;

										// libtpms added begin
/* The s_ContextSlotMask masks CONTEXT_SLOT values; this variable can have
 * only two valid values, 0xff or 0xffff. The former is used to simulate
 * a CONTEXT_SLOT defined as UINT8, the latter is used for the CONTEXT_SLOT
 * when it is a UINT16. The original TPM 2 code uses a cast to CONTEXT_SLOT
 * to truncate larger values and has been modified to use CONTEXT_SLOT_MASKED
 * to achieve the same effect with the above two values.
 *
 * Using CONTEXT_SLOT_MASKED we make sure that when we write values into
 * gr.contextArray that these values are properly masked/truncated so that
 * when we read values from gr.contextArray that we don't have to mask
 * them again.
 *
 * s_ContextSlotMask may only be initialized to 0xff when resuming an older
 * state from the time when CONTEXT_SLOT was UINT8, otherwise it must be set
 * to 0xffff. We set it to 0xffff in SessionStartup(SU_CLEAR) and to be
 * able to save the TPM state really early (and restore it) also in
 * TPM_Manufacture().
 */
EXTERN CONTEXT_SLOT s_ContextSlotMask;
#define CONTEXT_SLOT_MASKED(val) ((CONTEXT_SLOT)(val) & s_ContextSlotMask)	// libtpms added end

//** NV Layout
// The NV data organization is
// 1) a PERSISTENT_DATA structure
// 2) a STATE_RESET_DATA structure
// 3) a STATE_CLEAR_DATA structure
// 4) an ORDERLY_DATA structure
// 5) the user defined NV index space

/* libtpms added: to put certain data structure at fixed offsets
 *                to give the ones below some room to expand
 */
#  define NV_PERSISTENT_DATA  (0)
#  define NV_STATE_RESET_DATA (NV_PERSISTENT_DATA + sizeof(PERSISTENT_DATA))
#  define NV_STATE_CLEAR_DATA (NV_STATE_RESET_DATA + sizeof(STATE_RESET_DATA))
#  define NV_ORDERLY_DATA     (NV_STATE_CLEAR_DATA + sizeof(STATE_CLEAR_DATA))
#  define NV_INDEX_RAM_DATA   TPM2_ROUNDUP(NV_ORDERLY_DATA + sizeof(ORDERLY_DATA),\
                                         1024) /* libtpms added */
#  define NV_USER_DYNAMIC     (NV_INDEX_RAM_DATA + sizeof(s_indexOrderlyRam))
#  define NV_USER_DYNAMIC_END NV_MEMORY_SIZE

//** Global Macro Definitions
// The NV_READ_PERSISTENT and NV_WRITE_PERSISTENT macros are used to access members
// of the PERSISTENT_DATA structure in NV.
#  define NV_READ_PERSISTENT(to, from)					\
    NvRead(&to, offsetof(PERSISTENT_DATA, from), sizeof(to))

#  define NV_WRITE_PERSISTENT(to, from)					\
    NvWrite(offsetof(PERSISTENT_DATA, to), sizeof(gp.to), &from)

#  define CLEAR_PERSISTENT(item)					\
    NvClearPersistent(offsetof(PERSISTENT_DATA, item), sizeof(gp.item))

#  define NV_SYNC_PERSISTENT(item) NV_WRITE_PERSISTENT(item, gp.item)

// At the start of command processing, the index of the command is determined. This
// index value is used to access the various data tables that contain per-command
// information. There are multiple options for how the per-command tables can be
// implemented. This is resolved in GetClosestCommandIndex().
typedef UINT16 COMMAND_INDEX;
#  define UNIMPLEMENTED_COMMAND_INDEX ((COMMAND_INDEX)(~0))

#if 0                                      /* libtpms added */
typedef struct _COMMAND_FLAGS_
{
#if LITTLE_ENDIAN_TPM == YES               /* libtpms added */
    unsigned trialPolicy : 1;  //1) If SET, one of the handles references a
    //   trial policy and authorization may be
    //   skipped. This is only allowed for a policy
    //   command.
    unsigned    reserved : 31;     //2-31) /* libtpms added begin */
#endif
#if BIG_ENDIAN_TPM == YES
    unsigned    reserved : 31;     //2-31)
    unsigned    trialPolicy : 1;    //1) If SET, one of the handles references a
#endif                                     /* libtpms added end */
} COMMAND_FLAGS;
#endif                                     /* libtpms added */

// This structure is used to avoid having to manage a large number of
// parameters being passed through various levels of the command input processing.
//

// The following macros are used to define the space for the CP and RP hashes. Space,
// is provided for each implemented hash algorithm because it is not known what the
// caller may use.
#  define CP_HASH(HASH, Hash) TPM2B_##HASH##_DIGEST Hash##CpHash;
#  define RP_HASH(HASH, Hash) TPM2B_##HASH##_DIGEST Hash##RpHash;

typedef struct COMMAND
{
    TPM_ST        tag;                   // the parsed command tag
    TPM_CC        code;                  // the parsed command code
    COMMAND_INDEX index;                 // the computed command index
    UINT32        handleNum;             // the number of entity handles in the
    //   handle area of the command
    TPM_HANDLE handles[MAX_HANDLE_NUM];  // the parsed handle values
    UINT32     sessionNum;               // the number of sessions found
    INT32      parameterSize;            // starts out with the parsed command size
    // and is reduced and values are
    // unmarshaled. Just before calling the
    // command actions, this should be zero.
    // After the command actions, this number
    // should grow as values are marshaled
    // in to the response buffer.
    INT32 authSize;                      // this is initialized with the parsed size
    // of authorizationSize field and should
    // be zero when the authorizations are
    // parsed.
    BYTE* parameterBuffer;               // input to ExecuteCommand
    BYTE* responseBuffer;                // input to ExecuteCommand
    FOR_EACH_HASH(CP_HASH)               // space for the CP hashes
    FOR_EACH_HASH(RP_HASH)               // space for the RP hashes
} COMMAND;

// TPM2B String constants used for KDFs.
// actual definition in global.c
extern const TPM2B* PRIMARY_OBJECT_CREATION;
extern const TPM2B* CFB_KEY;
extern const TPM2B* CONTEXT_KEY;
extern const TPM2B* INTEGRITY_KEY;
extern const TPM2B* SECRET_KEY;
extern const TPM2B* HIERARCHY_PROOF_SECRET_LABEL;
extern const TPM2B* HIERARCHY_SEED_SECRET_LABEL;
extern const TPM2B* HIERARCHY_FW_SECRET_LABEL;
extern const TPM2B* HIERARCHY_SVN_SECRET_LABEL;
extern const TPM2B* SESSION_KEY;
extern const TPM2B* STORAGE_KEY;
extern const TPM2B* XOR_KEY;
extern const TPM2B* COMMIT_STRING;
extern const TPM2B* DUPLICATE_STRING;
extern const TPM2B* IDENTITY_STRING;
extern const TPM2B* OBFUSCATE_STRING;
#  if ENABLE_SELF_TESTS
extern const TPM2B* OAEP_TEST_STRING;
#  endif  // ENABLE_SELF_TESTS

//*****************************************************************************
//** From CryptTest.c
//*****************************************************************************
// This structure contains the self-test state values for the cryptographic modules.
EXTERN CRYPTO_SELF_TEST_STATE g_cryptoSelfTestState;

//*****************************************************************************
//** From Manufacture.c
//*****************************************************************************
extern BOOL g_manufactured;

// This value indicates if a TPM2_Startup commands has been
// receive since the power on event.  This flag is maintained in power
// simulation module because this is the only place that may reliably set this
// flag to FALSE.
EXTERN BOOL g_initialized;

//** Private data

//*****************************************************************************
//*** From SessionProcess.c
//*****************************************************************************
#  if defined SESSION_PROCESS_C || defined GLOBAL_C || defined MANUFACTURE_C
// The following arrays are used to save command sessions information so that the
// command handle/session buffer does not have to be preserved for the duration of
// the command. These arrays are indexed by the session index in accordance with
// the order of sessions in the session area of the command.
//
// Array of the authorization session handles
EXTERN TPM_HANDLE s_sessionHandles[MAX_SESSION_NUM];

// Array of authorization session attributes
EXTERN TPMA_SESSION s_attributes[MAX_SESSION_NUM];

// Array of handles authorized by the corresponding authorization sessions;
// and if none, then TPM_RH_UNASSIGNED value is used
EXTERN TPM_HANDLE s_associatedHandles[MAX_SESSION_NUM];

// Array of nonces provided by the caller for the corresponding sessions
EXTERN TPM2B_NONCE s_nonceCaller[MAX_SESSION_NUM];

// Array of authorization values (HMAC's or passwords) for the corresponding
// sessions
EXTERN TPM2B_AUTH s_inputAuthValues[MAX_SESSION_NUM];

// Array of pointers to the SESSION structures for the sessions in a command
EXTERN SESSION* s_usedSessions[MAX_SESSION_NUM];

// Special value to indicate an undefined session index
#    define UNDEFINED_INDEX (0xFFFF)

// Index of the session used for encryption of a response parameter
EXTERN UINT32 s_encryptSessionIndex;

// Index of the session used for decryption of a command parameter
EXTERN UINT32 s_decryptSessionIndex;

// Index of a session used for audit
EXTERN UINT32 s_auditSessionIndex;

// The cpHash for command audit
#    if CC_GetCommandAuditDigest
EXTERN TPM2B_DIGEST s_cpHashForCommandAudit;
#    endif

// Flag indicating if NV update is pending for the lockOutAuthEnabled or
// failedTries DA parameter
EXTERN BOOL s_DAPendingOnNV;

#  endif  // SESSION_PROCESS_C

//*****************************************************************************
//*** From DA.c
//*****************************************************************************
#  if defined DA_C || defined GLOBAL_C || defined MANUFACTURE_C
// This variable holds the accumulated time since the last time
// that 'failedTries' was decremented. This value is in millisecond.
#    if !ACCUMULATE_SELF_HEAL_TIMER
EXTERN UINT64 s_selfHealTimer;

// This variable holds the accumulated time that the lockoutAuth has been
// blocked.
EXTERN UINT64 s_lockoutTimer;
#    endif  // ACCUMULATE_SELF_HEAL_TIMER

#  endif  // DA_C

//*****************************************************************************
//*** From NV.c
//*****************************************************************************
#  if defined NV_C || defined GLOBAL_C
// This marks the end of the NV area. This is a run-time variable as it might
// not be compile-time constant.
EXTERN NV_REF s_evictNvEnd;

// This space is used to hold the index data for an orderly Index. It also contains
// the attributes for the index.
EXTERN BYTE s_indexOrderlyRam[RAM_INDEX_SPACE];  // The orderly NV Index data

// This value contains the current max counter value. It is written to the end of
// allocatable NV space each time an index is deleted or added. This value is
// initialized on Startup. The indices are searched and the maximum of all the
// current counter indices and this value is the initial value for this.
EXTERN UINT64 s_maxCounter;

// This is space used for the NV Index cache. As with a persistent object, the
// contents of a referenced index are copied into the cache so that the
// NV Index memory scanning and data copying can be reduced.
// Only code that operates on NV Index data should use this cache directly. When
// that action code runs, s_lastNvIndex will contain the index header information.
// It will have been loaded when the handles were verified.
// NOTE: An NV index handle can appear in many commands that do not operate on the
// NV data (e.g. TPM2_StartAuthSession). However, only one NV Index at a time is
// ever directly referenced by any command. If that changes, then the NV Index
// caching needs to be changed to accommodate that. Currently, the code will verify
// that only one NV Index is referenced by the handles of the command.
EXTERN NV_INDEX s_cachedNvIndex;
EXTERN NV_REF   s_cachedNvRef;
EXTERN BYTE*    s_cachedNvRamRef;

// Initial NV Index/evict object iterator value
#    define NV_REF_INIT (NV_REF)0xFFFFFFFF

#  endif

//*****************************************************************************
//*** From Object.c
//*****************************************************************************
#  if defined OBJECT_C || defined GLOBAL_C
// This type is the container for an object.

EXTERN OBJECT s_objects[MAX_LOADED_OBJECTS];

#  endif  // OBJECT_C

//*****************************************************************************
//*** From PCR.c
//*****************************************************************************
#  if defined PCR_C || defined GLOBAL_C
#    include "pcrstruct.h"

EXTERN PCR s_pcrs[IMPLEMENTATION_PCR];

#  endif  // PCR_C

//*****************************************************************************
//*** From Session.c
//*****************************************************************************
#  if defined SESSION_C || defined GLOBAL_C
// Container for HMAC or policy session tracking information
typedef struct
{
    BOOL    occupied;
    SESSION session;  // session structure
} SESSION_SLOT;

EXTERN SESSION_SLOT s_sessions[MAX_LOADED_SESSIONS];

//  The index in contextArray that has the value of the oldest saved session
//  context. When no context is saved, this will have a value that is greater
//  than or equal to MAX_ACTIVE_SESSIONS.
EXTERN UINT32 s_oldestSavedSession;

// The number of available session slot openings.  When this is 1,
// a session can't be created or loaded if the GAP is maxed out.
// The exception is that the oldest saved session context can always
// be loaded (assuming that there is a space in memory to put it)
EXTERN int s_freeSessionSlots;

#  endif  // SESSION_C

//*****************************************************************************
//*** From IoBuffers.c
//*****************************************************************************
#  if defined IO_BUFFER_C || defined GLOBAL_C
// Each command function is allowed a structure for the inputs to the function and
// a structure for the outputs. The command dispatch code unmarshals the input butter
// to the command action input structure starting at the first byte of
// s_actionIoBuffer. The value of s_actionIoAllocation is the number of UINT64 values
// allocated. It is used to set the pointer for the response structure. The command
// dispatch code will marshal the response values into the final output buffer.
EXTERN UINT64 s_actionIoBuffer[768];  // action I/O buffer
EXTERN UINT32 s_actionIoAllocation;   // number of UIN64 allocated for the
// action input structure
#  endif                              // IO_BUFFER_C

//*****************************************************************************
//*** From TPMFail.c
//*****************************************************************************
// This value holds the address of the string containing the name of the function
// in which the failure occurred. This address value is not useful for anything
// other than helping the vendor to know in which file the failure  occurred.
EXTERN BOOL g_inFailureMode;  // Indicates that the TPM is in failure mode
#  if ALLOW_FORCE_FAILURE_MODE
EXTERN BOOL g_forceFailureMode;  // flag to force failure mode during test
#  endif

typedef void(FailFunction)(const char *function, int line, int code);
#if defined TPM_FAIL_C || defined GLOBAL_C || 1
EXTERN UINT32 s_failFunction;
// The line in the file at which the error was signaled.
EXTERN UINT32 s_failLine;
// the reason for the failure.
EXTERN UINT32 s_failCode;
EXTERN FailFunction    *LibFailCallback;
#endif // TPM_FAIL_C

//*****************************************************************************
//*** From ACT_spt.c
//*****************************************************************************
// This value is used to indicate if an ACT has been updated since the last
// TPM2_Startup() (one bit for each ACT). If the ACT is not updated
// (TPM2_ACT_SetTimeout()) after a startup, then on each TPM2_Shutdown() the TPM will
// save 1/2 of the current timer value. This prevents an attack on the ACT by saving
// the counter and then running for a long period of time before doing a TPM Restart.
// A quick TPM2_Shutdown() after each
EXTERN UINT16 s_ActUpdated;

//*****************************************************************************
//*** From CommandCodeAttributes.c
//*****************************************************************************
// This array is instanced in CommandCodeAttributes.c when it includes
// CommandCodeAttributes.h. Don't change the extern to EXTERN.
extern const TPMA_CC            s_ccAttr[];
extern const COMMAND_ATTRIBUTES s_commandAttributes[];

#endif  // GLOBAL_H
