/********************************************************************************/
/*										*/
/*			  CryptoInterface header file				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2017,2018.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

//** Introduction
//
// This file contains prototypes that are common to all TPM crypto interfaces.
//
#ifndef CRYPTO_INTERFACE_H
#define CRYPTO_INTERFACE_H

#include "TpmBuildSwitches.h"

#if SIMULATION && CRYPTO_LIB_REPORTING

typedef struct crypto_impl_description
{
    // The name of the crypto library, ASCII encoded.
    char name[32];
    // The version of the crypto library, ASCII encoded.
    char version[32];
} _CRYPTO_IMPL_DESCRIPTION;

// When building the simulator, the plugged-in crypto libraries can report its
// version information by implementing these interfaces.
void _crypto_GetSymImpl(_CRYPTO_IMPL_DESCRIPTION* result);
void _crypto_GetHashImpl(_CRYPTO_IMPL_DESCRIPTION* result);
void _crypto_GetMathImpl(_CRYPTO_IMPL_DESCRIPTION* result);

#endif  // SIMULATION && CRYPTO_LIB_REPORTING

#endif  // CRYPTO_INTERFACE_H
