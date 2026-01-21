// SPDX-License-Identifier: BSD-2-Clause

/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Oct 24, 2019  Time: 11:37:07AM
 */

#ifndef _BN_TO_OSSL_MATH_FP_H_
#define _BN_TO_OSSL_MATH_FP_H_

#ifdef MATH_LIB_OSSL

//*** OsslToTpmBn()
// This function converts an OpenSSL BIGNUM to a TPM bigNum. In this implementation
// it is assumed that OpenSSL uses a different control structure but the same data
// layout -- an array of native-endian words in little-endian order.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure because value will not fit or OpenSSL variable doesn't
//                      exist
BOOL OsslToTpmBn(bigNum bn, const BIGNUM* osslBn);		// libtpms changed

//*** BigInitialized()
// This function initializes an OSSL BIGNUM from a TPM bigConst. Do not use this for
// values that are passed to OpenSLL when they are not declared as const in the
// function prototype. Instead, use BnNewVariable().
BIGNUM* BigInitialized(BIGNUM* toInit, bigConst initializer);
#endif  // MATHLIB OSSL

// libtpms added begin
EC_POINT *EcPointInitialized(pointConst          initializer,
			     const bigCurveData* E
			     );
// libtpms added end

#endif  // _TPM_TO_OSSL_MATH_FP_H_
