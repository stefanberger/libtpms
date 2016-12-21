/********************************************************************************/
/*										*/
/*		 Used by the simulator to mimic a hardware clock  		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: Clock.c 953 2017-03-06 20:31:40Z kgoldman $			*/
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
/*  (c) Copyright IBM Corp. and others, 2016, 2017				*/
/*										*/
/********************************************************************************/

/* added for portability because Linux clock is 32 bits */

#include <stdint.h>
#include <stdio.h>
#include <time.h>

static uint64_t tpmclock(void);

#ifdef TPM_WINDOWS

/* Windows returns result in units of CLOCKS_PER_SEC.  seconds = clock() / CLOCKS_PER_SEC */

static uint64_t tpmclock(void)
{
    clock_t clocktime = clock();
    uint64_t tpmtime = ((uint64_t)clocktime * 1000) / (uint64_t)CLOCKS_PER_SEC;
    return tpmtime;
}

#endif

#ifdef TPM_POSIX


#include <sys/time.h>

/* return time in milliseconds */

static uint64_t tpmclock(void)
{
    struct timeval      tval;
    uint64_t		tpmtime;

    gettimeofday(&tval, NULL);   /* get the time */
    tpmtime = ((uint64_t)tval.tv_sec * 1000) + ((uint64_t)tval.tv_usec / 1000);
    return tpmtime;
}

#endif

/* C.3 Clock.c */
/* C.3.1. Introduction */
/* This file contains the routines that are used by the simulator to mimic a hardware clock on a
   TPM. In this implementation, all the time values are measured in millisecond. However, the
   precision of the clock functions may be implementation dependent. */
/* C.3.2. Includes and Data Definitions */
#include "PlatformData.h"
#include "Platform_fp.h"
#include "TpmFail_fp.h"
#include <assert.h>
/* C.3.3. Simulator Functions */
/* C.3.3.1. Introduction */
/* This set of functions is intended to be called by the simulator environment in order to simulate
   hardware events. */
/* C.3.3.2. _plat__TimerReset() */
/* This function sets current system clock time as t0 for counting TPM time. This function is called
   at a power on event to reset the clock. */
LIB_EXPORT void
_plat__TimerReset(
		  void
		  )
{
    s_realTimePrevious = (clock_t) tpmclock();	/* kgold, FIXME, something wrong here */
    s_tpmTime = 0;
    s_adjustRate = CLOCK_NOMINAL;
    s_timerReset = TRUE;
    s_timerStopped = TRUE;
    return;
}
/* C.3.3.3. _plat__TimerRestart() */
/* This function should be called in order to simulate the restart of the timer should it be stopped
   while power is still applied. */
LIB_EXPORT void
_plat__TimerRestart(
		    void
		    )
{
    s_timerStopped = TRUE;
    return;
}
/* C.3.4. Functions Used by TPM */
/* C.3.4.1. Introduction */
/* These functions are called by the TPM code. They should be replaced by appropriated hardware
   functions. */
/* C.3.4.2. _plat__TimerRead() */
/* This function provides access to the tick timer of the platform. The TPM code uses this value to
   drive the TPM Clock. */
/* The tick timer is supposed to run when power is applied to the device. This timer should not be
   reset by time events including _TPM_Init(). It should only be reset when TPM power is
   re-applied. */
/* If the TPM is run in a protected environment, that environment may provide the tick time to the
   TPM as long as the time provided by the environment is not allowed to go backwards. If the time
   provided by the system can go backwards during a power discontinuity, then the
   _plat__Signal_PowerOn() should call _plat__TimerReset(). */
/* The code in this function should be replaced by a read of a hardware tick timer. */
LIB_EXPORT uint64_t
_plat__TimerRead(
		 void
		 )
{
#ifdef HARDWARE_CLOCK
#error      "need a defintion for reading the hardware clock"
    return HARDWARE_CLOCK
#else
#define BILLION     1000000000
#define MILLION     1000000
#define THOUSAND    1000
	clock_t         timeDiff;
    uint64_t        adjusted;
    // Save the value previously read from the system clock
    timeDiff = s_realTimePrevious;
    // update with the current value of the system clock
    s_realTimePrevious = tpmclock();
    // In the place below when we "put back" the unused part of the timeDiff
    // it is possible that we can put back more than we take out. That is, we could
    // take out 1000 mSec, rate adjust it and put back 1001 mS. This means that
    // on a subsequent call, time may not have caught up. Rather than trying
    // to rate adjust this, just stop time. This only occurs in a simulation so
    // time for more than one command being the same should not be an issue.
    if(timeDiff >= s_realTimePrevious)
	{
	    s_realTimePrevious = timeDiff;
	    return s_tpmTime;
	}
    // Compute the amount of time since the last call to the system clock
    timeDiff = s_realTimePrevious - timeDiff;
    // Do the time rate adjustment and conversion from CLOCKS_PER_SEC to mSec
#if 0
    adjusted = (((uint64_t)timeDiff * (THOUSAND * CLOCK_NOMINAL))
		/ ((uint64_t)s_adjustRate * CLOCKS_PER_SEC));
#endif
    /* kgold */
    adjusted = (timeDiff * (uint64_t)(s_adjustRate)) / (uint64_t)CLOCK_NOMINAL;
    s_tpmTime += (clock_t)adjusted;
    // Might have some rounding error that would loose CLOCKS. See what is not
    // being used. As mentioned above, this could result in putting back more than
    // is taken out
#if 0
    adjusted = (adjusted * ((uint64_t)s_adjustRate * CLOCKS_PER_SEC))
	       / (THOUSAND * CLOCK_NOMINAL);
#endif
    // If adjusted is not the same as timeDiff, then there is some rounding
    // error that needs to be pushed back into the previous sample.
    // NOTE: the following is so that the fact that everything is signed will not
    // matter.
    s_realTimePrevious = (clock_t)((int64_t)s_realTimePrevious - adjusted);
    s_realTimePrevious += timeDiff;
#ifdef  DEBUGGING_TIME
    // Put this in so that TPM time will pass much faster than real time when
    // doing debug.
    // A value of 1000 for DEBUG_TIME_MULTIPLER will make each ms into a second
    // A good value might be 100
    return (s_tpmTime * DEBUG_TIME_MULTIPLIER);
#endif
    return s_tpmTime;
#endif
}
/* C.3.4.3. _plat__TimerWasReset() */
/* This function is used to interrogate the flag indicating if the tick timer has been reset. */
/* If the resetFlag parameter is SET, then the flag will be CLEAR before the function returns. */
LIB_EXPORT BOOL
_plat__TimerWasReset(
		     void
		     )
{
    BOOL         retVal = s_timerReset;
    s_timerReset = FALSE;
    return retVal;
}
/* C.3.4.4. _plat__TimerWasStopped() */
/* This function is used to interrogate the flag indicating if the tick timer has been stopped. If
   so, this is typically a reason to roll the nonce. */
/* This function will CLEAR the s_timerStopped flag before returning. This provides functionality
   that is similar to status register that is cleared when read. This is the model used here because
   it is the one that has the most impact on the TPM code as the flag can only be accessed by one
   entity in the TPM. Any other implementation of the hardware can be made to look like a read-once
   register. */
LIB_EXPORT BOOL
_plat__TimerWasStopped(
		       void
		       )
{
    BOOL         retVal = s_timerStopped;
    s_timerStopped = FALSE;
    return retVal;
}
/* C.3.4.5. _plat__ClockAdjustRate() */
/* Adjust the clock rate */
LIB_EXPORT void
_plat__ClockAdjustRate(
		       int              adjust         // IN: the adjust number.  It could be positive
		       //     or negative
		       )
{
    // We expect the caller should only use a fixed set of constant values to
    // adjust the rate
    switch(adjust)
	{
	  case CLOCK_ADJUST_COARSE:
	    s_adjustRate += CLOCK_ADJUST_COARSE;
	    break;
	  case -CLOCK_ADJUST_COARSE:
	    s_adjustRate -= CLOCK_ADJUST_COARSE;
	    break;
	  case CLOCK_ADJUST_MEDIUM:
	    s_adjustRate += CLOCK_ADJUST_MEDIUM;
	    break;
	  case -CLOCK_ADJUST_MEDIUM:
	    s_adjustRate -= CLOCK_ADJUST_MEDIUM;
	    break;
	  case CLOCK_ADJUST_FINE:
	    s_adjustRate += CLOCK_ADJUST_FINE;
	    break;
	  case -CLOCK_ADJUST_FINE:
	    s_adjustRate -= CLOCK_ADJUST_FINE;
	    break;
	  default:
	    // ignore any other values;
	    break;
	}
    if(s_adjustRate > (CLOCK_NOMINAL + CLOCK_ADJUST_LIMIT))
	s_adjustRate = CLOCK_NOMINAL + CLOCK_ADJUST_LIMIT;
    if(s_adjustRate < (CLOCK_NOMINAL - CLOCK_ADJUST_LIMIT))
	s_adjustRate = CLOCK_NOMINAL - CLOCK_ADJUST_LIMIT;
    return;
}
