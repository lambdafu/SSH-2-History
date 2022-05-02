/*

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (C) 1998 SSH Communications Security Oy, Espoo, Finland
All rights reserved.

Real time measuring.

*/

/*
 * $Id: sshtimemeasure.h,v 1.3 1998/10/20 17:39:16 tri Exp $
 * $Log: sshtimemeasure.h,v $
 * $EndLog$
 */

#ifndef SSHTIMEMEASURE_H
#define SSHTIMEMEASURE_H

typedef struct SshTimeMeasureRec *SshTimeMeasure;

/* 
 * Allocates and returns a new nonrunning timer object.
 */
SshTimeMeasure ssh_time_measure_allocate(void);

/*
 * Frees an allocated timer object.  
 */
void ssh_time_measure_free(SshTimeMeasure timer);

/*
 * Start (or restart) the timer.
 * Returns the time (in seconds), that timer
 * has been running before this.
 */
double ssh_time_measure_start(SshTimeMeasure timer);

/*
 * Stop the timer.
 * Returns the time (in seconds), that timer
 * has been running before this.
 */
double ssh_time_measure_stop(SshTimeMeasure timer);

/*
 * Returns the time (in seconds), that timer
 * has been running before this.
 * If timer is running before this call, the timer runs
 * also after the call.
 */
double ssh_time_measure_intermediate(SshTimeMeasure timer);

/*
 * Generate a timestamp value from the timer.  This is
 * very similar to ssh_time_measure_intermediate, but returns
 * only full seconds.
 */
SshUInt32 ssh_time_measure_stamp(SshTimeMeasure timer);

/*
 * Return the full seconds the timer has been running.
 * If parameter seconds and/or nanoseconds are non-NULL
 * set those integers to seconds and nanoseconds value
 * or the timer accordingly.
 */
SshUInt32 ssh_time_measure_get_integer(SshTimeMeasure timer, 
                                       SshUInt32 *seconds,
                                       SshUInt32 *nanoseconds);

/*
 * Reset the timer to zero.
 * Returns the time (in seconds), that timer
 * has been running before this (after possible reset).
 */
double ssh_time_measure_reset(SshTimeMeasure timer);

/*
 * Set the timer to given value in seconds.
 * Returns the time (in seconds), that timer
 * has been running before this (after possible reset).
 * If timer is running before this call, the timer runs
 * also after reset.
 */
double ssh_time_measure_set(SshTimeMeasure timer, double value);

/*
 * Set the timer to given value in seconds and nanoseconds (10e-9s).
 * Returns the time (in seconds), that timer
 * has been running before this (after possible reset).
 * If timer is running before this call, the timer runs
 * also after reset.
 */
double ssh_time_measure_set_integer(SshTimeMeasure timer, 
                                    SshUInt32 seconds,
                                    SshUInt32 nanoseconds);

/*
 * Return TRUE if timer is running.
 */
Boolean ssh_time_measure_running(SshTimeMeasure timer);

/*
 * Return the granularity of the time measurement (in seconds).
 * In some systems this value may be more like guess based
 * on the structure carrying the time information.
 * In any case, significant granularity is not less than
 * the value returned by this function.
 */
double ssh_time_measure_granularity(void);

#endif /* ! SSHTIMEMEASURE_H */
/* eof (sshtimemeasure.h) */
