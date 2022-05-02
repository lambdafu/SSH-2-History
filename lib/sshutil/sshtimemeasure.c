/*

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (C) 1998 SSH Communications Security Oy, Espoo, Finland
All rights reserved.

Real time measuring.

*/

/*
 * $Id: sshtimemeasure.c,v 1.5 1998/10/20 17:39:15 tri Exp $
 * $Log: sshtimemeasure.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#ifdef WINDOWS
#include <winbase.h>
#include <sys/timeb.h>
#endif /* WINDOWS */

#ifdef CHORUS
#include <exec/chTime.h>
#endif

/*
 * FOLLOWING SECTION HAS CODE TO EMULATE DIFFERENT TIME MEASUREMENT
 * FUNCTIONS WITH UNIX GETTIMEOFDAY.  THIS IS FOR TESTING ONLY.
 */
/* Define this to test Windows specific code in Unix. */
#undef TEST_WINDOWS
/*#define TEST_WINDOWS 1*/

/* Define this to test Chorus specific code in Unix. */
#undef TEST_CHORUS 
/*#define TEST_CHORUS 1*/

/* Emulate Windows time measurement in Unix (for testing only!) */
#if TEST_WINDOWS
#if defined (WINDOWS)
/* No need to emulate Windows in Windows. */
#elif defined (HAVE_GETTIMEOFDAY)
struct _timeb {
  long time;
  long millitm;
};
void _ftime(struct _timeb *tb)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  tb->time = tv.tv_sec;
  tb->millitm = tv.tv_usec / 1000;
  return;
}
#define WINDOWS 1
#else /* !WINDOWS && !HAVE_GETTIMEOFDAY */
#error "Cannot emulate Windows time measurement in this system."
#endif /* !WINDOWS && !HAVE_GETTIMEOFDAY */
#endif /* TEST_WINDOWS */

/* Emulate Chorus time measurement in Unix (for testing only!) */
#ifdef TEST_CHORUS
#if defined (CHORUS)
/* No need to emulate Chorus in Chorus. */
#elif defined (HAVE_GETTIMEOFDAY)
typedef struct {
  long tmSec;
  long tmNSec;
} KnTimeVal;
#define K_OK 0
int sysTime (KnTimeVal *time)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  time->tmSec = tv.tv_sec;
  time->tmNSec = tv.tv_usec * 1000;
  return K_OK;
}
int sysTimeGetRes(KnTimeVal *time)
{
  time->tmSec = 0;
  time->tmNSec = 1000;
  return K_OK;
}
#define CHORUS 1
#else /* !CHORUS && !HAVE_GETTIMEOFDAY */
#error "Cannot emulate Chorus time measurement in this system."
#endif /* !CHORUS && !HAVE_GETTIMEOFDAY */
#endif /* TEST_CHORUS */
/*
 * THE TEST SECTION ENDS HERE.
 */

struct SshTimeMeasureRec {

#if defined(WINDOWS)
  struct _timeb start;
  struct _timeb cumulated;
#elif defined(CHORUS)
  KnTimeVal start;
  KnTimeVal cumulated;
#elif defined(HAVE_GETTIMEOFDAY)
  struct timeval start;
  struct timeval cumulated;
#else /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */
  time_t start;
  time_t cumulated;
#endif /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */

  Boolean running;
};

#include "sshtimemeasure.h"

#define RETURN_WITH_SANITY(r, f)                                              \
 {                                                                            \
   if ((r) < 0.0)                                                             \
     {                                                                        \
       ssh_warning("%s: Weird return value %.6f converted to 0.0", (f), (r)); \
       return 0.0;                                                            \
     }                                                                        \
   else                                                                       \
     {                                                                        \
       return (r);                                                            \
     }                                                                        \
 }                                                                            \
 ((void)1) /* To make things go smoothly with ; at the end. */

/*
 * Init time measure structure to initial 
 * nonrunning zero state.
 */
static void ssh_time_measure_init(SshTimeMeasure timer);

/*
 * Convert the system dependent cumulated time of the
 * timer to double presenting the time in seconds.
 */
static double cumulated_time_to_double(SshTimeMeasure timer);

/* 
 * Allocates and returns a new nonrunning timer object.
 */
SshTimeMeasure ssh_time_measure_allocate(void)
{
  SshTimeMeasure timer = ssh_xcalloc(1, sizeof (struct SshTimeMeasureRec));
  ssh_time_measure_init(timer);
  return timer;
}

/*
 * Frees an allocated timer object.  
 * Returns the time (in seconds), that timer
 * has been running.
 */
void ssh_time_measure_free(SshTimeMeasure timer)
{
  ssh_xfree(timer);
  return;
}

/*
 * Start (or restart) the timer.
 * Returns the time (in seconds), that timer
 * has been running before this.
 */
double ssh_time_measure_start(SshTimeMeasure timer)
{
  if (ssh_time_measure_running(timer))
    return ssh_time_measure_intermediate(timer);

#if defined(WINDOWS)
  _ftime(&(timer->start));
  timer->running = TRUE;
#elif defined(CHORUS)
  if (sysTime(&(timer->start)) == K_OK)
    {
      timer->running = TRUE;
    }
  else
    {
      ssh_warning("ssh_time_measure_start: sysTime unexpectedly failed.");
    }
#elif defined(HAVE_GETTIMEOFDAY)
  if (gettimeofday(&(timer->start), NULL) == 0)
    {
      timer->running = TRUE;
    }
  else
    {
      ssh_warning("ssh_time_measure_start: gettimeofday unexpectedly failed.");
    }
#else /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */
  timer->start = time(NULL);
  timer->running = TRUE;
#endif /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */
  RETURN_WITH_SANITY(cumulated_time_to_double(timer),
                     "ssh_time_measure_start");
}

/*
 * Stop the timer.
 * Returns the time (in seconds), that timer
 * has been running before this.
 */
double ssh_time_measure_stop(SshTimeMeasure timer)
{
#if defined(WINDOWS)
  struct _timeb stop;
#elif defined(CHORUS)
  KnTimeVal stop;
#elif defined(HAVE_GETTIMEOFDAY)
  struct timeval stop;
#else /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */
  time_t stop;
#endif /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */

  if (! ssh_time_measure_running(timer))
    RETURN_WITH_SANITY(cumulated_time_to_double(timer),
                       "ssh_time_measure_stop");

#if defined(WINDOWS)
  _ftime(&stop);
  timer->running = FALSE;
  if (timer->start.millitm > stop.millitm)
    {
      stop.millitm += 1000;
      stop.time -= 1;
    }
  timer->cumulated.time += (stop.time - timer->start.time);
  timer->cumulated.millitm += (stop.millitm - timer->start.millitm);
  if (timer->cumulated.millitm > 999)
    {
      timer->cumulated.millitm -= 1000;
      timer->cumulated.time += 1;
    }
#elif defined(CHORUS)
  if (sysTime(&stop) == K_OK)
    {
      timer->running = FALSE;
      if (timer->start.tmNSec > stop.tmNSec)
        {
          stop.tmNSec += 1000000000;
          stop.tmSec -= 1;
        }
      timer->cumulated.tmSec += (stop.tmSec - timer->start.tmSec);
      timer->cumulated.tmNSec += (stop.tmNSec - timer->start.tmNSec);
      if (timer->cumulated.tmNSec > 999999999)
        {
          timer->cumulated.tmNSec -= 1000000000;
          timer->cumulated.tmSec += 1;
        }
    }
  else
    {
      ssh_warning("ssh_time_measure_stop: sysTime unexpectedly failed.");
      timer->running = FALSE;
    }
#elif defined(HAVE_GETTIMEOFDAY)
  if (gettimeofday(&stop, NULL) == 0)
    {
      timer->running = FALSE;
      if (timer->start.tv_usec > stop.tv_usec)
        {
          stop.tv_usec += 1000000;
          stop.tv_sec -= 1;
        }
      timer->cumulated.tv_sec += (stop.tv_sec - timer->start.tv_sec);
      timer->cumulated.tv_usec += (stop.tv_usec - timer->start.tv_usec);
      if (timer->cumulated.tv_usec > 999999)
        {
          timer->cumulated.tv_usec -= 1000000;
          timer->cumulated.tv_sec += 1;
        }
    }
  else
    {
      ssh_warning("ssh_time_measure_stop: gettimeofday unexpectedly failed.");
      timer->running = FALSE;
    }
#else /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */
  stop = time(NULL);
  timer->running = FALSE;
  timer->cumulated += (stop - timer->start);
#endif /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */
  RETURN_WITH_SANITY(cumulated_time_to_double(timer),
                     "ssh_time_measure_stop");
}

/*
 * Returns the time (in seconds), that timer
 * has been running before this.
 */
double ssh_time_measure_intermediate(SshTimeMeasure timer)
{
  struct SshTimeMeasureRec tmp_timer = *timer;
  return ssh_time_measure_stop(&tmp_timer);
}

SshUInt32 ssh_time_measure_get_integer(SshTimeMeasure timer, 
                                       SshUInt32 *seconds,
                                       SshUInt32 *nanoseconds)
{
  struct SshTimeMeasureRec tmp_timer = *timer;
  SshUInt32 r;

  ssh_time_measure_stop(&tmp_timer);
#if defined(WINDOWS)
  r = ((SshUInt32)(tmp_timer.cumulated.time));
  if (nanoseconds)
    *nanoseconds = ((SshUInt32)(tmp_timer.cumulated.millitm)) * 1000000;
#elif defined(CHORUS)
  r = ((SshUInt32)(tmp_timer.cumulated.tmSec));
  if (nanoseconds)
    *nanoseconds = ((SshUInt32)(tmp_timer.cumulated.tmNSec));
#elif defined(HAVE_GETTIMEOFDAY)
  r = ((SshUInt32)(tmp_timer.cumulated.tv_sec));
  if (nanoseconds)
    *nanoseconds = ((SshUInt32)(tmp_timer.cumulated.tv_usec)) * 1000;
#else /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */
  r = ((SshUInt32)(tmp_timer.cumulated));
  if (nanoseconds)
    *nanoseconds = 0;
#endif /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */
  if (seconds)
    *seconds = r;
  return r;
}

/*
 * Generate a timestamp value from the timer.  This is
 * very similar to ssh_time_measure_intermediate, but returns
 * only full seconds.
 */
SshUInt32 ssh_time_measure_stamp(SshTimeMeasure timer)
{
    return ssh_time_measure_get_integer(timer, NULL, NULL);
}

/*
 * Reset the timer to zero.
 * Returns the time (in seconds), that timer
 * has been running before this (after possible reset).
 * If timer is running before this call, the timer runs
 * also after reset.
 */
double ssh_time_measure_reset(SshTimeMeasure timer)
{
  double r;
  Boolean restart;

  if (ssh_time_measure_running(timer))
    {
      restart = TRUE;
      r = ssh_time_measure_stop(timer);
    }
  else
    {
      restart = FALSE;
      r = cumulated_time_to_double(timer);
    }
  ssh_time_measure_init(timer);
  if (restart)
    ssh_time_measure_start(timer);
  RETURN_WITH_SANITY(r, "ssh_time_measure_reset");
}

/*
 * Set the timer to given value in seconds and nanoseconds (10e-9s).
 * Returns the time (in seconds), that timer
 * has been running before this (after possible reset).
 * If timer is running before this call, the timer runs
 * also after reset.
 */
double ssh_time_measure_set_integer(SshTimeMeasure timer, 
                                    SshUInt32 seconds,
                                    SshUInt32 nanoseconds)
{
  double r;
  Boolean restart;

  if (nanoseconds > 1000000000)
    {
      ssh_warning("ssh_time_measure_set: Odd nanoseconds %ul converted to 0",
                  nanoseconds);
      nanoseconds = 0;
    }
  if (ssh_time_measure_running(timer))
    {
      restart = TRUE;
      r = ssh_time_measure_stop(timer);
    }
  else
    {
      restart = FALSE;
      r = cumulated_time_to_double(timer);
    }
  ssh_time_measure_init(timer);
#if defined(WINDOWS)
  timer->cumulated.time = seconds;
  timer->cumulated.millitm = nanoseconds / 1000000;
#elif defined(CHORUS)
  timer->cumulated.tmSec = secongs;
  timer->cumulated.tmNSec = nanoseconds;
#elif defined(HAVE_GETTIMEOFDAY)
  timer->cumulated.tv_sec = seconds;
  timer->cumulated.tv_usec = nanoseconds / 1000;
#else /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */
  timer->cumulated = seconds;
#endif /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */
  if (restart)
    ssh_time_measure_start(timer);
  RETURN_WITH_SANITY(r, "ssh_time_measure_set_integer");
}

/*
 * Set the timer to given value in seconds.
 * Returns the time (in seconds), that timer
 * has been running before this (after possible reset).
 * If timer is running before this call, the timer runs
 * also after reset.
 */
double ssh_time_measure_set(SshTimeMeasure timer, double value)
{
  SshUInt32 seconds, nanoseconds;
  
  seconds = (SshUInt32)value;
  nanoseconds = (SshUInt32)((value - ((double)seconds)) * 1000000000.0);

  return ssh_time_measure_set_integer(timer, 
                                      (SshUInt32)seconds,
                                      (SshUInt32)nanoseconds);
}

/*
 * Return TRUE if timer is running.
 */
Boolean ssh_time_measure_running(SshTimeMeasure timer)
{
  return timer->running;
}

/*
 * Return the granularity of the time measurement (in seconds).
 * In some systems this value may be more like guess based
 * on the structure carrying the time information.
 * In any case, significant granularity is not less than
 * the value returned by this function.
 */
double ssh_time_measure_granularity()
{
  double r;
#ifdef CHORUS
  KnTimeVal diff;
#endif

#if defined(WINDOWS)
  r = (1.0 / 1000.0);
#elif defined(CHORUS)
  if (sysTimeGetRes(&diff) == K_OK)
    {
      r = ((double)(diff.tmSec)) + (((double)(diff.tmNSec)) / 1000000000.0);
    }
  else
    {
      ssh_warning("ssh_time_measure_granularity: "
                  "sysTimeGetRes unexpectedly failed.");
      r = (1.0 / 1000000000.0);
    }
#elif defined(HAVE_GETTIMEOFDAY)
  r = (1.0 / 1000000.0);
#else /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */
  r = 1.0;
#endif /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */
  return r;
}

/*
 * Init time measure structure to initial 
 * nonrunning zero state.
 */
static void ssh_time_measure_init(SshTimeMeasure timer)
{
  timer->running = FALSE;
#if defined(WINDOWS)
  timer->start.time = 0;
  timer->start.millitm = 0;
  timer->cumulated.time = 0;
  timer->cumulated.millitm = 0;
#elif defined(CHORUS)
  timer->start.tmSec = 0;
  timer->start.tmNSec = 0;
  timer->cumulated.tmSec = 0;
  timer->cumulated.tmNSec = 0;
#elif defined(HAVE_GETTIMEOFDAY)
  timer->start.tv_sec = 0;
  timer->start.tv_usec = 0;
  timer->cumulated.tv_sec = 0;
  timer->cumulated.tv_usec = 0;
#else /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */
  timer->start = (time_t)0;
  timer->cumulated= (time_t)0;
#endif /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */
}

/*
 * Convert the system dependent cumulated time of the
 * timer to double presenting the time in seconds.
 */
static double cumulated_time_to_double(SshTimeMeasure timer)
{
  double r;
#if defined(WINDOWS)
  r = (((double)(timer->cumulated.time)) +
       (((double)(timer->cumulated.millitm)) / 1000.0));
#elif defined(CHORUS)
  r = (((double)(timer->cumulated.tmSec)) +
       (((double)(timer->cumulated.tmNSec)) / 1000000000.0));
#elif defined(HAVE_GETTIMEOFDAY)
  r = (((double)(timer->cumulated.tv_sec)) +
       (((double)(timer->cumulated.tv_usec)) / 1000000.0));
#else /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */
  r = ((double)(timer->cumulated));
#endif /* !WINDOWS && !CHORUS && !HAVE_GETTIMEOFDAY */
  return r;
}

/* eof (sshtimemeasure.c) */
