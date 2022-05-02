/*

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (C) 1998 SSH Communications Security Oy, Espoo, Finland
All rights reserved.

Test time measurement.

*/

/*
 * $Id: t-timemeasure.c,v 1.6 1998/10/20 17:39:50 tri Exp $
 * $Log: t-timemeasure.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshtimemeasure.h"

/* 
 * START, STOP, RESET and INTERMEDIATE macros are context dependent
 * and expect that there is a double variable `rv' in which operation
 * can store the return value of the operation.
 */
#define START(x)  (printf("Starting timer %s (%.12f seconds).\n",           \
                          #x, ((rv) = ssh_time_measure_start(x))))

#define STOP(x)   (printf("Stopping timer %s (%.12f seconds).\n",           \
                          #x, ((rv) = ssh_time_measure_stop(x))))

#define RESET(x)  (printf("Resetting timer %s (%.12f seconds).\n",          \
                          #x, ((rv) = ssh_time_measure_reset(x))))

#define INTERMEDIATE(x)                                                     \
                  (printf("Intermediate timer %s (%.12f seconds).\n",       \
                          #x, ((rv) = ssh_time_measure_intermediate(x))))

#define GRANULARITY()                                                       \
                  (printf("Timer granularity is %.15f seconds.\n",          \
                          ((rv) = ssh_time_measure_granularity())))

#define STAMP(x)   (printf("Stamp timer %s (%lu seconds).\n",               \
                          #x, (unsigned long)ssh_time_measure_stamp(x)))


#define SET(x, v)  (printf("Set timer %s (%.12f seconds) -> %.12f\n",       \
                          #x, ssh_time_measure_set(x, v), v))

#define GET_INT(x) do {                                                     \
                      SshUInt32 _s, _n;                                     \
                      ssh_time_measure_get_integer((x), &_s, &_n);          \
                      printf("Timer %s value %u sec, %u nanosec.\n",        \
                             #x, _s, _n);                                   \
                   } while (0);


#ifdef HAVE_USLEEP
#define USLEEP(x)                                                           \
    ((printf("sleep for %.12f seconds.\n", ((double)(x)) / 1000000.0)),     \
     (usleep(x)))
#else /* HAVE_USLEEP */
#define USLEEP(x)                                                           \
    ((printf("sleep for %.12f seconds.\n", ((double)((x)/1000000)))),       \
     (sleep(x / 1000000)))
#endif /* HAVE_USLEEP */

int main()
{
  SshTimeMeasure total_timer;
  SshTimeMeasure timer_1;
  SshTimeMeasure timer_2;
  SshTimeMeasure timer_3;
  SshTimeMeasure timer_4;
  SshTimeMeasure timer_5;
  int i;
  double rv = 0.0;
  int ev = 0;
#ifdef HAVE_GETTIMEOFDAY      
  struct timeval tv;
#endif /* HAVE_GETTIMEOFDAY */

  total_timer = ssh_time_measure_allocate();
  timer_1 = ssh_time_measure_allocate();
  timer_2 = ssh_time_measure_allocate();
  timer_3 = ssh_time_measure_allocate();
  timer_4 = ssh_time_measure_allocate();
  timer_5 = ssh_time_measure_allocate();

  rv = ssh_time_measure_intermediate(total_timer); 
  if ((rv < 0.0) || (rv > 0.0))
    {
      ssh_warning("Weird initial value.\n");
      ev++;
    }

  GRANULARITY();
  if (rv <= 0.0)
    {
      ssh_warning("Weird granularity.\n");
      ev++;
    }

  START(total_timer);
  START(timer_1);
  START(timer_3);
  START(timer_4);
  START(timer_5);

  STAMP(total_timer);

  USLEEP(2000000);
  STAMP(total_timer);

  SET(timer_5, 12345.012345678901234567890);
  INTERMEDIATE(timer_5);
  if ((rv < 12345.0) || (rv > 12350.0))
    {
      ssh_warning("Weird intermediate after running set.\n");
      ev++;
    }

  INTERMEDIATE(timer_1);
  if (rv < 1.0)
    {
      ssh_warning("Weird intermediate.\n");
      ev++;
    }
  STOP(timer_3);
  if (rv < 1.0)
    {
      ssh_warning("Weird stop value.\n");
      ev++;
    }
  START(timer_2);
  RESET(timer_4);

  USLEEP(3000000);
  STAMP(total_timer);

  INTERMEDIATE(timer_2);
  START(timer_3);
  if (rv < 1.0)
    {
      ssh_warning("Weird restart value.\n");
      ev++;
    }
  RESET(timer_4);
  STOP(timer_1);


  USLEEP(4000000);
  STAMP(total_timer);


  STOP(timer_5);

  SET(timer_5, 12345.012345678901234567890);
  INTERMEDIATE(timer_5);
  if ((rv < 12345.0) || (rv > 12346.0))
    {
      ssh_warning("Weird intermediate after stopped set.\n");
      ev++;
    }

  STOP(timer_4);
  STOP(timer_3);
  STOP(timer_2);
  STOP(timer_1);

#define TIMESTAMPS 1000000

  ssh_time_measure_reset(timer_1);
  ssh_time_measure_reset(timer_2);
  printf("\nGenerating %d timestamps.\n", TIMESTAMPS);
  START(timer_2);
  START(timer_1);
  for (i = 1; i < TIMESTAMPS; i++)
    {
      ssh_time_measure_stamp(timer_2);
    }
  STOP(timer_1);
  STOP(timer_2);
  printf("Time elapsed %.12f seconds (%.12f seconds/timestamp", 
         ssh_time_measure_intermediate(timer_1),
         ssh_time_measure_intermediate(timer_1) / (double)TIMESTAMPS);
  if (ssh_time_measure_intermediate(timer_1) > 0.0)
    printf(", %d timestamps/second",
           (int)((double)TIMESTAMPS / ssh_time_measure_intermediate(timer_1)));
  printf(")\n");

  ssh_time_measure_reset(timer_3);
  ssh_time_measure_reset(timer_4);
  printf("\nFor reference generating %d timestamps with time(3).\n", 
         TIMESTAMPS);
  START(timer_4);
  START(timer_3);
  for (i = 1; i < TIMESTAMPS; i++)
    {
      time(NULL);
    }
  STOP(timer_3);
  STOP(timer_4);
  printf("Time elapsed %.12f seconds (%.12f seconds/timestamp", 
         ssh_time_measure_intermediate(timer_3),
         ssh_time_measure_intermediate(timer_3) / (double)TIMESTAMPS);
  if (ssh_time_measure_intermediate(timer_3) > 0.0)
    printf(", %d timestamps/second",
           (int)((double)TIMESTAMPS / ssh_time_measure_intermediate(timer_3)));
  printf(")\n");

  if ((ssh_time_measure_intermediate(timer_1) > 0.0) &&
      (ssh_time_measure_intermediate(timer_3) > 0.0))
    printf("Using time(3) is %2.1f%% faster than ssh_..._stamp.\n", 
           ((ssh_time_measure_intermediate(timer_1) - 
             ssh_time_measure_intermediate(timer_3)) /
            ssh_time_measure_intermediate(timer_1)) * 100.0);

#ifdef HAVE_GETTIMEOFDAY
  ssh_time_measure_reset(timer_3);
  ssh_time_measure_reset(timer_4);
  printf("\nFor reference generating %d timestamps with gettimeofday.\n", 
         TIMESTAMPS);
  START(timer_4);
  START(timer_3);
  for (i = 1; i < TIMESTAMPS; i++)
    {
      gettimeofday(&tv, NULL);
    }
  STOP(timer_3);
  STOP(timer_4);
  printf("Time elapsed %.12f seconds (%.12f seconds/timestamp", 
         ssh_time_measure_intermediate(timer_3),
         ssh_time_measure_intermediate(timer_3) / (double)TIMESTAMPS);
  if (ssh_time_measure_intermediate(timer_3) > 0.0)
    printf(", %d timestamps/second",
           (int)((double)TIMESTAMPS / ssh_time_measure_intermediate(timer_3)));
  printf(")\n");

  if ((ssh_time_measure_intermediate(timer_1) > 0.0) &&
      (ssh_time_measure_intermediate(timer_3) > 0.0))
    printf("Using gettimeofday(3) is %2.1f%% faster than ssh_..._stamp.\n", 
           ((ssh_time_measure_intermediate(timer_1) - 
             ssh_time_measure_intermediate(timer_3)) /
            ssh_time_measure_intermediate(timer_1)) * 100.0);
#endif /* HAVE_GETTIMEOFDAY */
  
  STOP(total_timer);
  GET_INT(timer_1);
  GET_INT(timer_2);
  GET_INT(timer_3);
  GET_INT(timer_4);
  GET_INT(timer_5);
  GET_INT(total_timer);
  ssh_time_measure_free(timer_5);
  ssh_time_measure_free(timer_4);
  ssh_time_measure_free(timer_3);
  ssh_time_measure_free(timer_2);
  ssh_time_measure_free(timer_1);
  ssh_time_measure_free(total_timer);

  exit(ev);
}

