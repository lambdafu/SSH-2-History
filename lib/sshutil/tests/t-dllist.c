/*
  File: t-dllist.h

  Authors:
	Juha P‰‰j‰rvi <jpp@ssh.fi>

  Description:
	Test driver for doubly linked list implemented in sshdllist.[hc].

  Copyright:
  	Copyright (c) 1998 SSH Communications Security, Finland
	All rights reserved
*/

#include "sshincludes.h"
#include "sshdllist.h"
#include "sshtimemeasure.h"

#define TEST_NUMBERS_MIN 0
#define TEST_NUMBERS_MAX 20
#define ITEMS_TO_ADD_TO_THE_LIST 50000

/* Test data object */
typedef struct TestDataRec
{
  int number;
} TestData;

TestData *test_data;

/* Initializes the test data structures. */
void init_test_data(int min, int max)
{
  int i, j;

  for (i=0, j=min; j <= max; i++, j++)
    test_data[i].number = j;
}

/* Mapper to print out the contents of single list element. Used by
   print_list. */
void *print_list_mapper(void *item, void *ctx)
{
  printf("%d, ", ((TestData *)item)->number);
  return item;
}

/* Prints out the list contents. */
void print_list(SshDlList list)
{
  printf("List contents:\n");
  ssh_dllist_mapcar(list, print_list_mapper, NULL);
  printf("\n\n");
}

/* Reverses the list. */
void reverse_list(SshDlList list)
{
  SshDlListNode node;

  ssh_dllist_rewind(list);
  while (ssh_dllist_is_current_valid(list))
    {
      node = ssh_dllist_remove_current_node(list);
      ssh_dllist_add_node(list, node, SSH_DLLIST_BEGIN);
    }
}

/* Mapper for removing even items from a list. */
void *remove_evens(void *item, void *ctx)
{
  if (((TestData *)item)->number % 2 == 0)
    return NULL;
  else
    return item;
}

/* The main test program. */
int main(int argc, char *argv[])
{
  Boolean verbose = FALSE;
  SshDlList t_list;
  SshTimeMeasure ssh_timer;
  double timer_value;
  int i, k, evens, odds;

  /* Initialize the random number generator and timer */
  srand((unsigned int)time(NULL));
  ssh_timer = ssh_time_measure_allocate();

  /* Check for verbose output option */
  if (argc == 2 && !strcmp("-v", argv[1]))
    verbose = TRUE;

  /* Really necessary consistency check :) */
  if (TEST_NUMBERS_MAX < TEST_NUMBERS_MIN)
    ssh_fatal("Error in source code: TEST_NUMBERS_MAX < TEST_NUMBERS_MIN. Test failed.");

  /* Initialize the test data */
  test_data = ssh_xmalloc((TEST_NUMBERS_MAX - TEST_NUMBERS_MIN + 1) * sizeof(TestData));
  init_test_data(TEST_NUMBERS_MIN, TEST_NUMBERS_MAX);

  t_list = ssh_dllist_allocate();

  /* List addition tests */
  k = (TEST_NUMBERS_MAX + TEST_NUMBERS_MIN) / 2;
  for (i=k; i <= TEST_NUMBERS_MAX; i++)
    if (ssh_dllist_add_item(t_list, (void *)&test_data[i], SSH_DLLIST_END)
	!= SSH_DLLIST_OK)
      ssh_fatal("t-dllist: list addition failed. Test failed.");

  if (verbose)
    print_list(t_list);

  for (i=k-1; i >= TEST_NUMBERS_MIN; i--)
    if (ssh_dllist_add_item(t_list, (void *)&test_data[i], SSH_DLLIST_BEGIN)
	!= SSH_DLLIST_OK)
      ssh_fatal("t-dllist: list addition failed. Test failed.");

  if (verbose)
    print_list(t_list);

  /* List searching tests */
  if (verbose)
    printf("Testing list searching... ");
  ssh_dllist_rewind(t_list);

  i = 5;
  ssh_dllist_fw(t_list, i);
  if (ssh_dllist_current(t_list) != &test_data[i])
    ssh_fatal("t-dllist: problems with ssh_dllist_fw. Test failed.");

  i = 11;
  ssh_dllist_find(t_list, &test_data[i]);
  if (ssh_dllist_current(t_list) != &test_data[i])
    ssh_fatal("t-dllist: problems with ssh_dllist_find. Test failed.");

  if (verbose)
    printf("OK\n");

  /* List clear test */
  if (verbose)
    printf("Clearing the list... ");
  ssh_dllist_clear(t_list);
  if (verbose)
    printf("checking is the list empty... ");
  if (ssh_dllist_is_empty(t_list) != TRUE)
    ssh_fatal("t-dllist: list NOT empty! Test failed.\n");
  else if (verbose)
    printf("OK\n");

  /* ----------------------- performance testing ----------------------- */

  /* list addition */
  evens = odds = 0;
  for (k=0; k < ITEMS_TO_ADD_TO_THE_LIST; k++)
    {
      i = (int)(((long)rand() / 256) * TEST_NUMBERS_MAX / (RAND_MAX/256));
      if (i % 2 == 0)
	evens++;
      else
	odds++;

      ssh_time_measure_start(ssh_timer);
      ssh_dllist_add_item(t_list, (void *)&test_data[i], SSH_DLLIST_END);
      timer_value = ssh_time_measure_stop(ssh_timer);
    }
  if (verbose)
    printf("%d item additions took %.2f ms. Added %d evens, %d odds.\n",
	   ITEMS_TO_ADD_TO_THE_LIST, timer_value * 1000, evens, odds);
  if (evens + odds != ITEMS_TO_ADD_TO_THE_LIST)
    ssh_fatal("t-dllist: evens + odds does not match. Test failed.");
  ssh_time_measure_reset(ssh_timer);

  /* list length calculation */
  ssh_time_measure_start(ssh_timer);
  i = ssh_dllist_length(t_list);
  timer_value = ssh_time_measure_reset(ssh_timer);
  if (verbose)
    printf("Calculating list length took %.2f ms for %d elements.\n",
	   timer_value * 1000, i);
  if (i != ITEMS_TO_ADD_TO_THE_LIST)
    ssh_fatal("t-dllist: number of list elements does not match the expected. Test failed.");

  /* list reverse */
  ssh_time_measure_start(ssh_timer);
  reverse_list(t_list);
  timer_value = ssh_time_measure_reset(ssh_timer);
  if (verbose)
    printf("List reverse took %.2f ms (reverse is user implemented).\n", timer_value * 1000);

  /* mapcar test */
  ssh_time_measure_start(ssh_timer);
  ssh_dllist_mapcar(t_list, remove_evens, NULL);
  timer_value = ssh_time_measure_reset(ssh_timer);
  if (verbose)
    printf("Remove evens with mapcar call, it took %.2f ms, elements left: %d\n",
	   timer_value * 1000,
	   ssh_dllist_length(t_list));
  if (ssh_dllist_length(t_list) != odds)
    ssh_fatal("t-dllist: invalid number of list elements after mapcar. Test failed.");

  if (verbose)
    printf("Freeing everything... ");
  ssh_time_measure_start(ssh_timer);
  ssh_dllist_free(t_list);
  timer_value = ssh_time_measure_reset(ssh_timer);
  ssh_xfree(test_data);
  if (verbose)
    printf("OK, took %.2f ms (list had %d items).\n", timer_value * 1000, odds);

  return 0;
}
