
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */

  /* This is for global unique identifier */
  nat->icmp_tcp_identifier = 1024;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void sr_nat_mapping_destroy(struct sr_nat *nat, struct sr_nat_mapping *mapping) {
  if (mapping) {
    struct sr_nat_mapping *cur, *prev = NULL, *next = NULL;
    for (cur = nat->mappings; cur != NULL; cur = cur->next) {
      if (cur == mapping) {
        if (prev) {
          next = cur->next;
          prev->next = next;
        } else {
          next = cur->next;
          nat->mappings = next;
        }

        break;
      }
      prev = cur;
    }

    struct sr_nat_connection *conn, *nxt;

    for (conn = mapping->conns; conn != NULL; conn = nxt) {
      nxt = conn->next;
      free(conn);
    }

    free(mapping);
  }
}

void sr_nat_connection_destroy(struct sr_nat_mapping *mapping, struct sr_nat_connection *conn) {
  if (mapping && conn) {
    struct sr_nat_connection *cur, *prev = NULL, *next = NULL;
    for (cur = mapping->conns; cur != NULL; cur = cur->next) {
      if (cur == conn) {
        if (prev) {
          next = cur->next;
          prev->next = next;
        } else {
          next = cur->next;
          mapping->conns = next;
        }

        break;
      }
      prev = cur;
    }
  }

  free(conn);
}

void sr_nat_check_tcp_conns(struct sr_nat *nat, struct sr_nat_mapping *mapping) {
  struct sr_nat_connection *cur, *next;

  cur = mapping->conns;

  while (cur) {
    next = cur->next;

    time_t curtime = time(NULL);

    if (cur->state == nat_tcp_conn_established) {
      if (difftime(curtime, cur->last_updated) > nat->tcp_established_timeout ||
          difftime(curtime, cur->last_updated) > nat->tcp_transitory_timeout) {
        sr_nat_connection_destroy(mapping, cur);
      }
    }

    cur = next;
  }
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    struct sr_nat_mapping *cur, *next;
    cur = nat->mappings;

    while (cur) {
      next = cur->next;

      if (cur->type == nat_mapping_icmp) {
        if (difftime(curtime, cur->last_updated) > nat->icmp_query_timeout) {
          sr_nat_mapping_destroy(nat, cur);
        }
      } else if (cur->type == nat_mapping_tcp) {
        sr_nat_check_tcp_conns(nat, cur);

        if (cur->conns == NULL && difftime(curtime, cur->last_updated) > 0.5) {
          sr_nat_mapping_destroy(nat, cur);
        }
      }

      cur = next;
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));
  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *cur = nat->mappings, *copy = NULL;

  while (cur) {
    if (cur->type == type && cur->aux_ext == aux_ext) {
      cur->last_updated = time(NULL);
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, cur, sizeof(struct sr_nat_mapping));
      break;
    }

    cur = cur->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *cur = nat->mappings, *copy = NULL;

  while (cur) {
    if (cur->type == type && cur->ip_int == ip_int && cur->aux_int == aux_int) {
      cur->last_updated = time(NULL);
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, cur, sizeof(struct sr_nat_mapping));
      break;
    }

    cur = cur->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));
  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping));

  mapping->type = type;
  mapping->last_updated = time(NULL);
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->aux_ext = nat->icmp_tcp_identifier;
  nat->icmp_tcp_identifier = nat->icmp_tcp_identifier + 1;
  mapping->conns = NULL;

  struct sr_nat_mapping *cur = nat->mappings;
  nat->mappings = mapping;
  mapping->next = cur;

  struct sr_nat_mapping *copy = malloc(sizeof(struct sr_nat_mapping));
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}
