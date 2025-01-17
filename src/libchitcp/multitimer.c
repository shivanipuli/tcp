/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  An API for managing multiple timers
 */

/*
 *  Copyright (c) 2013-2019, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include "chitcp/multitimer.h"
#include "chitcp/log.h"

/* Helper function for each thread of multitimer
 * Written in accordance with example given in class */
void *mt_thread_handler(void* args) {
    multi_timer_t *mt = (multi_timer_t*)args;
    pthread_mutex_lock(&mt->lock);
    while (mt->active) {
        if (mt->num_active == 0) {
            pthread_cond_wait(&mt->condvar, &mt->lock);
        } else {
            struct timespec now;
            clock_gettime(CLOCK_REALTIME, &now);
            struct timespec next_wake = *mt->active_timers->time;

            int rc = pthread_cond_timedwait(&mt->condvar, &mt->lock, &next_wake);
            if (rc == ETIMEDOUT) {
                single_timer_t *expired_timer = mt->active_timers;
                expired_timer->callback(mt, expired_timer, expired_timer->callback_params);
                expired_timer->num_timeouts++;
                expired_timer->active = false;
                mt->num_active--;
                mt->active_timers = mt->active_timers->next; 
            }
        }
    }
    pthread_mutex_unlock(&mt->lock);
    pthread_exit(0);
}

/* See multitimer.h */
int timespec_subtract(struct timespec *result, struct timespec *x, struct timespec *y)
{
    struct timespec tmp;
    tmp.tv_sec = y->tv_sec;
    tmp.tv_nsec = y->tv_nsec;

    /* Perform the carry for the later subtraction by updating tmp. */
    if (x->tv_nsec < tmp.tv_nsec) {
        uint64_t sec = (tmp.tv_nsec - x->tv_nsec) / SECOND + 1;
        tmp.tv_nsec -= SECOND * sec;
        tmp.tv_sec += sec;
    }
    if (x->tv_nsec - tmp.tv_nsec > SECOND) {
        uint64_t sec = (x->tv_nsec - tmp.tv_nsec) / SECOND;
        tmp.tv_nsec += SECOND * sec;
        tmp.tv_sec -= sec;
    }

    /* Compute the time remaining to wait.
       tv_nsec is certainly positive. */
    result->tv_sec = x->tv_sec - tmp.tv_sec;
    result->tv_nsec = x->tv_nsec - tmp.tv_nsec;

    /* Return 1 if result is negative. */
    return x->tv_sec < tmp.tv_sec;
}

int mt_init(multi_timer_t *mt, uint16_t num_timers)
{
    /* Checking first if mt is valid */
    if (mt == NULL) {
        return CHITCP_EINIT;
    }

    /* Initializing mt fields */
    mt->num_timers = num_timers;
    mt->num_active = 0;
    mt->active = true;
    mt->active_timers = NULL;

    /* Allocating memory */
    mt->timers = malloc(num_timers * sizeof(single_timer_t*));
    if (mt->timers == NULL) {
        return CHITCP_ENOMEM;
    }

    /* Initializing the mutex and cond var */
    if (pthread_mutex_init(&mt->lock, NULL) != 0 || pthread_cond_init(&mt->condvar, NULL) != 0) {
        free(mt->timers);
        return CHITCP_EINIT;
    }

    /* Creating and initializing each timer */
    for (int i = 0; i < num_timers; i++) {
        mt->timers[i] = malloc(sizeof(single_timer_t));
        if (mt->timers[i] == NULL) {
            free(mt->timers);
            return CHITCP_ENOMEM;
        }
        mt->timers[i]->id = i;
        mt->timers[i]->active = false;
        mt->timers[i]->num_timeouts = 0;
        mt->timers[i]->next = NULL;
        mt->timers[i]->callback = NULL;
        mt->timers[i]->callback_params = NULL;
        mt->timers[i]->time = malloc(sizeof(struct timespec));
        if (mt->timers[i]->time == NULL) {
            return CHITCP_ENOMEM;
        }
        memset(mt->timers[i]->name, 0, MAX_TIMER_NAME_LEN + 1); // Initialize name to all zeros
    }

    /* Creating thread */
    if (pthread_create(&mt->thread, NULL, mt_thread_handler, mt) != 0) {
        chilog(ERROR, "Could not create a worker thread");
        mt_free(mt);
        return CHITCP_ETHREAD;
    }

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_free(multi_timer_t *mt)
{
    if (mt == NULL) return CHITCP_EINVAL;
    pthread_mutex_lock(&mt->lock);
    mt->active = false;
    /* Wake up the handler for the exit */
    pthread_cond_broadcast(&mt->condvar);

    for (int i = 0; i < mt->num_timers; i++) {
        if (mt->timers[i] != NULL) {
            free(mt->timers[i]->time);
            free(mt->timers[i]);
        }
    }
    free(mt->timers);
    pthread_mutex_unlock(&mt->lock);

    pthread_join(mt->thread,NULL);
    pthread_mutex_destroy(&mt->lock);
    pthread_cond_destroy(&mt->condvar);

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_get_timer_by_id(multi_timer_t *mt, uint16_t id, single_timer_t **timer)
{
    if(id >= mt->num_timers || id < 0) {
        return CHITCP_EINVAL;
    }
    *timer = mt->timers[id];
    return CHITCP_OK;
}


/* See multitimer.h */
int mt_set_timer(multi_timer_t *mt, uint16_t id, uint64_t timeout, mt_callback_func callback, void* callback_args) {
    single_timer_t* mytimer;
    if (mt_get_timer_by_id(mt, id, &mytimer) != 0) {
        chilog(MINIMAL, "returning after mt get timer by id");
        return CHITCP_EINVAL;
    }

    pthread_mutex_lock(&mt->lock);
    if (mytimer->active) {
        chilog(MINIMAL, "timer is active");
        pthread_mutex_unlock(&mt->lock);
        return CHITCP_EINVAL;
    }

    /* Getting the current time */
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);

    /* Setting the nanoseconds and the seconds of the timer */
    mytimer->time->tv_nsec = (timeout + now.tv_nsec) % SECOND;
    mytimer->time->tv_sec = (timeout + now.tv_nsec) / SECOND + now.tv_sec;

    /* Setting the timer variables */
    mytimer->active = true;
    mytimer->callback = callback;
    mytimer->callback_params = callback_args;
    mt->num_active++;

    /* Adding to the linked list */
    single_timer_t *head = mt->active_timers;
    if (head == NULL) {
        mt->active_timers = mytimer;
    } else {
        struct timespec result;
        if (timespec_subtract(&result, mytimer->time, head->time) == 1) {
            mytimer->next = mt->active_timers;
            mt->active_timers = mytimer;
        } else {
            single_timer_t *next = mt->active_timers->next;
            while (next != NULL && timespec_subtract(&result, mytimer->time, next->time) == 0) {
                head = next;
                next = next->next;
            }
            mytimer->next = head->next;
            head->next = mytimer;
        }
    }

    /* Mutex signaling */
    pthread_cond_signal(&mt->condvar);
    pthread_mutex_unlock(&mt->lock);

    return CHITCP_OK;
}



/* See multitimer.h */
int mt_cancel_timer(multi_timer_t *mt, uint16_t id)
{
    single_timer_t* mytimer;
    
    if(mt_get_timer_by_id(mt, id, &mytimer) != 0) {
        return CHITCP_EINVAL;
    }

    if(!mytimer->active) {
        return CHITCP_EINVAL;
    }

    pthread_mutex_lock(&mt->lock);
    mytimer->active = false; // Deactivate the timer
    mt->num_active--;

    // Update linked list to remove the timer
    single_timer_t *current = mt->active_timers, *prev = NULL;
    while(current != NULL && current->id != id) {
        prev = current;
        current = current->next;
    }
    if(prev == NULL) {
        mt->active_timers = current->next; // Timer was at head
    } else {
        prev->next = current->next;
    }

    pthread_cond_signal(&mt->condvar);
    pthread_mutex_unlock(&mt->lock);

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_set_timer_name(multi_timer_t *mt, uint16_t id, const char *name)
{
    single_timer_t *mytimer;
    if(mt_get_timer_by_id(mt, id, &mytimer)!=0)
        return CHITCP_EINVAL;
    strncpy(mytimer->name,name,strlen(name));
    return CHITCP_OK;
}


/* mt_chilog_single_timer - Prints a single timer using chilog
 *
 * level: chilog log level
 *
 * timer: Timer
 *
 * Returns: Always returns CHITCP_OK
 */
int mt_chilog_single_timer(loglevel_t level, single_timer_t *timer)
{
    struct timespec now, diff;
    clock_gettime(CLOCK_REALTIME, &now);

    if(timer->active) {
        /* Compute the appropriate value for "diff" here; it should contain
         * the time remaining until the timer times out.
         * Note: The timespec_subtract function can come in handy here*/
        diff.tv_sec = 0;
        diff.tv_nsec = 0;
        // timer - now
        timespec_subtract(&diff, timer->time, &now); //not sure if this is right
        chilog(level, "%i %s %lis %lins", timer->id, timer->name, diff.tv_sec, diff.tv_nsec);
    } else
        chilog(level, "%i %s", timer->id, timer->name);

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_chilog(loglevel_t level, multi_timer_t *mt, bool active_only)
{
    for(int i=0; i<mt->num_timers; i++) {
        if(active_only) {
            if(mt->timers[i]->active)
                mt_chilog_single_timer(level, mt->timers[i]);
        } else
            mt_chilog_single_timer(level, mt->timers[i]);
    }
    return CHITCP_OK;
}