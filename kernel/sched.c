/*
 * implementing the scheduler
 */

#include "sched.h"
#include "spike_interface/spike_utils.h"
#include "spike_interface/atomic.h"
#include "sync_utils.h"
#include "process.h"

process* ready_queue_head[NCPU] = {NULL};

//
// insert a process, proc, into the END of ready queue.
//
void insert_to_ready_queue( process* proc ) {

  uint64 tp=read_tp();

  log( "going to insert process %d to ready queue.\n", proc->pid );
  // if the queue is empty in the beginning
  if( ready_queue_head[tp] == NULL ){
    spinlock_lock(&procs_status_lock);
    proc->status = READY;
    spinlock_unlock(&procs_status_lock);
    proc->queue_next = NULL;
    ready_queue_head[tp] = proc;
    return;
  }

  // ready queue is not empty
  process *p;
  // browse the ready queue to see if proc is already in-queue
  for( p=ready_queue_head[tp]; p->queue_next!=NULL; p=p->queue_next )
    if( p == proc ) return;  //already in queue

  // p points to the last element of the ready queue
  if( p==proc ) return;
  p->queue_next = proc;
  spinlock_lock(&procs_status_lock);
  proc->status = READY;
  spinlock_unlock(&procs_status_lock);
  proc->queue_next = NULL;

  return;
}

int shutdown_barrier=0;

//
// choose a proc from the ready queue, and put it to run.
// note: schedule() does not take care of previous current process. If the current
// process is still runnable, you should place it into the ready queue (by calling
// ready_queue_insert), and then call schedule().
//
extern process procs[NPROC];
void schedule() {
  uint64 tp=read_tp();
  if ( !ready_queue_head[tp] ){
    // by default, if there are no ready process, and all processes are in the status of
    // FREE and ZOMBIE, we should shutdown the emulated RISC-V machine.
    int should_shutdown = 1;

    spinlock_lock(&procs_status_lock);
    for( int i=0; i<NPROC; i++ )
      if( (procs[i].status != FREE) && (procs[i].status != ZOMBIE) ){
        should_shutdown = 0;
        log( "ready queue empty, but process %d is not in free/zombie state:%d\n", 
          i, procs[i].status );
      }
    spinlock_unlock(&procs_status_lock);
    sync_barrier(&shutdown_barrier,NCPU);
    if( should_shutdown ){
      if(tp==0){
        log( "no more ready processes, system shutdown now.\n" );
        shutdown( 0 );
      }
      return;
    }else{
      panic( "Not handled: we should let system wait for unfinished processes.\n" );
    }
  }

  current[tp] = ready_queue_head[tp];
  spinlock_lock(&procs_status_lock);
  assert( current[tp]->status == READY );
  ready_queue_head[tp] = ready_queue_head[tp]->queue_next;

  current[tp]->status = RUNNING;
  spinlock_unlock(&procs_status_lock);
  log( "going to schedule process %d to run.\n", current[tp]->pid );
  switch_to( current[tp] );
}
