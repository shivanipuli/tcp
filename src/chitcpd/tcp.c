/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  Implementation of the TCP protocol.
 *
 *  chiTCP follows a state machine approach to implementing TCP.
 *  This means that there is a handler function for each of
 *  the TCP states (CLOSED, LISTEN, SYN_RCVD, etc.). If an
 *  event (e.g., a packet arrives) while the connection is
 *  in a specific state (e.g., ESTABLISHED), then the handler
 *  function for that state is called, along with information
 *  about the event that just happened.
 *
 *  Each handler function has the following prototype:
 *
 *  int f(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event);
 *
 *  si is a pointer to the chiTCP server info. The functions in
 *       this file will not have to access the data in the server info,
 *       but this pointer is needed to call other functions.
 *
 *  entry is a pointer to the socket entry for the connection that
 *          is being handled. The socket entry contains the actual TCP
 *          data (variables, buffers, etc.), which can be extracted
 *          like this:
 *
 *            tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
 *
 *          Other than that, no other fields in "entry" should be read
 *          or modified.
 *
 *  event is the event that has caused the TCP thread to wake up. The
 *          list of possible events corresponds roughly to the ones
 *          specified in http://tools.ietf.org/html/rfc793#section-3.9.
 *          They are:
 *
 *            APPLICATION_CONNECT: Application has called socket_connect()
 *            and a three-way handshake must be initiated.
 *
 *            APPLICATION_SEND: Application has called socket_send() and
 *            there is unsent data in the send buffer.
 *
 *            APPLICATION_RECEIVE: Application has called socket_recv() and
 *            any received-and-acked data in the recv buffer will be
 *            collected by the application (up to the maximum specified
 *            when calling socket_recv).
 *
 *            APPLICATION_CLOSE: Application has called socket_close() and
 *            a connection tear-down should be initiated.
 *
 *            PACKET_ARRIVAL: A packet has arrived through the network and
 *            needs to be processed (RFC 793 calls this "SEGMENT ARRIVES")
 *
 *            TIMEOUT: A timeout (e.g., a retransmission timeout) has
 *            happened.
 *
 */

/*
 *  Copyright (c) 2013-2014, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or withsend
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
 *    software withsend specific prior written permission.
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
 *  ARISING IN ANY WAY send OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "chitcp/log.h"
#include "chitcp/utils.h"
#include "chitcp/buffer.h"
#include "chitcp/chitcpd.h"
#include "serverinfo.h"
#include "connection.h"
#include "tcp.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

void tcp_data_init(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    tcp_data->pending_packets = NULL;
    pthread_mutex_init(&tcp_data->lock_pending_packets, NULL);
    pthread_cond_init(&tcp_data->cv_pending_packets, NULL);

    /* Initialization of additional tcp_data_t fields,
     * and creation of retransmission thread, goes here */
         /* Initialization of additional tcp_data_t fields,
     * and creation of retransmission thread, goes here */
    tcp_data->retransmission_queue = NULL;
    tcp_data->out_of_order_packets = NULL;
    pthread_mutex_init(&tcp_data->lock_ooo_packets, NULL);
    pthread_mutex_init(&tcp_data->lock_rtx_packets, NULL);
    pthread_cond_init(&tcp_data->cv_rtx_packets, NULL);

    /* Initializing RTT */
    /* This is the first RTT measurement */
    tcp_data->RTO = 200 * MILLISECOND;
    tcp_data->SRTT = -1;
    /* Initializing timers */
    mt_init(&tcp_data->mt, 2);
    mt_set_timer_name(&tcp_data->mt, RETRANSMISSION, "Retransmission");
    mt_set_timer_name(&tcp_data->mt, PERSIST, "Persist");
}

void tcp_data_free(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    circular_buffer_free(&tcp_data->send);
    circular_buffer_free(&tcp_data->recv);
    chitcp_packet_list_destroy(&tcp_data->pending_packets);
    pthread_mutex_destroy(&tcp_data->lock_pending_packets);
    pthread_cond_destroy(&tcp_data->cv_pending_packets);
    chitcp_packet_list_destroy(&tcp_data->out_of_order_packets);
    pthread_mutex_destroy(&tcp_data->lock_rtx_packets);
    pthread_mutex_destroy(&tcp_data->lock_ooo_packets);
    pthread_cond_destroy(&tcp_data->cv_rtx_packets);
    mt_free(&tcp_data->mt);

    tcp_retransmission_packet_t *current = tcp_data->retransmission_queue, *tmp;
    while (current != NULL) {
        tmp = current;
        current = current->next;
        chitcp_tcp_packet_free(tmp->packet);
        free(tmp->packet);
        free(tmp);
    }
    /* Cleanup of additional tcp_data_t fields goes here */
}

/* Additional function declarations */
void send_syn_packet(serverinfo_t *si, chisocketentry_t *entry, tcp_data_t *tcp_data);
void send_ack_packet(serverinfo_t *si, chisocketentry_t *entry, tcp_data_t *tcp_data);
void send_syn_ack_packet(serverinfo_t *si, chisocketentry_t *entry, tcp_data_t *tcp_data);
void send_fin_packet(serverinfo_t *si, chisocketentry_t *entry, tcp_data_t *tcp_data);
void send_buffer(serverinfo_t *si, chisocketentry_t *entry, int send_amount);
void send_probe_packet(serverinfo_t *si, chisocketentry_t *entry);
int check_seg(tcp_packet_t *packet, tcp_data_t *tcp_data);
int process_out_of_order_packets(serverinfo_t *si, chisocketentry_t *entry);
int calculate_rto(tcp_data_t *tcp_data, struct timespec *send_time);
tcp_packet_t *get_recv_packet(tcp_data_t *tcp_data);
int compare_rtx_packets(tcp_retransmission_packet_t *item1, tcp_retransmission_packet_t *item2);
int chitcp_rtx_queue_add_in_order(tcp_retransmission_packet_t **pl, tcp_packet_t *packet);

typedef struct chitcpd_timer_context {
    serverinfo_t *server_info;      // Pointer to server info
    chisocketentry_t *socket_entry; // Pointer to socket entry
    int timer_id;                   // Identifier for the timer
} chitcpd_timer_context_t;

/* chitcpd_tcp_handle_callback
 * 
 * The callback function for when a rtx timer or persist timer times out
 * 
 * mi: The multitimer that times out
 * args which is casted into a chitcpd_timer_context_t type
 * 
 * Void function with no return value
*/
void chitcpd_tcp_handle_callback(multi_timer_t *mi, single_timer_t *t, void *args)
{
    chilog(ERROR, "entering chitcpd handle callback");
    chitcpd_timer_context_t *timer_context = (chitcpd_timer_context_t *) args;
    if(timer_context->timer_id == RETRANSMISSION) {
        chilog(MINIMAL, "Retransmission timer expired.");
        chitcpd_timeout(timer_context->server_info, timer_context->socket_entry, RETRANSMISSION);
    } else if(timer_context->timer_id == PERSIST) {
        chilog(MINIMAL, "Persist timer expired.");
        chitcpd_timeout(timer_context->server_info, timer_context->socket_entry, PERSIST);
    }
}

/* create_timer_context
 * 
 * This function creates a timer context struct to be used for multitimer timeout handling
 * 
 * si: The serverinfo struct
 * entry: the chisocket entry struct
 * timer_id: the id of the multitimer
 * 
 * Returns a struct of type chitcpd_timer_context_t
*/
chitcpd_timer_context_t *create_timer_context(serverinfo_t *si, chisocketentry_t *entry, int timer_id) {
    chitcpd_timer_context_t *context = malloc(sizeof(chitcpd_timer_context_t));
    if (context == NULL) {
        chilog(ERROR, "Failed to allocate memory for timer context.");
        return NULL;
    }

    context->server_info = si;
    context->socket_entry = entry;
    context->timer_id = timer_id;

    return context;
}


void print_retransmission_queue(serverinfo_t *si, chisocketentry_t *entry){
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_retransmission_packet_t *current;
    if(!tcp_data->retransmission_queue){
        chilog(MINIMAL,"(empty)");
        return;
    }
    DL_FOREACH(tcp_data->retransmission_queue, current){
        chilog(MINIMAL, "Seg: %i Ack: %i length: %i", SEG_SEQ(current->packet), SEG_ACK(current->packet), TCP_PAYLOAD_LEN(current->packet));
    }
}

/* chitcpd_clean_retransmission_queue
 * 
 * This function is called whenever new data is acked to remove properly transmitted data from the retransmission
 * queue. If there is nothing left in the queue, it cancels the retransmision timer
 * 
 * si: The serverinfo struct
 * entry: the chisocket entry struct
 * packet: the received packet that's acking new data
 * 
 * Void function with no return
*/
void chitcpd_clean_retransmission_queue(serverinfo_t *si, chisocketentry_t *entry, tcp_packet_t *packet)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    pthread_mutex_lock(&tcp_data->lock_rtx_packets);
    while (tcp_data->retransmission_queue != NULL) {
        tcp_retransmission_packet_t *current = tcp_data->retransmission_queue;
        if(SEG_ACK(packet) < (SEG_SEQ(current->packet)+TCP_PAYLOAD_LEN(current->packet)))
            break;
            if(!current->retransmitted)
                calculate_rto(tcp_data, current->send_time);
            chitcp_tcp_packet_free(current->packet);
            //tcp_data->retransmission_queue = current->next;
            DL_DELETE(tcp_data->retransmission_queue,current);
    }
    /* Restart retransmission timer*/
        single_timer_t* rtx_timer;
        mt_get_timer_by_id(&tcp_data->mt,RETRANSMISSION,&rtx_timer);
        if(rtx_timer->active)
            mt_cancel_timer(&tcp_data->mt,RETRANSMISSION);
        if(tcp_data->retransmission_queue!=NULL){
            /* Restart timer when data is cleared*/
            chitcpd_timer_context_t *context = create_timer_context(si, entry, RETRANSMISSION);
            mt_set_timer(&tcp_data->mt,RETRANSMISSION,tcp_data->RTO,chitcpd_tcp_handle_callback, context);
        }
    pthread_mutex_unlock(&tcp_data->lock_rtx_packets);
}

void chitcpd_tcp_handle_persist_timeout(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    /* Creating the timer context */
    chitcpd_timer_context_t *context = create_timer_context(si, entry, PERSIST);
    if(circular_buffer_count(&tcp_data->send) > 0) {
        send_probe_packet(si, entry);
    }
    tcp_data->RTO = MIN(tcp_data->RTO,6 * SECOND);
    mt_set_timer(&tcp_data->mt, PERSIST, tcp_data->RTO, chitcpd_tcp_handle_callback, context);
}

void chitcpd_tcp_handle_rtx_timeout(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
     
    if(tcp_data->retransmission_queue ==NULL){
        send_ack_packet(si, entry, tcp_data);
        return;
    }

    single_timer_t* persist;
    mt_get_timer_by_id(&tcp_data->mt,PERSIST,&persist);
    if(persist->active){
        chilog(MINIMAL, "WINDOW is 0, can't retransmit");
        tcp_data->RTO /= 2;
        chitcpd_send_tcp_packet(si, entry, tcp_data->retransmission_queue->packet);
    }
    else{
        pthread_mutex_lock(&tcp_data->lock_rtx_packets);
        tcp_retransmission_packet_t *current;
        DL_FOREACH(tcp_data->retransmission_queue, current){
            current->retransmitted=true;
            tcphdr_t *snd_hdr = TCP_PACKET_HEADER(current->packet);
            snd_hdr->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
            chitcpd_send_tcp_packet(si, entry, current->packet);
        }
        pthread_mutex_unlock(&tcp_data->lock_rtx_packets);
    }
    // Back off the timer
    tcp_data->RTO *= 2;
    tcp_data->RTO = MIN(tcp_data->RTO,6 * SECOND);

    // Reset the retransmission timer
    chitcpd_timer_context_t *context = create_timer_context(si, entry, RETRANSMISSION);
    mt_set_timer(&tcp_data->mt, RETRANSMISSION, tcp_data->RTO, chitcpd_tcp_handle_callback, context);
}

/*
 * chitcpd_tcp_handle_packet
 *
 * This function handles packets according to RFC793
 *
 * si: serverinfo_t struct
 * entry: chisocketentry_t struct
 *
 * Returns: CHITCP_OK
 */
int chitcpd_tcp_handle_packet(serverinfo_t *si, chisocketentry_t *entry)
{
    /* Handling Packet Arrival */
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    /* Getting the incoming packet */
    tcp_packet_t *recv_packet = get_recv_packet(tcp_data);
    if(recv_packet == NULL) {
        chilog(ERROR, "Error getting packet in handle packet function");
    }
    tcphdr_t *recv_hdr = TCP_PACKET_HEADER(recv_packet);

    /* When the advertized window is 0 */

    single_timer_t* persist;
    mt_get_timer_by_id(&tcp_data->mt,PERSIST,&persist);

    /* Checking if the tcp_state is CLOSED */
    if(entry->tcp_state == CLOSED) {
        return CHITCP_OK;
    }

    /* Checking if the tcp_state is LISTEN */
    if(entry->tcp_state == LISTEN) {
        if(recv_hdr->ack) {
            /* ACK should not be set */
            return CHITCP_OK;
        } else if (recv_hdr->syn) {
            int seg_seq = SEG_SEQ(recv_packet);

            /* Assigning vars */
            tcp_data->RCV_NXT = seg_seq + 1;
            tcp_data->IRS = seg_seq;
            tcp_data->ISS = (tcp_seq)(5);//((rand() % 1000) * 10000); /* Change to 5 for consistent testing */
            tcp_data->SND_WND = fmin(SEG_WND(recv_packet),circular_buffer_available(&tcp_data->send)-tcp_data->SND_NXT+tcp_data->SND_UNA);
            tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);

            /* Setting initial SEQ for circular buffer */
            circular_buffer_set_seq_initial(&tcp_data->send, tcp_data->ISS);
            circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->IRS);

            /* Updating SND_UNA and SND_NXT */
            tcp_data->SND_UNA = tcp_data->ISS;
            tcp_data->SND_NXT = tcp_data->ISS + 1;

            /* Check if retransmission timer is on*/
            single_timer_t* rtx_timer;
            mt_get_timer_by_id(&tcp_data->mt,RETRANSMISSION,&rtx_timer);
            if(rtx_timer->active){
                mt_cancel_timer(&tcp_data->mt,RETRANSMISSION);
                //tcp_data->RTO = 200 * MILLISECOND;
            }

            /* Sending the SYN+ACK packet */
            send_syn_ack_packet(si, entry, tcp_data);

            /* Updating the TCP state to SYN_RCVD */
            chitcpd_update_tcp_state(si, entry, SYN_RCVD);

            return CHITCP_OK;
        } else {
            chilog(ERROR, "Should not be getting to here in LISTEN");
            return CHITCP_OK;
        }
    }

    /* Checking if the tcp_state is SYN_SENT */
    if(entry->tcp_state == SYN_SENT) {
        /* Setting up some useful variables */
        tcp_seq recv_seg_ack = SEG_ACK(recv_packet);
        tcp_seq recv_seg_seq = SEG_SEQ(recv_packet);

        if(recv_hdr->ack) {
            if(recv_seg_ack <= tcp_data->ISS || recv_seg_ack > tcp_data->SND_NXT)
                return CHITCP_OK;
            /* Checking to see if ACK is acceptable */
            if(!(tcp_data->SND_UNA <= recv_seg_ack && recv_seg_ack <= tcp_data->SND_NXT)) {
                return CHITCP_OK;
            }

            /* Checking header for SYN */
            if(recv_hdr->syn) {
                tcp_data->RCV_NXT = recv_seg_seq + 1;
                tcp_data->IRS = recv_seg_seq;
                tcp_data->SND_UNA = recv_seg_ack;
                
                /* Check if retransmission timer is on*/
                single_timer_t* rtx_timer;
                mt_get_timer_by_id(&tcp_data->mt,RETRANSMISSION,&rtx_timer);
                if(rtx_timer->active){
                    mt_cancel_timer(&tcp_data->mt,RETRANSMISSION);
                    //tcp_data->RTO = 200 * MILLISECOND;
                }

                /* Update state to ESTABLISHED */
                if(tcp_data->SND_UNA  > tcp_data->ISS) {
                    send_ack_packet(si, entry, tcp_data);
                    /*restart RTO as well when entering established state */
                    // tcp_data->RTO = 200 * MILLISECOND;
                    // tcp_data->SRTT = -1;
                    chitcpd_update_tcp_state(si, entry, ESTABLISHED);
                    return CHITCP_OK;
                } else {
                    /* Updating the send window and the circular buffer */
                    tcp_data->SND_WND = fmin(SEG_WND(recv_packet),circular_buffer_available(&tcp_data->send)-tcp_data->SND_NXT+tcp_data->SND_UNA);
                    circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->ISS);

                    /* Sending the SYN ACK packet */
                    send_syn_ack_packet(si, entry, tcp_data);

                    /* Updating state to SYN_RCVD */
                    chitcpd_update_tcp_state(si, entry, SYN_RCVD);
                }
            }
        }

        return CHITCP_OK;
    }

    else {
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
        tcp_data->SND_WND = fmin(SEG_WND(recv_packet),circular_buffer_available(&tcp_data->send)-tcp_data->SND_NXT+tcp_data->SND_UNA);
        tcp_seq recv_seq = SEG_SEQ(recv_packet);

        bool valid = true;
        /* Initial checks based on else-case RFC793 */
        if(TCP_PAYLOAD_LEN(recv_packet) == 0 && tcp_data->RCV_WND == 0) {
            if(recv_seq != tcp_data->RCV_NXT) {
                chilog(ERROR, "Seq doesn't match RCV_NXT");
            }
        } else if(TCP_PAYLOAD_LEN(recv_packet) > 0 && tcp_data->RCV_WND == 0) {
            chilog(ERROR, "Receive packet length greater than a 0 window");
            valid=false;
        } else if(TCP_PAYLOAD_LEN(recv_packet) == 0 && tcp_data->RCV_WND > 0) {
            if (!(tcp_data->RCV_NXT <= recv_seq < tcp_data->RCV_NXT + tcp_data->RCV_WND)) {
                chilog(ERROR, "Segment out of bounds");
                valid=false;
            }
        } else {
            if(!(tcp_data->RCV_NXT <= recv_seq && recv_seq < (tcp_data->RCV_NXT + tcp_data->RCV_WND)) &&
            !(tcp_data->RCV_NXT <= (recv_seq+TCP_PAYLOAD_LEN(recv_packet)-1) && (recv_seq+TCP_PAYLOAD_LEN(recv_packet)-1) < (tcp_data->RCV_NXT + tcp_data->RCV_WND))){
                chilog(ERROR, "Segment outside of window");
                valid=false;
            }
            if(!recv_hdr->fin && SEG_SEQ(recv_packet) < tcp_data->RCV_NXT && (SEG_SEQ(recv_packet) + TCP_PAYLOAD_LEN(recv_packet)) > tcp_data->RCV_NXT){
                int offset =  tcp_data->RCV_NXT - SEG_SEQ(recv_packet);
                int len = TCP_PAYLOAD_LEN(recv_packet) - offset;
                circular_buffer_write(&tcp_data->recv, TCP_PAYLOAD_START(recv_packet)+offset, len, BUFFER_NONBLOCKING);
                tcp_data->RCV_NXT = SEG_SEQ(recv_packet)+TCP_PAYLOAD_LEN(recv_packet);
                tcp_data->SND_WND = fmin(SEG_WND(recv_packet),circular_buffer_available(&tcp_data->send)-tcp_data->SND_NXT+tcp_data->SND_UNA);
                send_ack_packet(si,entry,tcp_data);
                valid=true;
            }
        }
        if(!valid){
            if(SEG_WND(recv_packet) == 0 && !persist->active) {
                chilog(INFO, "Setting the PERSIST timer");
                chitcpd_timer_context_t *context = create_timer_context(si, entry, PERSIST);
                mt_set_timer(&tcp_data->mt, PERSIST, tcp_data->RTO, chitcpd_tcp_handle_callback, context);
            }
            send_ack_packet(si,entry,tcp_data);
            return CHITCP_OK;
        }

        if(recv_hdr->syn){
            return CHITCP_OK;
        }
        /* If the ACK bit is off drop the segment and return */
        if(!recv_hdr->ack) {
            return CHITCP_OK;
        }

        /* Checking if the tcp_state is SYN_RCVD */
        if(entry->tcp_state == SYN_RCVD) {
            if(tcp_data->SND_UNA <= SEG_ACK(recv_packet) && SEG_ACK(recv_packet) <= tcp_data->SND_NXT) {
                /* Updating the state to ESTABLISHED */
                /* Also restarting RTO to remove conn_init values*/
                //tcp_data->RTO = 200 * MILLISECOND;
                tcp_data->SRTT = -1;
                chitcpd_update_tcp_state(si, entry, ESTABLISHED);
                tcp_data->SND_UNA = SEG_ACK(recv_packet);
                tcp_data->SND_NXT = SEG_ACK(recv_packet);
            }
        }

        /* From here the next possible state is ESTABLISHED */
        if(tcp_data->SND_UNA < SEG_ACK(recv_packet) && SEG_ACK(recv_packet) <= tcp_data->SND_NXT) {
            /* Update based on ESTABLISHED RFC */
            chitcpd_clean_retransmission_queue(si, entry, recv_packet);
        }
        if(!recv_hdr->fin && !tcp_data->closing && SEG_ACK(recv_packet) <= tcp_data->SND_UNA && (SEG_SEQ(recv_packet) + TCP_PAYLOAD_LEN(recv_packet)) <= tcp_data->RCV_NXT){
                return CHITCP_OK;// ignore -> repeated payload
            }

        tcp_data->SND_UNA = SEG_ACK(recv_packet);
        tcp_data->SND_WND = fmin(SEG_WND(recv_packet),circular_buffer_available(&tcp_data->send)-tcp_data->SND_NXT+tcp_data->SND_UNA);
        
        if (SEG_WND(recv_packet) > 0 && persist->active) {
            chilog(MINIMAL, "cancelling the PERSIST timer");
            mt_cancel_timer(&tcp_data->mt, PERSIST);
        }

        if(tcp_data->RCV_NXT < recv_seq && TCP_PAYLOAD_LEN(recv_packet)>0){
            pthread_mutex_lock(&tcp_data->lock_ooo_packets);
            chitcp_packet_list_add_in_order(&tcp_data->out_of_order_packets,recv_packet);
            pthread_mutex_unlock(&tcp_data->lock_ooo_packets);
            send_ack_packet(si, entry, tcp_data);
            return CHITCP_OK;
        }

        if(entry->tcp_state == FIN_WAIT_1){
            chitcpd_clean_retransmission_queue(si,entry,recv_packet);
            if(SEG_ACK(recv_packet) == tcp_data->SND_NXT) {
            /* Update to FIN_WAIT_2 */
            chitcpd_update_tcp_state(si, entry, FIN_WAIT_2);
        }
        else{
            send_fin_packet(si, entry, tcp_data);
        }
    }

        if(entry->tcp_state == FIN_WAIT_2) {
            /* In addition to the processing for the ESTABLISHED state, if
            the retransmission queue is empty, the user's CLOSE can be
            acknowledged */

        }

        if(SEG_ACK(recv_packet) == tcp_data->SND_NXT) {
            if(entry->tcp_state == CLOSING) {
                chitcpd_update_tcp_state(si, entry, TIME_WAIT);
                chitcpd_update_tcp_state(si, entry, CLOSED);
                return CHITCP_OK;
            } else if (entry->tcp_state == LAST_ACK) {
                chitcpd_update_tcp_state(si, entry, CLOSED);
                return CHITCP_OK;
            }
        }
        if(entry->tcp_state == TIME_WAIT){
            /* retransmission processing*/
        }

        /* Seventh, process the segment text */
        if((entry->tcp_state == ESTABLISHED) || entry->tcp_state == FIN_WAIT_1 || entry->tcp_state == FIN_WAIT_2) {
            if(TCP_PAYLOAD_LEN(recv_packet)> circular_buffer_available(&tcp_data->recv)){
               tcp_data->RCV_NXT += circular_buffer_available(&tcp_data->recv);
                circular_buffer_write(&tcp_data->recv, TCP_PAYLOAD_START(recv_packet), circular_buffer_available(&tcp_data->recv), BUFFER_NONBLOCKING);
            }
            else{
                tcp_data->RCV_NXT += TCP_PAYLOAD_LEN(recv_packet);
                circular_buffer_write(&tcp_data->recv, TCP_PAYLOAD_START(recv_packet), TCP_PAYLOAD_LEN(recv_packet), BUFFER_NONBLOCKING);
            }
            tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
            if(TCP_PAYLOAD_LEN(recv_packet)>0)
                process_out_of_order_packets(si, entry);
            int wnd = tcp_data->SND_UNA +  circular_buffer_count(&tcp_data->send) - tcp_data->SND_NXT;
            if(wnd>0) {
                if(SEG_WND(recv_packet)<wnd)
                    wnd = SEG_WND(recv_packet);
                    send_buffer(si,entry, wnd);
            } else {
                send_ack_packet(si, entry, tcp_data);
            }

        }
    }

    if(recv_hdr->fin) {
        if(entry->tcp_state == LISTEN || entry->tcp_state == SYN_SENT || entry->tcp_state == CLOSED) 
        return CHITCP_OK;

        circular_buffer_close(&tcp_data->recv);

        tcp_data->RCV_NXT += 1;
        send_ack_packet(si, entry, tcp_data);

        /* SYN received state or ESTABLSIHED state -> CLOSE_WAIT state */
        if(entry->tcp_state == SYN_RCVD || entry->tcp_state == ESTABLISHED) {
            chitcpd_update_tcp_state(si, entry, CLOSE_WAIT);
        } else if (entry->tcp_state == FIN_WAIT_1) {
            if(SEG_ACK(recv_packet) == tcp_data->SND_NXT) {
                chitcpd_update_tcp_state(si, entry, TIME_WAIT);
                chitcpd_update_tcp_state(si, entry, CLOSED); /* Change for 2B */
            } else {
                chitcpd_update_tcp_state(si, entry, CLOSING);
            }

        } else if (entry->tcp_state == FIN_WAIT_2) {
            chitcpd_update_tcp_state(si, entry, TIME_WAIT);
            chitcpd_update_tcp_state(si, entry, CLOSED);
        }
    }
    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_CLOSED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == APPLICATION_CONNECT) {
        /* Initial setup */
        circular_buffer_init(&tcp_data->recv, circular_buffer_capacity(&tcp_data->recv));
        circular_buffer_init(&tcp_data->send, circular_buffer_capacity(&tcp_data->send));
        tcp_data->closing = false;
        tcp_data->ISS = (tcp_seq)(105);//((rand() % 1000) * 10000); /* Change to 105 for consistent testing */
        tcp_data->SND_UNA = tcp_data->ISS;
        tcp_data->SND_NXT = tcp_data->ISS + 1;
        circular_buffer_set_seq_initial(&tcp_data->send, tcp_data->ISS);

        /* Updating RCV_WND */
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);

        /* Sending SYN packet */
        send_syn_packet(si, entry, tcp_data);

        /* Manually updating the TCP state */
        chitcpd_update_tcp_state(si, entry, SYN_SENT);
        return CHITCP_OK;
    } else if (event == CLEANUP) {
        /* Any additional cleanup goes here */
    } else
        chilog(WARNING, "In CLOSED state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_LISTEN(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else
        chilog(WARNING, "In LISTEN state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_RCVD(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == TIMEOUT_RTX) {
        tcp_data->RTO *= 2;
        send_syn_ack_packet(si, entry, tcp_data);
    } else
        chilog(WARNING, "In SYN_RCVD state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_SENT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == TIMEOUT_RTX) {
        tcp_data->RTO *= 2;
        send_syn_packet(si, entry, tcp_data);
    } else
        chilog(WARNING, "In SYN_SENT state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_ESTABLISHED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == APPLICATION_SEND) {
        int wnd = tcp_data->SND_UNA + circular_buffer_count(&tcp_data->send) - tcp_data->SND_NXT;
        send_buffer(si, entry, wnd);
    } else if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);

    } else if (event == APPLICATION_RECEIVE) {
        /* Updating the receive window */
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
        send_ack_packet(si,entry,tcp_data);
    } else if (event == APPLICATION_CLOSE) {
        if(circular_buffer_count(&tcp_data->send) <= 0) {
            send_fin_packet(si, entry, tcp_data);
            tcp_data->SND_NXT += 1;
            tcp_data->closing =true;
            chitcpd_update_tcp_state(si, entry, FIN_WAIT_1);
        } else {
            int wnd = tcp_data->SND_UNA + circular_buffer_count(&tcp_data->send) - tcp_data->SND_NXT;
            send_buffer(si, entry,wnd);
            send_fin_packet(si, entry, tcp_data);
            tcp_data->SND_NXT += 1;
            tcp_data->closing =true;
            chitcpd_update_tcp_state(si, entry, FIN_WAIT_1);
        }

    } else if (event == TIMEOUT_RTX) {
        chitcpd_tcp_handle_rtx_timeout(si, entry);
    } else if (event == TIMEOUT_PST) {
        chitcpd_tcp_handle_persist_timeout(si,entry);
    } else
        chilog(WARNING, "In ESTABLISHED state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_1(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == APPLICATION_RECEIVE) {
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
        send_ack_packet(si,entry,tcp_data);
    } else if (event == TIMEOUT_RTX) {
        chitcpd_tcp_handle_rtx_timeout(si, entry);
    } else if (event == TIMEOUT_PST) {
        chitcpd_tcp_handle_persist_timeout(si,entry);
    } else
        chilog(WARNING, "In FIN_WAIT_1 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_2(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == APPLICATION_RECEIVE) {
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
        send_ack_packet(si,entry,tcp_data);
    } else if (event == TIMEOUT_RTX) {
        chitcpd_tcp_handle_rtx_timeout(si, entry);
    } else
        chilog(WARNING, "In FIN_WAIT_2 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_CLOSE_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == APPLICATION_CLOSE) {
        if(circular_buffer_count(&tcp_data->send) == 0) {
            send_fin_packet(si, entry, tcp_data);
        } else {
            tcp_data->closing = true;
        }
        chitcpd_update_tcp_state(si, entry, LAST_ACK); /* Follow diagram */
    } else if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == TIMEOUT_RTX) {
        chitcpd_tcp_handle_rtx_timeout(si, entry);
    } else if (event == TIMEOUT_PST) {
        chitcpd_tcp_handle_persist_timeout(si,entry);
    } else
        chilog(WARNING, "In CLOSE_WAIT state, received unexpected event (%i).", event);


    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_CLOSING(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == TIMEOUT_RTX) {
        chitcpd_tcp_handle_rtx_timeout(si, entry);
    } else if (event == TIMEOUT_PST) {
        chitcpd_tcp_handle_persist_timeout(si,entry);
    } else
        chilog(WARNING, "In CLOSING state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_TIME_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    chilog(WARNING, "Running handler for TIME_WAIT. This should not happen");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_LAST_ACK(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == TIMEOUT_RTX) {
        chitcpd_tcp_handle_rtx_timeout(si, entry);
    } else if (event == TIMEOUT_PST) {
       chitcpd_tcp_handle_persist_timeout(si,entry);
    } else
        chilog(WARNING, "In LAST_ACK state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

/*                                                           */
/*     Any additional functions you need should go here      */
/*                                                           */


/*
 * get_recv_packet
 *
 * Locks the mutex, creates a new tcp_packet_t sruct, gets the packet
 * from the pending_packets, then pops the packet off the head, and then
 * unlocks the mutex and returns the found packet.
 *
 * tcp_data: tcp_data_t struct
 *
 * Returns: tcp_packet_t the received packet from the top of the list
 */
tcp_packet_t *get_recv_packet(tcp_data_t *tcp_data)
{
    /* Locking the data mutex */
    pthread_mutex_lock(&tcp_data->lock_pending_packets);

    /* Getting the receive packet */
    tcp_packet_t *recv_packet = tcp_data->pending_packets->packet;
    chitcp_packet_list_pop_head(&tcp_data->pending_packets);

    /* Unlocking the mutex */
    pthread_mutex_unlock(&tcp_data->lock_pending_packets);

    return recv_packet;
}


/*
 * send_syn_packet
 *
 * This function creates, sends, and frees the SYN packet
 *
 * si: serverinfo_t struct
 * entry: chisocketentry_t struct
 * tcp_data: tcp_data_t struct
 *
 * Returns: Nothing (void function)
 */
void send_syn_packet(serverinfo_t *si, chisocketentry_t *entry, tcp_data_t *tcp_data)
{

    /* Initializing the SYN packet (1st in 3-way handshake) */
    tcp_packet_t *syn_packet = malloc(sizeof(tcp_packet_t));
    if(syn_packet == NULL) {
        chilog(ERROR, "Error allocating for packet");
        return;
    }

    /* Creating packet and header */
    chitcpd_tcp_packet_create(entry, syn_packet, NULL, 0);
    tcphdr_t *hdr = TCP_PACKET_HEADER(syn_packet);

    /* Assigning the flag bits for the header*/
    hdr->syn = 1;
    hdr->seq = chitcp_htonl(tcp_data->ISS);
    hdr->win = chitcp_htons(tcp_data->RCV_WND);

    /* Sending the first SYN packet */
    chitcpd_send_tcp_packet(si, entry, syn_packet);
    chitcp_tcp_packet_free(syn_packet);
    free(syn_packet);

    /* Starting retransmission timer*/
    single_timer_t* rtx_timer;
    mt_get_timer_by_id(&tcp_data->mt,RETRANSMISSION,&rtx_timer);
    if(!rtx_timer->active){
        chitcpd_timer_context_t *context = create_timer_context(si, entry, RETRANSMISSION);
        mt_set_timer(&tcp_data->mt,RETRANSMISSION,tcp_data->RTO,chitcpd_tcp_handle_callback, context);
    }

}

/*
 * send_ack_packet
 *
 * This function creates, sends, and frees the ACK packet
 *
 * si: serverinfo_t struct
 * entry: chisocketentry_t struct
 * tcp_data: tcp_data_t struct
 *
 * Returns: Nothing (void function)
 */
void send_ack_packet(serverinfo_t *si, chisocketentry_t *entry, tcp_data_t *tcp_data)
{
    single_timer_t* persist;
    mt_get_timer_by_id(&tcp_data->mt,PERSIST,&persist);
    if(persist->active){
        chilog(MINIMAL, "WINDOW is 0, can't send");
        return;
    }
    /* Preparing ACK packet */
    tcp_packet_t *snd_packet = malloc(sizeof(tcp_packet_t));
    chitcpd_tcp_packet_create(entry, snd_packet, NULL, 0);
    tcphdr_t *snd_hdr = TCP_PACKET_HEADER(snd_packet);

    /* Assigning the ACK vars */
    snd_hdr->seq = chitcp_htonl(tcp_data->SND_NXT);
    snd_hdr->win = chitcp_htons(tcp_data->RCV_WND);
    snd_hdr->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
    snd_hdr->ack = 1;

    /* Freeing then sending FIN packet */
    if(tcp_data->closing) {
        chitcp_tcp_packet_free(snd_packet);
        free(snd_packet);
        send_fin_packet(si,entry,tcp_data);
        return;
    }

    /* Sending ACK packet */
    chitcpd_send_tcp_packet(si, entry, snd_packet);
    chitcp_tcp_packet_free(snd_packet);
    free(snd_packet);
}

/*
 * send_syn_ack_packet
 *
 * This function creates, sends, and frees the SYN+ACK packet
 *
 * si: serverinfo_t struct
 * entry: chisocketentry_t struct
 * tcp_data: tcp_data_t struct
 *
 * Returns: Nothing (void function)
 */
void send_syn_ack_packet(serverinfo_t *si, chisocketentry_t *entry, tcp_data_t *tcp_data)
{

    /* Packet creation and var assignment */
    tcp_packet_t *snd_packet = malloc(sizeof(tcp_packet_t));
    chitcpd_tcp_packet_create(entry, snd_packet, NULL, 0);
    tcphdr_t *snd_hdr = TCP_PACKET_HEADER(snd_packet);

    /* Have to change snd_hdr based on tcp_state */
    // if(entry->tcp_state == LISTEN) {
        snd_hdr->seq = chitcp_htonl(tcp_data->ISS);
    // } else {
    //     snd_hdr->seq = chitcp_htonl(tcp_data->SND_NXT);
    // }

    /* Assigning packet vars */
    snd_hdr->win = chitcp_htons(tcp_data->RCV_WND);
    snd_hdr->ack_seq = chitcp_htonl(tcp_data->IRS+1);
    snd_hdr->syn = 1;
    snd_hdr->ack = 1;

    /* Sending the packet */
    chitcpd_send_tcp_packet(si, entry, snd_packet);
    chitcp_tcp_packet_free(snd_packet);
    free(snd_packet);

    /* Starting retransmission timer*/
    single_timer_t* rtx_timer;
    mt_get_timer_by_id(&tcp_data->mt,RETRANSMISSION,&rtx_timer);
    if(!rtx_timer->active){
        chitcpd_timer_context_t *context = create_timer_context(si, entry, RETRANSMISSION);
        mt_set_timer(&tcp_data->mt,RETRANSMISSION,tcp_data->RTO,chitcpd_tcp_handle_callback, context);
    }
}

/*
 * send_fin_packet
 *
 * This function creates, sends, and frees the FIN packet
 *
 * si: serverinfo_t struct
 * entry: chisocketentry_t struct
 * tcp_data: tcp_data_t struct
 *
 * Returns: Nothing (void function)
 */
void send_fin_packet(serverinfo_t *si, chisocketentry_t *entry, tcp_data_t *tcp_data)
{

    /* Creating FIN packet and header */
    tcp_packet_t *fin_packet = malloc(sizeof(tcp_packet_t));
    chitcpd_tcp_packet_create(entry, fin_packet, NULL, 0);
    tcphdr_t *fin_hdr = TCP_PACKET_HEADER(fin_packet);

    /* Assigning packet vars */
    fin_hdr->seq = chitcp_htonl(tcp_data->SND_NXT);
    fin_hdr->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
    fin_hdr->win = chitcp_htons(tcp_data->RCV_WND);
    fin_hdr->ack = 1;
    fin_hdr->fin = 1;

    /* Sending packet */
    chitcpd_send_tcp_packet(si, entry, fin_packet);
    chitcp_tcp_packet_free(fin_packet);
    free(fin_packet);

    /* Closing circular buffer*/
    circular_buffer_close(&tcp_data->send);
}

/*
 * send_buffer
 *
 * This function sends data from the circular buffer and creates the TCP packet
 * that will be sent over the network.
 *
 * si: serverinfo_t struct
 * entry: chisocketentry_t struct
 * wnd: the current size of the send window
 *
 * Returns: Nothing (void function)
 */
void send_buffer(serverinfo_t *si, chisocketentry_t *entry, int wnd)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    int sent = 0;

    single_timer_t* persist;
    mt_get_timer_by_id(&tcp_data->mt,PERSIST,&persist);
    if(persist->active){
        chilog(INFO, "WINDOW is 0, can't send more data");
        return;
    }

    while(sent < wnd) {
        int unread = TCP_MSS < wnd ? TCP_MSS : wnd;
        uint8_t data[unread];

        /* Need to change to peak later to handle lost data */
        int read = circular_buffer_read(&tcp_data->send, data, unread, 0);

        /* Testing for cases that would require break */
        if(read == CHITCP_EWOULDBLOCK || read <= 0) {
            break;
        }

        /* Send the packet */
        tcp_packet_t *snd_packet = malloc(sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, snd_packet, data, read);
        tcphdr_t *snd_hdr = TCP_PACKET_HEADER(snd_packet);

        /* Setting the packet vars */
        snd_hdr->seq = chitcp_htonl(tcp_data->SND_NXT);
        snd_hdr->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
        snd_hdr->win = chitcp_htons(tcp_data->RCV_WND);
        snd_hdr->ack = 1;

        /* Sending the data packet */
        chitcpd_send_tcp_packet(si, entry, snd_packet);
        chitcp_rtx_queue_add_in_order(&tcp_data->retransmission_queue, snd_packet);

        /* Updating the send next */
        tcp_data->SND_WND -= read;
        tcp_data->SND_NXT+=read;

        /* Updating the sent variable */
        sent += read;
    }

    /* Starting retransmission timer*/
    single_timer_t* rtx_timer;
    mt_get_timer_by_id(&tcp_data->mt,RETRANSMISSION,&rtx_timer);
    if(!rtx_timer->active){
        chitcpd_timer_context_t *context = create_timer_context(si, entry, RETRANSMISSION);
        mt_set_timer(&tcp_data->mt,RETRANSMISSION,tcp_data->RTO,chitcpd_tcp_handle_callback, context);
    }


    /* Sending FIN packet */
    if(tcp_data->closing && circular_buffer_count(&tcp_data->send)<=0) {
        send_fin_packet(si,entry,tcp_data);
    }
}

/*
 * process_out_of_order_packets
 *
 * This function iterates through the out of order packet list and processes them
 *
 *
 * si: serverinfo_t struct
 * entry: chisocketentry_t struct
 * wnd: the current size of the send window
 *
 * Returns: CHITCP_OK if properly handled
 */
int process_out_of_order_packets(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    bool processed_packet = false;

    pthread_mutex_lock(&tcp_data->lock_ooo_packets);
    tcp_packet_list_t *current_packet = tcp_data->out_of_order_packets;

    while(current_packet != NULL && SEG_SEQ(current_packet->packet) == tcp_data->RCV_NXT) {
        tcp_packet_t *packet = current_packet->packet;
        tcp_data->RCV_NXT += TCP_PAYLOAD_LEN(packet);
        circular_buffer_write(&tcp_data->recv, TCP_PAYLOAD_START(packet), TCP_PAYLOAD_LEN(packet), BUFFER_NONBLOCKING);
        tcp_packet_list_t *temp = current_packet;
        current_packet = current_packet->next;
        DL_DELETE(tcp_data->out_of_order_packets, temp);
        free(temp->packet);
        free(temp);
        processed_packet = true;
    }

    pthread_mutex_unlock(&tcp_data->lock_ooo_packets);

    return CHITCP_OK;
}

/* See tcp.h */
int compare_packets(tcp_packet_list_t *item1, tcp_packet_list_t *item2)
{
    tcp_packet_t *packet1 = item1->packet;
    tcp_packet_t *packet2 = item2->packet;
    return SEG_SEQ(packet1) - SEG_SEQ(packet2);
}

/* See tcp.h */
int chitcp_packet_list_add_in_order(tcp_packet_list_t **pl, tcp_packet_t *packet) 
{
    tcp_packet_list_t *elt = calloc(1, sizeof(tcp_packet_list_t));

    elt->packet = packet;

    DL_INSERT_INORDER(*pl, elt, compare_packets);

    return CHITCP_OK;
}


/*
 * compare_rtx_packets
 *
 * Helper function used for chitcp_rtx_queue_add_in_order
 *
 * item1: retransmission packet to compare
 * item2: retransmission packet to compare
 *
 * Returns: comparison integer between two retransmision packets
 */
int compare_rtx_packets(tcp_retransmission_packet_t *item1, tcp_retransmission_packet_t *item2){
    tcp_packet_t *packet1 = item1->packet;
    tcp_packet_t *packet2 = item2->packet;
    return SEG_SEQ(packet1) - SEG_SEQ(packet2);
}


/*
 * chitcp_rtx_queue_add_in_order
 *
 * This function adds a transmitted packet to the retransmission queue, as well as
 * stores the current time of transmission to be used for RTO calculation later
 *
 * pl: the retransmission queue to append
 * packet: the packet to be added to the queue
 *
 * Returns: CHITCP_OK if properly handled
 */
int chitcp_rtx_queue_add_in_order(tcp_retransmission_packet_t **pl, tcp_packet_t *packet){
    tcp_retransmission_packet_t *elt = calloc(1, sizeof(tcp_retransmission_packet_t));
    elt->packet = packet;
    elt->retransmitted = false;

    /* First check for duplicates*/
    tcp_retransmission_packet_t *head = *pl;
    while(head){
        if(compare_rtx_packets(head,elt)==0){
            head->retransmitted=true;
            return CHITCP_OK;
        }
        head=head->next;
    }

    struct timespec *now = malloc (sizeof (struct timespec));
    clock_gettime(CLOCK_REALTIME, now);
    elt->send_time = now;
    DL_INSERT_INORDER(*pl, elt, compare_rtx_packets);

    return CHITCP_OK;
}

/*
 * calculate_rto
 *
 * This function gets the send time of a packet and the current time and calculates
 *  the RTT and RTO accordingly
 *
 * tcp_data: the tcp_data of the socket
 * send_time: the timespec of the original send time of the packet
 *
 * Returns: CHITCP_OK if properly handled
 */
int calculate_rto(tcp_data_t *tcp_data, struct timespec *send_time)
{
    /* Constants for the function */
    uint64_t G = 50 * MILLISECOND; 
    uint64_t min = 200 * MILLISECOND;
    uint64_t max = 6 * SECOND; // changed to 6 seconds

    /* for CONN INIT drop syn/drop ack, since we are not adding to rtx queue*/
    if(send_time==NULL){
        send_time = malloc (sizeof (struct timespec));
        clock_gettime(CLOCK_REALTIME, send_time);
    }

    struct timespec now;
    struct timespec temp;
    clock_gettime(CLOCK_REALTIME, &now);
    timespec_subtract(&temp, &now, send_time);
    uint64_t RTT = temp.tv_sec * SECOND + temp.tv_nsec;

    /* Check for initial RTT measurement */
    if (tcp_data->SRTT == -1) {
        /* This is the first RTT measurement */
        tcp_data->SRTT = RTT;
        tcp_data->RTTVAR = RTT / 2.0;
        tcp_data->RTO = tcp_data->SRTT + MAX(G, 4 * tcp_data->RTTVAR);
    } else {
        /* Update RTTVAR and SRTT */
        tcp_data->RTTVAR = (1 - 0.25) * tcp_data->RTTVAR + 0.25 * labs(tcp_data->SRTT - RTT);
        tcp_data->SRTT = (1 - 0.125) * tcp_data->SRTT + 0.125 * RTT;
        tcp_data->RTO = tcp_data->SRTT + MAX(G, 4 * tcp_data->RTTVAR);
    }
    /* Ensure RTO is not less than the minimum threshold */
    tcp_data->RTO = MAX(tcp_data->RTO,min); // minimum RTO
    tcp_data->RTO = MIN(tcp_data->RTO,max);
    return CHITCP_OK;
}


/*
 * send_probe_packet
 *
 * This function sends one byte of data when the persist timer is on and there is data in the send buffer
 *
 *
 * si: serverinfo_t struct
 * entry: chisocketentry_t struct
 *
 * Returns: CHITCP_OK if properly handled
 */
void send_probe_packet(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    // We need to send only one byte to probe the connection
    uint8_t data[1];
    int read = circular_buffer_read(&tcp_data->send, data, 1, BUFFER_NONBLOCKING);

    if(read <= 0) {
        chilog(ERROR, "No data available to send as probe packet.");
        return; // Optionally handle this case more gracefully
    }

    // Create and set up the packet
    tcp_packet_t *snd_packet = malloc(sizeof(tcp_packet_t));
    if (snd_packet == NULL) {
        chilog(ERROR, "Failed to allocate memory for probe packet.");
        return;
    }

    chitcpd_tcp_packet_create(entry, snd_packet, data, read);
    tcphdr_t *snd_hdr = TCP_PACKET_HEADER(snd_packet);

    // Setting the packet vars
    snd_hdr->seq = chitcp_htonl(tcp_data->SND_NXT);
    snd_hdr->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
    snd_hdr->win = chitcp_htons(tcp_data->RCV_WND);
    snd_hdr->ack = 1;

    tcp_data->SND_NXT+=1;

    // Sending the probe packet
    chitcpd_send_tcp_packet(si, entry, snd_packet);
    chitcp_rtx_queue_add_in_order(&tcp_data->retransmission_queue, snd_packet);

    // Log that a probe packet has been sent
    chilog(INFO, "Probe packet sent with 1 byte of data from SND.NXT.");
}