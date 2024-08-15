Project 2 Resubmission
======================

Team members:
- Shivani Puli (shivanipuli)
- Spencer Dearman (dearmanspencer)

Resubmission for:
[ ] Project 2A
[X] Project 2B

Rubric items you have addressed
-------------------------------
 - Correctness - RTT estimation [Doing RTT estimation, but not excluding retransmitted segments from the RTT estimation]
On line 288 in the function chitcpd_tcp_handle_rtx_timeout and on line 226 in function chitcpd_clean_retransmission_queue, we added a check to omit retransmissited packets from RTT estimations.

- Correctness - General [Incorrect code for checking a condition specified in the RFC]
We fixed chitcpd_tcp_handle_packet to match exactly the format of the RFC. We put the timer handling in the right place rather than having it at the top of our function.

- Correctness - Persist timer [Not updating SND.NXT when sending a probe segment.]
We changed probe packet handling to update SND.NXT isn't necessary. This is found on line 1303.

- Completeness SNU Score
(listed in the changes to pass additional tests)

- Code Quality
We earned an S in Code Quality in Project 2B


Rubric items you have NOT addressed
-----------------------------------
n/a

Substantial new code added to your submission
---------------------------------------------
n/a

Changes made to pass additional tests
-------------------------------------
1. We fixed our unreliable connection termination by properly checking that the retransmission queue was empty beforing advancing over RCV.NXT. Before we were always updating RCV.NXT+1.
2. We were not sending an ack packet when handling the event APPLICATION_RECEIVE to let the other client know when the receive window is no longer 0, which was causing a major timeout issue. Adding that line of code under the EVENT=APPLICATION_RECEIVE case fixed many major issues. 
3. We also had major issues with the ordering of our packet_handler which we restructured. 
4. We also weren't properly removing packets from our retransmission queue once they'd been acked which was causing issues. 


Other changes
-------------
RTO calculations are done when appending a packet to rtx in chitcp_rtx_queue_add_in_order.