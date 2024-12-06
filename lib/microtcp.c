/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "microtcp.h"
#include "../utils/crc32.h"

microtcp_sock_t
microtcp_socket (int domain, int type, int protocol)
{
  microtcp_sock_t socket;
  socket.sd = socket(domain, type, protocol);
  if (socket.sd == -1) { /* socket returned invalid */
    socket.state = INVALID;
    perror("Failed to create the socket");
    return socket; /* return the invalid socket */
  }
  /* else init the socket fields */ 
  socket.state =          LISTEN; /* waitfor incoming connections */ 
  socket.init_win_size =  MICROTCP_WIN_SIZE; /* full window usage */ 
  socket.curr_win_size =  MICROTCP_WIN_SIZE;
  socket.recvbuf =        NULL;
  socket.buf_fill_level =   0;
  socket.cwnd =           MICROTCP_INIT_CWND; /* congestion window */ 
  socket.ssthresh =       MICROTCP_INIT_SSTHRESH; /* slow start th */ 
  socket.seq_number =       0;
  socket.ack_number =       0;
  socket.packets_send =     0;
  socket.packets_received = 0;
  socket.packets_lost =     0;
  socket.bytes_send =       0;
  socket.bytes_received =   0;
  socket.bytes_lost =       0; 
  /* fields initialized with 0 or NULL are negotiated on connection */ 

  return socket; /* return the valid socket */
}

int
microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address,
               socklen_t address_len)
{
  /* assign the given address to the socket */
  if (bind(socket->sd, address, address_len) == -1) {
    socket->state = INVALID;
    perror("Failed to bind address to the socket");
    return -1;
  }
  return 0;
}

int
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len)
{
  /* create and send SYN packet */
  microtcp_header_t syn_packet;
  syn_packet.seq_number =   rand(time(NULL)) % 1000; /* random seq number */
  syn_packet.ack_number =   0;
  syn_packet.control =      MICROTCP_SYN;
  syn_packet.window =       socket->init_win_size;
  syn_packet.data_len =     0;
  syn_packet.future_use0 =  0;
  syn_packet.future_use1 =  0;
  syn_packet.future_use2 =  0;  
  syn_packet.checksum = crc32((uint8_t *)&syn_packet, sizeof(syn_packet));

  if (sendto(socket->sd, &syn_packet, sizeof(syn_packet), 0, address, address_len) == -1) {
    socket->state = INVALID;
    perror("Failed to send SYN packet");
    return -1;
  } /* SYN packet sent */

  /* wait for SYN-ACK packet */
  microtcp_header_t syn_ack_packet;
  if (recvfrom(socket->sd, &syn_ack_packet, sizeof(syn_ack_packet), 0, address, &address_len) == -1) {
    socket->state = INVALID;
    perror("Failed to receive SYN-ACK packet");
    return -1;
  } /* SYN-ACK packet received */

  /* create and send ACK packet */
  microtcp_header_t ack_packet;
  ack_packet.seq_number =   syn_ack_packet.ack_number; 
  ack_packet.ack_number =   syn_ack_packet.seq_number + 1;
  ack_packet.control =      MICROTCP_ACK;
  ack_packet.window =       socket->curr_win_size;
  ack_packet.data_len =     0;
  ack_packet.future_use0 =  0;
  ack_packet.future_use1 =  0;
  ack_packet.future_use2 =  0;
  ack_packet.checksum = crc32((uint8_t *)&ack_packet, sizeof(ack_packet));

  /* first compare checksums */
  if (ack_packet.checksum != syn_ack_packet.checksum) {
    socket->state = INVALID;
    perror("SYN_ACK ACK checksums mismatch");
    return -1;
  } /* checksums match */

  /* ensure received packet is SYN_ACK */
  if (syn_ack_packet.control != MICROTCP_SYN_ACK) {
    socket->state = INVALID;
    perror("Received packet is not SYN_ACK");
    return -1;
  } /* received packet is SYN_ACK */

  if (sendto(socket->sd, &ack_packet, sizeof(ack_packet), 0, address, address_len) == -1) {
    socket->state = INVALID;
    perror("Failed to send ACK packet");
    return -1;
  } /* ACK packet sent */

  /* assume connection was accepted */
  socket->state = ESTABLISHED;
  socket->seq_number = ack_packet.seq_number;
  socket->ack_number = ack_packet.ack_number;
  /* initialize receive buffer */
  socket->recvbuf = malloc(MICROTCP_RECVBUF_LEN);
  return 0;
}

int
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
                 socklen_t address_len)
{
  /* Your code here (phase 1) */
}

int
microtcp_shutdown (microtcp_sock_t *socket, int how)
{
  /* Your code here (phase 1) */
}

ssize_t
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,
               int flags)
{
  /* Your code here (phase 2) */
}

ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  /* Your code here (phase 2) */
}
