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
  microtcp_sock_t new_socket;
  new_socket.sd = socket(domain, type, protocol);
  if (new_socket.sd == -1) { /* socket returned invalid */
    new_socket.state = INVALID;
    perror("Failed to create the socket");
    return new_socket; /* return the invalid socket */
  }
  /* else init the socket fields */ 
  new_socket.state =          LISTEN; /* waitfor incoming connections */ 
  new_socket.init_win_size =  MICROTCP_WIN_SIZE; /* full window usage */ 
  new_socket.curr_win_size =  MICROTCP_WIN_SIZE;
  new_socket.recvbuf =        NULL;
  new_socket.buf_fill_level =   0;
  new_socket.cwnd =           MICROTCP_INIT_CWND; /* congestion window */ 
  new_socket.ssthresh =       MICROTCP_INIT_SSTHRESH; /* slow start th */ 
  new_socket.seq_number =       0;
  new_socket.ack_number =       0;
  new_socket.packets_send =     0;
  new_socket.packets_received = 0;
  new_socket.packets_lost =     0;
  new_socket.bytes_send =       0;
  new_socket.bytes_received =   0;
  new_socket.bytes_lost =       0; 
  new_socket.client_addr =      NULL; 
  new_socket.server_addr =      NULL; 
  /* fields initialized with 0 or NULL are negotiated on connection */ 

  return new_socket; /* return the valid socket */
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
  /* assign server address value */
  socket->server_addr = address;
  /* create and send SYN packet */
  srand(time(NULL));
  microtcp_header_t syn_packet;
  syn_packet.seq_number =   rand() % 1000; /* random seq number */
  syn_packet.ack_number =   0;
  syn_packet.control =      MICROTCP_SYN;
  syn_packet.window =       socket->curr_win_size;
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
  /* initialize receive buffer */
  socket->recvbuf = malloc(MICROTCP_RECVBUF_LEN);
  
  return socket->sd; /* return the socket descriptor */
}

int
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
                 socklen_t address_len)
{
  /* assign client address value */
  socket->client_addr = address;
  /* wait for SYN packet */
  microtcp_header_t syn_packet;
  if (recvfrom(socket->sd, &syn_packet, sizeof(syn_packet), 0, address, &address_len) == -1) {
    socket->state = INVALID;
    perror("Failed to receive SYN packet");
    return -1;
  } /* SYN packet received */

  /* create and send SYN-ACK packet */
  srand(time(NULL));
  microtcp_header_t syn_ack_packet;
  syn_ack_packet.seq_number =   rand() % 1000; /* random seq number */
  syn_ack_packet.ack_number =   syn_packet.seq_number + 1;
  syn_ack_packet.control =      MICROTCP_SYN_ACK;
  syn_ack_packet.window =       socket->curr_win_size;
  syn_ack_packet.data_len =     0;
  syn_ack_packet.future_use0 =  0;
  syn_ack_packet.future_use1 =  0;
  syn_ack_packet.future_use2 =  0;
  syn_ack_packet.checksum = crc32((uint8_t *)&syn_ack_packet, sizeof(syn_ack_packet));

  /* first compare checksums */
  if (syn_ack_packet.checksum != syn_packet.checksum) {
    socket->state = INVALID;
    perror("SYN SYN_ACK checksums mismatch");
    return -1;
  } /* checksums match */

  /* ensure received packet is SYN */
  if (syn_packet.control != MICROTCP_SYN) {
    socket->state = INVALID;
    perror("Received packet is not SYN");
    return -1;
  } /* received packet is SYN */

  if (sendto(socket->sd, &syn_ack_packet, sizeof(syn_ack_packet), 0, address, address_len) == -1) {
    socket->state = INVALID;
    perror("Failed to send SYN-ACK packet");
    return -1;
  } /* SYN-ACK packet sent */

  /* wait for ACK packet */
  microtcp_header_t ack_packet;
  if (recvfrom(socket->sd, &ack_packet, sizeof(ack_packet), 0, address, &address_len) == -1) {
    socket->state = INVALID;
    perror("Failed to receive ACK packet");
    return -1;
  } /* ACK packet received */

  /* ensure received packet is ACK */
  if (ack_packet.control != MICROTCP_ACK) {
    socket->state = INVALID;
    perror("Received packet is not ACK");
    return -1;
  } /* received packet is ACK */

  /* accepting connection */
  socket->state = ESTABLISHED;
  socket->seq_number = ack_packet.ack_number;
  socket->ack_number = ack_packet.seq_number + 1; 

  return socket->sd; /* return the new socket descriptor */
}

int
microtcp_shutdown (microtcp_sock_t *socket, int how)
{
  /* client send a FIN packet to initiate connection shutdown */
  microtcp_header_t client_fin_packet;
  client_fin_packet.seq_number =   socket->seq_number;
  client_fin_packet.ack_number =   socket->ack_number;
  client_fin_packet.control =      MICROTCP_FIN;
  client_fin_packet.window =       socket->curr_win_size;
  client_fin_packet.data_len =     0;
  client_fin_packet.future_use0 =  0;
  client_fin_packet.future_use1 =  0;
  client_fin_packet.future_use2 =  0;
  client_fin_packet.checksum = crc32((uint8_t *)&client_fin_packet, sizeof(client_fin_packet));

  if (sendto(socket->sd, &client_fin_packet, sizeof(client_fin_packet), 0, socket->server_addr, sizeof(socket->server_addr)) == -1) {
    socket->state = INVALID;
    perror("Client failed to send FIN packet");
    return -1;
  } /* client FIN packet sent */

  /* server receive the FIN packet */
  microtcp_header_t received_client_fin_packet;
  if (recvfrom(socket->sd, &received_client_fin_packet, sizeof(received_client_fin_packet), 0, socket->client_addr, sizeof(socket->client_addr)) == -1) {
    socket->state = INVALID;
    perror("Server failed to receive FIN packet");
    return -1;
  } /* client FIN packet received */

  /* ensure received packet is FIN */
  if (received_client_fin_packet.control != MICROTCP_FIN) {
    socket->state = INVALID;
    perror("Received packet is not FIN");
    return -1;
  } /* received packet is FIN */

  /* server respond to client FIN packet with an ACK */
  microtcp_header_t server_ack_packet;
  server_ack_packet.seq_number =   received_client_fin_packet.ack_number;
  server_ack_packet.ack_number =   received_client_fin_packet.seq_number;
  server_ack_packet.control =      MICROTCP_ACK;
  server_ack_packet.window =       socket->curr_win_size;
  server_ack_packet.data_len =     0;
  server_ack_packet.future_use0 =  0;
  server_ack_packet.future_use1 =  0;
  server_ack_packet.future_use2 =  0;
  server_ack_packet.checksum = crc32((uint8_t *)&server_ack_packet, sizeof(server_ack_packet));

  /* first compare checksums */
  if (server_ack_packet.checksum != received_client_fin_packet.checksum) {
    socket->state = INVALID;
    perror("FIN ACK checksums mismatch");
    return -1;
  } /* checksums match */

  if (sendto(socket->sd, &server_ack_packet, sizeof(server_ack_packet), 0, socket->client_addr, sizeof(socket->client_addr)) == -1) {
    socket->state = INVALID;
    perror("Server failed to send ACK packet");
    return -1;
  } /* server ACK packet sent */
  socket->state = CLOSING_BY_PEER;

  /* client receive the ACK packet */
  microtcp_header_t received_server_ack_packet;
  if (recvfrom(socket->sd, &received_server_ack_packet, sizeof(received_server_ack_packet), 0, socket->server_addr, sizeof(socket->server_addr)) == -1) {
    socket->state = INVALID;
    perror("Client failed to receive ACK packet");
    return -1;
  } /* server ACK packet received */

  /* ensure received packet is ACK */
  if (received_server_ack_packet.control != MICROTCP_ACK) {
    socket->state = INVALID;
    perror("Received packet is not ACK");
    return -1;
  } /* received packet is ACK */

  /* first compare checksums */
  if (received_server_ack_packet.checksum != server_ack_packet.checksum) {
    socket->state = INVALID;
    perror("ACK checksums mismatch");
    return -1;
  } /* checksums match */
  socket->state = CLOSING_BY_HOST;

  /* server executes any opperations left and sends a FIN packet to the client */
  free(socket->recvbuf);

  microtcp_header_t server_fin_packet;
  server_fin_packet.seq_number =   server_ack_packet.seq_number;
  server_fin_packet.ack_number =   server_ack_packet.ack_number + 1;
  server_fin_packet.control =      MICROTCP_FIN;
  server_fin_packet.window =       socket->curr_win_size;
  server_fin_packet.data_len =     0;
  server_fin_packet.future_use0 =  0;
  server_fin_packet.future_use1 =  0;
  server_fin_packet.future_use2 =  0;
  server_fin_packet.checksum = crc32((uint8_t *)&server_fin_packet, sizeof(server_fin_packet));

  if (sendto(socket->sd, &server_fin_packet, sizeof(server_fin_packet), 0, socket->client_addr, sizeof(socket->client_addr)) == -1) {
    socket->state = INVALID;
    perror("Server failed to send FIN packet");
    return -1;
  } /* server FIN packet sent */

  /* client receive the server FIN packet */
  microtcp_header_t received_server_fin_packet;
  if (recvfrom(socket->sd, &received_server_fin_packet, sizeof(received_server_fin_packet), 0, socket->server_addr, sizeof(socket->server_addr)) == -1) {
    socket->state = INVALID;
    perror("Client failed to receive FIN packet");
    return -1;
  } /* server FIN packet received */

  /* ensure received packet is FIN */
  if (received_server_fin_packet.control != MICROTCP_FIN) {
    socket->state = INVALID;
    perror("Received packet is not FIN");
    return -1;
  } /* received packet is FIN */

  /* first compare checksums */
  if (received_server_fin_packet.checksum != server_fin_packet.checksum) {
    socket->state = INVALID;
    perror("FIN checksums mismatch");
    return -1;
  } /* checksums match */

  /* client respond to server FIN packet with an ACK */
  microtcp_header_t client_ack_packet;
  client_ack_packet.seq_number =   received_server_fin_packet.ack_number;
  client_ack_packet.ack_number =   received_server_fin_packet.seq_number + 1;
  client_ack_packet.control =      MICROTCP_ACK;
  client_ack_packet.window =       socket->curr_win_size;
  client_ack_packet.data_len =     0;
  client_ack_packet.future_use0 =  0;
  client_ack_packet.future_use1 =  0;
  client_ack_packet.future_use2 =  0;
  client_ack_packet.checksum = crc32((uint8_t *)&client_ack_packet, sizeof(client_ack_packet));

  /* first compare checksums */
  if (client_ack_packet.checksum != received_server_fin_packet.checksum) {
    socket->state = INVALID;
    perror("FIN ACK checksums mismatch");
    return -1;
  } /* checksums match */

  if (sendto(socket->sd, &client_ack_packet, sizeof(client_ack_packet), 0, socket->server_addr, sizeof(socket->server_addr)) == -1) {
    socket->state = INVALID;
    perror("Client failed to send ACK packet");
    return -1;
  } /* client ACK packet sent */
  socket->state = CLOSED;

  return 0;
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
