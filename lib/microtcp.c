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

packet_list_t *
packet_list_create (microtcp_header_t *packet, size_t size)
{
  packet_list_t *new_list = malloc(sizeof(packet_list_t));
  new_list->packet = packet;
  new_list->size = size;
  new_list->next = NULL;
  return new_list;
}

void
packet_list_add (packet_list_t *list, microtcp_header_t *packet, size_t size)
{
  packet_list_t *new_list = packet_list_create(packet, size);
  while (list->next != NULL) {
    list = list->next;
  }
  list->acked = 0;
  list->next = new_list;
}

void
packet_list_remove (packet_list_t *list, microtcp_header_t *packet, size_t size)
{
  packet_list_t *prev = list;
  while (list != NULL) {
    if (list->packet == packet && list->size == size) {
      prev->next = list->next;
      free(list);
      break;
    }
    prev = list;
    list = list->next;
  }
}

void
packet_list_free (packet_list_t *list)
{
  packet_list_t *next;
  while (list != NULL) {
    next = list->next;
    free(list);
    list = next;
  }
}

void
packet_list_print (packet_list_t *list)
{
  while (list != NULL) {
    printf("Packet: %p, Size: %lu\n", list->packet, list->size);
    list = list->next;
  }
}

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
  /* assuming peer initiated connection shutdown */
  if (socket->state == CLOSING_BY_PEER) {
    /* server received FIN packet (receive 1st handshake) */
    microtcp_header_t client_fin_packet;
    if (recvfrom(socket->sd, &client_fin_packet, sizeof(client_fin_packet), 0, socket->client_addr, sizeof(struct sockaddr)) == -1) {
      socket->state = INVALID;
      perror("Failed to receive FIN packet");
      return -1;
    } /* FIN packet received */

    /* ensure received packet is FIN */
    if (client_fin_packet.control != MICROTCP_FIN) {
      socket->state = INVALID;
      perror("Received packet is not FIN");
      return -1;
    } /* received packet is FIN */

    /* create and send ACK packet (2nd handshake) */
    microtcp_header_t server_ack_packet;
    server_ack_packet.seq_number =   client_fin_packet.ack_number;
    server_ack_packet.ack_number =   client_fin_packet.seq_number;
    server_ack_packet.control =      MICROTCP_ACK;
    server_ack_packet.window =       socket->curr_win_size;
    server_ack_packet.data_len =     0;
    server_ack_packet.future_use0 =  0;
    server_ack_packet.future_use1 =  0;
    server_ack_packet.future_use2 =  0;
    server_ack_packet.checksum = crc32((uint8_t *)&server_ack_packet, sizeof(server_ack_packet));

    /* first compare checksums */
    if (server_ack_packet.checksum != client_fin_packet.checksum) {
      socket->state = INVALID;
      perror("FIN ACK checksums mismatch");
      return -1;
    } /* checksums match */

    if (sendto(socket->sd, &server_ack_packet, sizeof(server_ack_packet), 0, socket->client_addr, sizeof(struct sockaddr)) == -1) {
      socket->state = INVALID;
      perror("Failed to send ACK packet");
      return -1;
    } /* ACK packet sent */

    /* server executes any remaining operations before shutdown */
    free(socket->recvbuf);

    /* server sends FIN packet (3rd handshake) */
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

    if (sendto(socket->sd, &server_fin_packet, sizeof(server_fin_packet), 0, socket->client_addr, sizeof(struct sockaddr)) == -1) {
      socket->state = INVALID;
      perror("Failed to send FIN packet");
      return -1;
    } /* FIN packet sent */
    
    /* wait for ACK packet (4th handshake) */
    microtcp_header_t client_ack_packet;
    if (recvfrom(socket->sd, &client_ack_packet, sizeof(client_ack_packet), 0, socket->client_addr, sizeof(struct sockaddr)) == -1) {
      socket->state = INVALID;
      perror("Failed to receive ACK packet");
      return -1;
    } /* ACK packet received */

    /* ensure received packet is ACK */
    if (client_ack_packet.control != MICROTCP_ACK) {
      socket->state = INVALID;
      perror("Received packet is not ACK");
      return -1;
    } /* received packet is ACK */

    /* connection is closed */
    socket->state = CLOSED;
    return socket->sd; /* return the socket descriptor */

  } else if (socket->state == CLOSING_BY_HOST) {
    
    /* receive server's ACK packet (receive 2nd handshake) */
    microtcp_header_t server_ack_packet;
    if (recvfrom(socket->sd, &server_ack_packet, sizeof(server_ack_packet), 0, socket->server_addr, sizeof(struct sockaddr)) == -1) {
      socket->state = INVALID;
      perror("Failed to receive ACK packet");
      return -1;
    } /* ACK packet received */

    /* ensure received packet is ACK */
    if (server_ack_packet.control != MICROTCP_ACK) {
      socket->state = INVALID;
      perror("Received packet is not ACK");
      return -1;
    } /* received packet is ACK */

    /* receive server's FIN packet (3rd handshake) */
    microtcp_header_t server_fin_packet;
    if (recvfrom(socket->sd, &server_fin_packet, sizeof(server_fin_packet), 0, socket->server_addr, sizeof(struct sockaddr)) == -1) {
      socket->state = INVALID;
      perror("Failed to receive FIN packet");
      return -1;
    } /* FIN packet received */

    /* ensure received packet is FIN */
    if (server_fin_packet.control != MICROTCP_FIN) {
      socket->state = INVALID;
      perror("Received packet is not FIN");
      return -1;
    } /* received packet is FIN */

    /* create and send ACK packet (4th handshake) */
    microtcp_header_t client_ack_packet;
    client_ack_packet.seq_number =   server_fin_packet.ack_number;
    client_ack_packet.ack_number =   server_fin_packet.seq_number + 1;
    client_ack_packet.control =      MICROTCP_ACK;
    client_ack_packet.window =       socket->curr_win_size;
    client_ack_packet.data_len =     0;
    client_ack_packet.future_use0 =  0;
    client_ack_packet.future_use1 =  0;
    client_ack_packet.future_use2 =  0;
    client_ack_packet.checksum = crc32((uint8_t *)&client_ack_packet, sizeof(client_ack_packet));

    /* first compare checksums */
    if (client_ack_packet.checksum != server_fin_packet.checksum) {
      socket->state = INVALID;
      perror("FIN ACK checksums mismatch");
      return -1;
    } /* checksums match */

    if (sendto(socket->sd, &client_ack_packet, sizeof(client_ack_packet), 0, socket->server_addr, sizeof(struct sockaddr)) == -1) {
      socket->state = INVALID;
      perror("Failed to send ACK packet");
      return -1;
    } /* ACK packet sent */

    /* waiting for server to close connection */

    return socket->sd; /* return the socket descriptor */

  }else {
    /* every other state is not accepted for shutdown */
    socket->state = INVALID;
    perror("Invalid state for shutdown");
    return -1;
  }
}

ssize_t
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length, int flags)
{
  microtcp_header_t sending_packet;  /* packet to be sent     */
  microtcp_header_t receiving_ack;   /* received ACK packet   */
  packet_list_t *packet_list;        /* list of sent packets  */
  packet_list_t *ack_list;           /* list of received ACKs */
  packet_list_t *tmp_packet_list;    /* temporary packet list */
  packet_list_t tmp_packet_list2;`   /* temporary packet list, find acked packets */
  void *packet_buffer; /* buffer to store header and data */
  
  size_t segments;
  size_t segment_size;
  size_t fill_segment_data_size;
  size_t bytes_sent; 
  ssize_t received_ack;
  int i, duplicate_ack_count;

  /* timeout variables */
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;

  if (!buffer) {
    perror("Buffer is NULL");
    return 0; /* nothing to send */
  }

  /* while the bytes sent are lt the length of the buffer */
  bytes_sent = 0;
  while (bytes_sent < length) {
    /* first splitting buffer into segments */
    segment_size = min(socket->curr_win_size, min(socket->cwnd, length - bytes_sent));
    segments = segment_size / (MICROTCP_MSS - sizeof(sending_packet)); 

    /* then send the packets */
    for (i=0; i<segments; i++) {
      packet_buffer = malloc(MICROTCP_MSS);

      /* create the packet */
      sending_packet.seq_number =   socket->ack_number;
      sending_packet.ack_number =   socket->seq_number + MICROTCP_MSS - sizeof(sending_packet); /* data length */
      sending_packet.control =      0;
      sending_packet.window =       socket->curr_win_size;
      sending_packet.data_len =     MICROTCP_MSS - sizeof(sending_packet);
      sending_packet.future_use0 =  0;
      sending_packet.future_use1 =  0;
      sending_packet.future_use2 =  0;
      sending_packet.checksum = crc32((uint8_t *)&sending_packet, sizeof(sending_packet));

      /* copy the header and data to the buffer */
      memcpy(packet_buffer, &sending_packet, sizeof(sending_packet));
      memcpy(packet_buffer + sizeof(sending_packet), buffer + bytes_sent, MICROTCP_MSS - sizeof(sending_packet));

      /* send the segment */
      if (sendto(socket->sd, packet_buffer, MICROTCP_MSS, flags, socket->server_addr, sizeof(struct sockaddr)) == -1) {
        socket->state = INVALID;
        perror("Failed to send packet");
        free(packet_buffer);
        return -1; 
      }
      /* reducing window size */
      socket->curr_win_size = socket->curr_win_size - MICROTCP_MSS;

      packet_list_add(packet_list, &sending_packet, sizeof(sending_packet));
      bytes_sent = bytes_sent + MICROTCP_MSS - sizeof(sending_packet);
      socket->seq_number = sending_packet.seq_number;
      socket->ack_number = sending_packet.ack_number;
      socket->packets_send++;
      socket->bytes_send = socket->bytes_send + MICROTCP_MSS - sizeof(sending_packet);
      free(packet_buffer);
    }
    /* check if there are remaining data for fill segment */
    if (segment_size % (MICROTCP_MSS - sizeof(sending_packet)) > 0) {
      fill_segment_data_size = segment_size % (MICROTCP_MSS - sizeof(sending_packet));
      packet_buffer = malloc(fill_segment_data_size + sizeof(sending_packet));
      segments++;

      /* create the packet */
      sending_packet.seq_number =   socket->ack_number;
      sending_packet.ack_number =   socket->seq_number + fill_segment_data_size; /* data length */
      sending_packet.control =      0;
      sending_packet.window =       socket->curr_win_size;
      sending_packet.data_len =     fill_segment_data_size;
      sending_packet.future_use0 =  0;
      sending_packet.future_use1 =  0;
      sending_packet.future_use2 =  0;
      sending_packet.checksum = crc32((uint8_t *)&sending_packet, sizeof(sending_packet));

      /* copy the header and data to the buffer */
      memcpy(packet_buffer, &sending_packet, sizeof(sending_packet));
      memcpy(packet_buffer + sizeof(sending_packet), buffer + bytes_sent, fill_segment_data_size);

      /* send the segment */
      if (sendto(socket->sd, packet_buffer, fill_segment_data_size + sizeof(sending_packet), flags, socket->server_addr, sizeof(struct sockaddr)) == -1) {
        socket->state = INVALID;
        perror("Failed to send packet");
        free(packet_buffer);
        return -1;
      }
      /* reducing window size */
      socket->curr_win_size = socket->curr_win_size - fill_segment_data_size - sizeof(sending_packet);

      packet_list_add(packet_list, &sending_packet, sizeof(sending_packet));
      bytes_sent = bytes_sent + fill_segment_data_size;
      socket->seq_number = sending_packet.seq_number;
      socket->ack_number = sending_packet.ack_number;
      socket->packets_send++;
      socket->bytes_send = socket->bytes_send + fill_segment_data_size;
      free(packet_buffer); 
    }
    /* wait for ACKs */ 
    for (i=0; i<segments; i++) {
      if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failure");
      }
      received_ack = recvfrom(socket->sd, &receiving_ack, sizeof(receiving_ack), 0, socket->server_addr, sizeof(struct sockaddr));
        

      if (received_ack == -1) { 
        /* timeout */
        socket->ssthresh = socket->cwnd / 2;
        socket->cwnd = MICROTCP_MSS;

        /* timeout occured */
        /* retransmit */
        if (sendto(socket->sd, packet_list->packet, sizeof(packet_list->packet), flags, socket->server_addr, sizeof(struct sockaddr)) == -1) {
          socket->state = INVALID;
          perror("Failed to send packet");
          return -1;
        }
        /* reducing window size */
        socket->curr_win_size = socket->curr_win_size - packet_list->packet->data_len - sizeof(sending_packet);

        //change cwnd and thresh
        socket->ssthresh = socket->cwnd/2;
        socket->cwnd = min(MICROTCP_MSS, socket->ssthresh);

      } /* ACK wasn't received */

      packet_list_add(ack_list, &receiving_ack, sizeof(receiving_ack));
      /* finding the corresponding packet to the ACK */
      tmp_packet_list = packet_list;
      while (tmp_packet_list != NULL) {
        if (tmp_packet_list->packet->ack_number == receiving_ack.seq_number) {
          tmp_packet_list->acked = 1;
          break;
        }
        tmp_packet_list = tmp_packet_list->next;
      }

      /* first compare checksums */
      if (receiving_ack.checksum != tmp_packet_list->packet->checksum) {
        socket->state = INVALID;
        perror("ACK checksums mismatch");
        return -1;
      }
      /* ensure received packet is ACK */
      if (receiving_ack.control != MICROTCP_ACK) {
        socket->state = INVALID;
        perror("Received packet is not ACK");
        return -1;
      } else {
        /* ACK received */
        /* inceasing window size */
        socket->curr_win_size = socket->curr_win_size + tmp_packet_list->packet->data_len + sizeof(sending_packet);
        /* checking for dup ACKs */
        if (receiving_ack.ack_number == socket->ack_number) {
          socket->packets_lost++;
          socket->bytes_lost = socket->bytes_lost + tmp_packet_list->packet->data_len;
          duplicate_ack_count++;  
          if (duplicate_ack_count == 3) {
            /*   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
            /* retransmit lost packet  */ 
            if (sendto(socket->sd, tmp_packet_list->packet, sizeof(tmp_packet_list->packet), flags, socket->server_addr, sizeof(struct sockaddr)) == -1) {
              socket->state = INVALID;
              perror("Failed to send packet");
              return -1;
            }
            /* reducing window size */
            socket->curr_win_size = socket->curr_win_size - tmp_packet_list->packet->data_len - sizeof(sending_packet);
          
            socket->ssthresh = socket->cwnd/2;
            socket->cwnd = socket->cwnd/2 + 1;
          }
        } else {
          /* packets isnt a duplicate so all good */
          duplicate_ack_count = 0;    
        }

      }

    }
    
    packet_list_t retransmit_lost = tmp_packet_list2;
    while (retransmit_lost != NULL) {
      if (retransmit_lost->acked == 0) {
        if (sendto(socket->sd, retransmit_lost->packet, sizeof(retransmit_lost->packet), flags, socket->server_addr, sizeof(struct sockaddr)) == -1) {
          socket->state = INVALID;
          perror("Failed to send packet");
          return -1;
        }
        retransmit_lost = retransmit_lost->next;
      }
    }

    if (socket->cwnd <= socket->ssthresh) {
      /* slow start */
      socket->cwnd = socket->cwnd * 2;
    } else if (socket->cwnd > socket->ssthresh) {
      /* congestion avoidance */
      socket->cwnd = socket->cwnd + MICROTCP_MSS;
    } 

  } 

  return bytes_sent;
}

ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  /* while the bytes received are lt the length of the buffer */
  size_t bytes_recv = 0;

  return bytes_recv;

}