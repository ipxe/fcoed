/*
 * Copyright (C) 2010 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <string.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <syslog.h>
#include "list.h"
#include "fcoe.h"
#include "fcoed.h"

/**
 * Forward FCoE packet
 *
 * @v intf		Interface
 * @v port		Port
 * @v data		Data
 * @v len		Length of data
 * @ret rc		Return status code
 */
static int forward_fcoe ( struct fcoed_interface *intf, struct fcoed_port *port,
			  void *data, size_t len ) {
	struct ethhdr *ethhdr = data;
	size_t sent_len;

	/* Rewrite MAC addresses */
	memcpy ( ethhdr->h_dest, port->mac, sizeof ( ethhdr->h_dest ) );
	memcpy ( ethhdr->h_source, fc_f_mac, sizeof ( ethhdr->h_source ) );

	/* Send packet */
	sent_len = pcap_inject ( intf->pcap, data, len );
	if ( sent_len != len ) {
		logmsg ( LOG_ERR, "could not forward to %s: %s\n",
			 intf->name, pcap_geterr ( intf->pcap ) );
		return -1;
	}

	return 0;
}

/**
 * Receive FCoE packet
 *
 * @v intf		Interface
 * @v data		Data
 * @v len		Length of data
 * @ret rc		Return status code
 */
int receive_fcoe ( struct fcoed_interface *intf, void *data, size_t len ) {
	struct ethhdr *ethhdr = data;
	struct fcoe_header *fcoehdr;
	struct fc_frame_header *fchdr;
	struct fc_port_id *dest_id;
	struct fcoed_interface *dest_intf;
	struct fcoed_port *dest_port;

	/* Locate FCoE header */
	fcoehdr = ( ( void * ) ( ethhdr + 1 ) );
	if ( ( data + len ) < ( ( void * ) ( fcoehdr + 1 ) ) ) {
		logmsg ( LOG_ERR, "received truncated FCoE header\n" );
		return -1;
	}

	/* Locate FC header */
	fchdr = ( ( void * ) ( fcoehdr + 1 ) );
	if ( ( data + len ) < ( ( void * ) ( fchdr + 1 ) ) ) {
		logmsg ( LOG_ERR, "received truncated FC header\n" );
		return -1;
	}
	dest_id = &fchdr->d_id;

	/* Identify destination interface and port */
	list_for_each_entry ( dest_intf, &interfaces, list ) {
		list_for_each_entry ( dest_port, &intf->ports, list ) {
			if ( memcmp ( &dest_port->port_id, dest_id,
				      sizeof ( dest_port->port_id ) ) != 0 ) {
				return forward_fcoe ( dest_intf, dest_port,
						      data, len );
			}
		}
	}

	logmsg ( LOG_WARNING, "received FCoE on %s for unknown ID "
		 FC_PORT_ID_FMT "\n", intf->name, FC_PORT_ID_ARGS ( dest_id ) );
	return 0;
}
