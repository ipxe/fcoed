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
#include <arpa/inet.h>
#include <pcap.h>
#include <syslog.h>
#include "list.h"
#include "fc.h"
#include "fcoe.h"
#include "fcoed.h"

/**
 * Forward FCoE packet
 *
 * @v intf		Interface
 * @v port		Port
 * @v fcoehdr		FCoE frame
 * @v len		Length of FCoE frame
 * @ret rc		Return status code
 */
static int fcoe_tx ( struct fcoed_interface *intf, struct fcoed_port *port,
		     struct fcoe_header *fcoehdr, size_t len ) {
	struct {
		struct ethhdr ethhdr;
		char fcoe[len];
	} __attribute__ (( packed )) data;
	size_t sent_len;

	/* Build complete data */
	memcpy ( data.ethhdr.h_dest, port->mac,
		 sizeof ( data.ethhdr.h_dest ) );
	memcpy ( data.ethhdr.h_source, fc_f_mac,
		 sizeof ( data.ethhdr.h_source ) );
	data.ethhdr.h_proto = htons ( ETH_P_FCOE );
	memcpy ( data.fcoe, fcoehdr, sizeof ( data.fcoe ) );

	/* Send packet */
	sent_len = pcap_inject ( intf->pcap, &data, sizeof ( data ) );
	if ( sent_len != sizeof ( data ) ) {
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
 * @v src		Source address
 * @v data		Data
 * @v len		Length of data
 * @ret rc		Return status code
 */
int fcoe_rx ( struct fcoed_interface *intf, uint8_t *src __unused,
	      void *data, size_t len ) {
	struct {
		struct fcoe_header fcoehdr;
		struct fc_frame_header fchdr;
	} __attribute__ (( packed )) *frame = data;
	struct fc_port_id *dest_id;
	struct fcoed_interface *dest_intf;
	struct fcoed_port *dest_port;

	/* Locate FCoE header */
	if ( len < sizeof ( *frame ) ) {
		logmsg ( LOG_ERR, "received truncated FCoE frame\n" );
		return -1;
	}

	/* Identify destination interface and port */
	dest_id = &frame->fchdr.d_id;
	if ( find_port_by_id ( dest_id, &dest_intf, &dest_port ) < 0 ) {
		logmsg ( LOG_WARNING, "received FCoE on %s for unknown ID "
			 FC_PORT_ID_FMT "\n", intf->name,
			 FC_PORT_ID_ARGS ( dest_id ) );
		return -1;
	}

	/* Forward to destination port */
	return fcoe_tx ( dest_intf, dest_port, &frame->fcoehdr, len );
}
