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
#include <endian.h>
#include "list.h"
#include "fc.h"
#include "fcoe.h"
#include "fcds.h"
#include "fcoed.h"

#define CRCPOLY		0xedb88320

/**
 * Calculate 32-bit little-endian CRC checksum
 *
 * @v seed	Initial value
 * @v data	Data to checksum
 * @v len	Length of data
 *
 * Usually @a seed is initially zero or all one bits, depending on the
 * protocol. To continue a CRC checksum over multiple calls, pass the
 * return value from one call as the @a seed parameter to the next.
 */
static uint32_t crc32_le ( uint32_t seed, const void *data, size_t len ) {
	uint32_t crc = seed;
	const uint8_t *src = data;
	uint32_t mult;
	int i;

	while ( len-- ) {
		crc ^= *src++;
		for ( i = 0; i < 8; i++ ) {
			mult = ( crc & 1 ) ? CRCPOLY : 0;
			crc = ( crc >> 1 ) ^ mult;
		}
	}

	return crc;
}

/**
 * Transmit FCoE frame
 *
 * @v fchdr		Fibre Channel frame
 * @v len		Length of Fibre Channel frame
 * @ret rc		Return status code
 */
int fc_tx ( struct fc_frame_header *fchdr, size_t len ) {
	struct fc_port_id *dest_id = &fchdr->d_id;
	struct fcoed_interface *dest_intf;
	struct fcoed_port *dest_port;
	struct {
		struct ethhdr ethhdr;
		struct fcoe_header fcoehdr;
		char fc[len];
		struct fcoe_footer fcoeftr;
	} __attribute__ (( packed )) data;
	uint32_t crc;
	size_t sent_len;

	/* Identify destination interface and port */
	if ( find_port_by_id ( dest_id, &dest_intf, &dest_port ) < 0 ) {
		logmsg ( LOG_WARNING, "cannot transmit to unknown ID "
			 FC_PORT_ID_FMT "\n", FC_PORT_ID_ARGS ( dest_id ) );
		return -1;
	}

	/* Calculate CRC */
	crc = crc32_le ( ~((uint32_t)0), fchdr, len );

	/* Build complete data */
	memcpy ( data.ethhdr.h_dest, dest_port->mac,
		 sizeof ( data.ethhdr.h_dest ) );
	memcpy ( data.ethhdr.h_source, fc_f_mac,
		 sizeof ( data.ethhdr.h_source ) );
	data.ethhdr.h_proto = htons ( ETH_P_FCOE );
	memset ( &data.fcoehdr, 0, sizeof ( data.fcoehdr ) );
	data.fcoehdr.sof = ( ( fchdr->seq_cnt == ntohs ( 0 ) ) ?
			     FCOE_SOF_I3 : FCOE_SOF_N3 );
	memcpy ( data.fc, fchdr, sizeof ( data.fc ) );
	memset ( &data.fcoeftr, 0, sizeof ( data.fcoeftr ) );
	data.fcoeftr.crc = htole32 ( crc ^ ~((uint32_t)0) );
	data.fcoeftr.eof = ( ( fchdr->f_ctl_es & FC_F_CTL_ES_END ) ?
			     FCOE_EOF_T : FCOE_EOF_N );

	/* Send packet */
	sent_len = pcap_inject ( dest_intf->pcap, &data, sizeof ( data ) );
	if ( sent_len != sizeof ( data ) ) {
		logmsg ( LOG_ERR, "could not forward to %s: %s\n",
			 dest_intf->name, pcap_geterr ( dest_intf->pcap ) );
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
int fcoe_rx ( struct fcoed_interface *intf __unused, uint8_t *src __unused,
	      void *data, size_t len ) {
	struct fcoe_header *fcoehdr;
	struct fcoe_footer *fcoeftr;
	struct fc_frame_header *fchdr;
	struct fc_port_id *dest_id;

	/* Strip FCoE header and footer */
	if ( len < sizeof ( *fcoehdr ) ) {
		logmsg ( LOG_ERR, "received truncated FCoE frame\n" );
		return -1;
	}
	fcoehdr = data;
	data += sizeof ( *fcoehdr );
	len -= sizeof ( *fcoehdr );
	if ( len < sizeof ( *fcoeftr ) ) {
		logmsg ( LOG_ERR, "received truncated FCoE frame\n" );
		return -1;
	}
	len -= sizeof ( *fcoeftr );
	fcoeftr = ( data + len );
	if ( len < sizeof ( *fchdr ) ) {
		logmsg ( LOG_ERR, "received truncated FCoE frame\n" );
		return -1;
	}
	fchdr = data;
	dest_id = &fchdr->d_id;

	/* Intercept traffic for special port IDs */
	if ( memcmp ( dest_id, &fc_gs_port_id, sizeof ( *dest_id ) ) == 0 )
		return fc_gs_rx ( fchdr, len );
	if ( memcmp ( dest_id, &fc_ls_port_id, sizeof ( *dest_id ) ) == 0 )
		return fc_ls_rx ( fchdr, len );

	/* Forward FC frame */
	return fc_tx ( fchdr, len );
}
