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
#include "fip.h"
#include "fcoe.h"
#include "fcoed.h"

/**
 * Find FIP descriptor
 *
 * @v fiphdr		FIP header
 * @v type		Descriptor type
 * @ret desc		Descriptor, or NULL
 */
static union fip_descriptor * fip_find_descriptor ( struct fip_header *fiphdr,
						    unsigned int type ) {
	void *descs = ( fiphdr + 1 );
	union fip_descriptor *desc;
	size_t offset = 0;
	size_t len;

	while ( 1 ) {
		desc = ( descs + offset );
		len = ( desc->common.len * 4 );
		if ( len == 0 )
			return NULL;
		offset += len;
		if ( offset > ( ntohs ( fiphdr->len ) * 4 ) )
			return NULL;
		if ( desc->common.type == type )
			return desc;
	}
}

/**
 * Define a function to find a specific FIP descriptor type
 *
 * @v type		Descriptor type
 * @v name		Descriptor name
 * @v finder		Descriptor finder
 */
#define FIP_FIND_DESCRIPTOR( type, name )				\
	static inline __attribute__ (( always_inline ))			\
	typeof ( ( ( union fip_descriptor * ) NULL )->name ) *		\
	fip_find_ ## name ( struct fip_header *fiphdr ) {		\
		return &( fip_find_descriptor ( fiphdr, type ) )->name;	\
	}
FIP_FIND_DESCRIPTOR ( FIP_PRIORITY, priority );
FIP_FIND_DESCRIPTOR ( FIP_MAC_ADDRESS, mac_address );
FIP_FIND_DESCRIPTOR ( FIP_FC_MAP, fc_map );
FIP_FIND_DESCRIPTOR ( FIP_NAME_ID, name_id );
FIP_FIND_DESCRIPTOR ( FIP_FABRIC, fabric );
FIP_FIND_DESCRIPTOR ( FIP_MAX_FCOE_SIZE, max_fcoe_size );
FIP_FIND_DESCRIPTOR ( FIP_FLOGI, flogi );
FIP_FIND_DESCRIPTOR ( FIP_NPIV_FDISC, npiv_fdisc );
FIP_FIND_DESCRIPTOR ( FIP_LOGO, logo );
FIP_FIND_DESCRIPTOR ( FIP_ELP, elp );
FIP_FIND_DESCRIPTOR ( FIP_VX_PORT_ID, vx_port_id );
FIP_FIND_DESCRIPTOR ( FIP_FKA_ADV_P, fka_adv_p );
FIP_FIND_DESCRIPTOR ( FIP_VENDOR_ID, vendor_id );
FIP_FIND_DESCRIPTOR ( FIP_VLAN, vlan );

/**
 * Transmit FIP packet
 *
 * @v intf		Interface
 * @v fiphdr		FIP frame
 * @v len		Length of FIP frame
 * @v dst		Destination MAC address
 * @ret rc		Return status code
 */
static int fip_transmit ( struct fcoed_interface *intf,
			  struct fip_header *fiphdr, size_t len,
			  uint8_t dst[ETH_ALEN] ) {
	struct {
		struct ethhdr ethhdr;
		char fip[len];
	} __attribute__ (( packed )) data;
	size_t sent_len;

	/* Build complete data */
	memcpy ( data.ethhdr.h_dest, dst, sizeof ( data.ethhdr.h_dest ) );
	memcpy ( data.ethhdr.h_source, &fc_f_mac,
		 sizeof ( data.ethhdr.h_source ) );
	data.ethhdr.h_proto = htons ( ETH_P_FIP );
	memcpy ( data.fip, fiphdr, sizeof ( data.fip ) );

	/* Send packet */
	sent_len = pcap_inject ( intf->pcap, &data, sizeof ( data ) );
	if ( sent_len != sizeof ( data ) ) {
		logmsg ( LOG_ERR, "could not send FIP response to %s: %s\n",
			 intf->name, pcap_geterr ( intf->pcap ) );
		return -1;
	}

	return 0;
}

/**
 * Send FIP discovery advertisement
 *
 * @v intf		Interface
 * @v dst		Destination MAC address
 * @ret rc		Return status code
 */
int fip_send_discovery_advertisement ( struct fcoed_interface *intf,
				       uint8_t dst[ETH_ALEN] ) {
	union fcoe_name fc_f_name;
	int solicited;
	struct {
		struct fip_header hdr;
		struct fip_descriptor_priority priority;
		struct fip_descriptor_mac_address mac_address;
		struct fip_descriptor_name_id name_id;
		struct fip_descriptor_fabric fabric;
		struct fip_descriptor_fka_adv_p fka_adv_p;
	} __attribute__ (( packed )) advert;

	/* Construct our name */
	fc_f_name.fcoe.authority = htons ( FCOE_AUTHORITY_IEEE );
	memcpy ( fc_f_name.fcoe.mac, &fc_f_mac,
		 sizeof ( fc_f_name.fcoe.mac ) );

	/* Send as solicited if and only if destination is unicast */
	solicited = ( ! ( dst[0] & 0x01 ) );

	/* Build Discovery Advert response */
	memset ( &advert, 0, sizeof ( advert ) );
	advert.hdr.version = FIP_VERSION;
	advert.hdr.code = htons ( FIP_CODE_DISCOVERY );
	advert.hdr.subcode = FIP_DISCOVERY_ADVERTISEMENT;
	advert.hdr.len =
		htons ( ( sizeof ( advert ) - sizeof ( advert.hdr ) ) / 4 );
	advert.hdr.flags = htons ( FIP_F | FIP_A | FIP_FP );
	if ( solicited )
		advert.hdr.flags |= htons ( FIP_S );
	advert.priority.type = FIP_PRIORITY;
	advert.priority.len = ( sizeof ( advert.priority ) / 4 );
	advert.priority.priority = FIP_DEFAULT_PRIORITY;
	advert.mac_address.type = FIP_MAC_ADDRESS;
	advert.mac_address.len = ( sizeof ( advert.mac_address ) / 4 );
	memcpy ( advert.mac_address.mac, &fc_f_mac,
		 sizeof ( advert.mac_address.mac ) );
	advert.name_id.type = FIP_NAME_ID;
	advert.name_id.len = ( sizeof ( advert.name_id ) / 4 );
	memcpy ( &advert.name_id.name, &fc_f_name,
		 sizeof ( advert.name_id.name ) );
	advert.fabric.type = FIP_FABRIC;
	advert.fabric.len = ( sizeof ( advert.fabric ) / 4 );
	memcpy ( &advert.fabric.fc_map, &fc_map,
		 sizeof ( advert.fabric.fc_map ) );
	memcpy ( &advert.fabric.name, &fc_f_name,
		 sizeof ( advert.fabric.name ) );
	advert.fka_adv_p.type = FIP_FKA_ADV_P;
	advert.fka_adv_p.len = ( sizeof ( advert.fka_adv_p ) / 4 );
	advert.fka_adv_p.period = htonl ( FKA_ADV_PERIOD );

	return fip_transmit ( intf, &advert.hdr, sizeof ( advert ), dst );
}

/**
 * Receive FIP discovery solicitation
 *
 * @v intf		Interface
 * @v fiphdr		FIP header
 * @ret rc		Return status code
 */
static int fip_receive_discovery_solicitation ( struct fcoed_interface *intf,
						struct fip_header *fiphdr ) {
	struct fip_descriptor_mac_address *mac_address;
	struct fip_descriptor_name_id *name_id;
	struct fip_descriptor_max_fcoe_size *max_fcoe_size;

	/* Find descriptors */
	mac_address = fip_find_mac_address ( fiphdr );
	if ( ! mac_address ) {
		logmsg ( LOG_ERR, "received FIP discovery solicititation "
			 "missing MAC address\n" );
		return -1;
	}
	name_id = fip_find_name_id ( fiphdr );
	if ( ! name_id ) {
		logmsg ( LOG_ERR, "received FIP discovery solicititation "
			 "missing name identifier\n" );
		return -1;
	}
	max_fcoe_size = fip_find_max_fcoe_size ( fiphdr );
	if ( ! max_fcoe_size ) {
		logmsg ( LOG_ERR, "received FIP discovery solicititation "
			 "missing maximum FCoE size\n" );
		return -1;
	}

	logmsg ( LOG_INFO, "received FIP discovery from MAC " MAC_FMT " name "
		 FC_NAME_FMT "\n", MAC_ARGS ( mac_address->mac ),
		 FC_NAME_ARGS ( &name_id->name ) );

	return fip_send_discovery_advertisement ( intf, mac_address->mac );
}
 
/** A FIP handler */
struct fip_handler {
	/** Protocol code */
	uint16_t code;
	/** Protocol subcode */
	uint8_t subcode;
	/**
	 * Receive FIP packet
	 *
	 * @v intf		Interface
	 * @v fiphdr		FIP header
	 * @ret rc		Return status code
	 */
	int ( * receive ) ( struct fcoed_interface *intf,
			    struct fip_header *fiphdr );
};

/** FIP handlers */
static struct fip_handler fip_handlers[] = {
	{ FIP_CODE_DISCOVERY, FIP_DISCOVERY_SOLICITATION,
	  fip_receive_discovery_solicitation },
};

/**
 * Receive FIP packet
 *
 * @v intf		Interface
 * @v data		Data
 * @v len		Length of data
 * @ret rc		Return status code
 */
int receive_fip ( struct fcoed_interface *intf, void *data, size_t len ) {
	struct ethhdr *ethhdr = data;
	struct fip_header *fiphdr;
	struct fip_handler *handler;
	unsigned int i;

	/* Locate FIP header */
	fiphdr = ( ( void * ) ( ethhdr + 1 ) );
	if ( ( data + len ) < ( ( void * ) ( fiphdr + 1 ) ) ) {
		logmsg ( LOG_ERR, "received truncated FIP header\n" );
		return -1;
	}

	/* Check FIP version */
	if ( fiphdr->version != FIP_VERSION ) {
		logmsg ( LOG_ERR, "received unsupported FIP version %02x\n",
			 fiphdr->version );
		return -1;
	}

	/* Check length */
	if ( len < ( sizeof ( *fiphdr ) + ( ntohs ( fiphdr->len ) * 4 ) ) ) {
		logmsg ( LOG_ERR, "received bad descriptor list length\n" );
		return -1;
	}

	/* Find a suitable handler */
	for ( i = 0 ; i < ( sizeof ( fip_handlers ) /
			    sizeof ( fip_handlers[0] ) ) ; i++ ) {
		handler = &fip_handlers[i];
		if ( ( handler->code == ntohs ( fiphdr->code ) ) &&
		     ( handler->subcode == fiphdr->subcode ) ) {
			return handler->receive ( intf, fiphdr );
		}
	}

	logmsg ( LOG_ERR, "received unsupported FIP code %04x.%02x\n",
		 ntohs ( fiphdr->code ), fiphdr->subcode );
	return -1;
}
