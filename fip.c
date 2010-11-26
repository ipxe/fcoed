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
#include "fcels.h"
#include "fip.h"
#include "fcoed.h"

/**
 * Parse FIP packet into descriptor set
 *
 * @v fiphdr		FIP header
 * @v len		Length of FIP packet
 * @v descs		Descriptor set to fill in
 * @ret rc		Return status code
 */
static int fip_parse ( struct fip_header *fiphdr, size_t len,
		       struct fip_descriptors *descs ) {
	union fip_descriptor *desc;
	size_t descs_len;
	size_t desc_len;
	size_t desc_offset;
	unsigned int desc_type;

	/* Check FIP version */
	if ( fiphdr->version != FIP_VERSION ) {
		logmsg ( LOG_ERR, "received unsupported FIP version %02x\n",
			 fiphdr->version );
		return -1;
	}

	/* Check length */
	descs_len = ( ntohs ( fiphdr->len ) * 4 );
	if ( ( sizeof ( *fiphdr ) + descs_len ) > len ) {
		logmsg ( LOG_ERR, "received bad descriptor list length\n" );
		return -1;
	}

	/* Parse descriptor list */
	memset ( descs, 0, sizeof ( *descs ) );
	for ( desc_offset = 0 ;
	      desc_offset <= ( descs_len - sizeof ( desc->common ) ) ;
	      desc_offset += desc_len ) {

		/* Find descriptor and validate length */
		desc = ( ( ( void * ) ( fiphdr + 1 ) ) + desc_offset );
		desc_type = desc->common.type;
		desc_len = ( desc->common.len * 4 );
		if ( desc_len == 0 ) {
			logmsg ( LOG_ERR, "received zero-length descriptor\n" );
			return -1;
		}
		if ( ( desc_offset + desc_len ) > descs_len ) {
			logmsg ( LOG_ERR, "descriptor overrun\n" );
			return -1;
		}

		/* Handle descriptors that we understand */
		if ( ( desc_type > FIP_RESERVED ) &&
		     ( desc_type < FIP_NUM_DESCRIPTOR_TYPES ) ) {
			descs->desc[desc_type] = desc;
			continue;
		}

		/* Abort if we cannot understand a critical descriptor */
		if ( FIP_IS_CRITICAL ( desc_type ) ) {
			logmsg ( LOG_ERR, "cannot understand critical "
				 "descriptor type %02x\n", desc_type );
			return -1;
		}

		/* Ignore non-critical descriptors that we cannot understand */
	}

	return 0;
}

/**
 * Transmit FIP packet
 *
 * @v intf		Interface
 * @v dst		Destination MAC address
 * @v fiphdr		FIP frame
 * @v len		Length of FIP frame
 * @ret rc		Return status code
 */
static int fip_tx ( struct fcoed_interface *intf, uint8_t *dst,
		    struct fip_header *fiphdr, size_t len ) {
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
int fip_tx_discovery_advertisement ( struct fcoed_interface *intf,
				     uint8_t *dst ) {
	int solicited;
	struct {
		struct fip_header hdr;
		struct fip_priority priority;
		struct fip_mac_address mac_address;
		struct fip_name_id name_id;
		struct fip_fabric fabric;
		struct fip_fka_adv_p fka_adv_p;
	} __attribute__ (( packed )) advert;

	/* Send as solicited if and only if destination is unicast */
	solicited = ( ! ( dst[0] & 0x01 ) );

	/* Build Discovery Advert response */
	memset ( &advert, 0, sizeof ( advert ) );
	advert.hdr.version = FIP_VERSION;
	advert.hdr.code = htons ( FIP_CODE_DISCOVERY );
	advert.hdr.subcode = FIP_DISCOVERY_ADVERTISE;
	advert.hdr.len =
		htons ( ( sizeof ( advert ) - sizeof ( advert.hdr ) ) / 4 );
	advert.hdr.flags = htons ( FIP_F | FIP_A | FIP_FP );
	if ( solicited )
		advert.hdr.flags |= htons ( FIP_S );
	if ( allow_spma )
		advert.hdr.flags |= htons (FIP_SP );
	advert.priority.type = FIP_PRIORITY;
	advert.priority.len = ( sizeof ( advert.priority ) / 4 );
	advert.priority.priority = FIP_DEFAULT_PRIORITY;
	advert.mac_address.type = FIP_MAC_ADDRESS;
	advert.mac_address.len = ( sizeof ( advert.mac_address ) / 4 );
	memcpy ( advert.mac_address.mac, &fc_f_mac,
		 sizeof ( advert.mac_address.mac ) );
	advert.name_id.type = FIP_NAME_ID;
	advert.name_id.len = ( sizeof ( advert.name_id ) / 4 );
	memcpy ( &advert.name_id.name, &fc_f_node_wwn,
		 sizeof ( advert.name_id.name ) );
	advert.fabric.type = FIP_FABRIC;
	advert.fabric.len = ( sizeof ( advert.fabric ) / 4 );
	memcpy ( &advert.fabric.fc_map, &fc_map,
		 sizeof ( advert.fabric.fc_map ) );
	memcpy ( &advert.fabric.name, &fc_f_node_wwn,
		 sizeof ( advert.fabric.name ) );
	advert.fka_adv_p.type = FIP_FKA_ADV_P;
	advert.fka_adv_p.len = ( sizeof ( advert.fka_adv_p ) / 4 );
	advert.fka_adv_p.period = htonl ( FKA_ADV_PERIOD );

	return fip_tx ( intf, dst, &advert.hdr, sizeof ( advert ) );
}

/**
 * Receive FIP discovery solicitation
 *
 * @v intf		Interface
 * @v src		Source address
 * @v descs		Descriptor list
 * @v flags		Flags
 * @ret rc		Return status code
 */
static int fip_rx_discovery_solicitation ( struct fcoed_interface *intf,
					   uint8_t *src __unused,
					   struct fip_descriptors *descs,
					   unsigned int flags __unused ) {
	struct fip_mac_address *mac_address = fip_mac_address ( descs );
	struct fip_name_id *name_id = fip_name_id ( descs );
	struct fip_max_fcoe_size *max_fcoe_size = fip_max_fcoe_size ( descs );

	/* Sanity check */
	if ( ! mac_address ) {
		logmsg ( LOG_ERR, "received FIP discovery solicititation "
			 "missing MAC address\n" );
		return -1;
	}
	if ( ! name_id ) {
		logmsg ( LOG_ERR, "received FIP discovery solicititation "
			 "missing name identifier\n" );
		return -1;
	}
	if ( ! max_fcoe_size ) {
		logmsg ( LOG_ERR, "received FIP discovery solicititation "
			 "missing maximum FCoE size\n" );
		return -1;
	}

	logmsg ( LOG_INFO, "received FIP discovery from MAC " MAC_FMT " name "
		 FC_NAME_FMT "\n", MAC_ARGS ( mac_address->mac ),
		 FC_NAME_ARGS ( &name_id->name ) );

	return fip_tx_discovery_advertisement ( intf, mac_address->mac );
}

/**
 * Construct FC response frame header
 *
 * @v port		Port
 * @v request		Request frame header
 * @v repsonse		Response frame header
 */
static void fip_fc_respond ( struct fcoed_port *port,
			     const struct fc_frame_header *request,
			     struct fc_frame_header *response ) {
	static uint16_t rx_id;

	/* Construct FC frame header */
	response->r_ctl = ( FC_R_CTL_ELS | FC_R_CTL_SOL_CTRL );
	memcpy ( &response->d_id, &port->port_id,
		 sizeof ( response->d_id ) );
	memcpy ( &response->s_id, &fc_f_port_id,
		 sizeof ( response->s_id ) );
	response->type = FC_TYPE_ELS;
	response->f_ctl_es = ( FC_F_CTL_ES_RESPONDER | FC_F_CTL_ES_END |
			       FC_F_CTL_ES_LAST );
	response->ox_id = request->ox_id;
	response->rx_id = htons ( ++rx_id );
}

/**
 * Receive FIP FLOGI request frame
 *
 * @v intf		Interface
 * @v src		Source address
 * @v descs		Descriptor list
 * @v flags		Flags
 * @ret rc		Return status code
 */
static int fip_rx_flogi_request ( struct fcoed_interface *intf,
				  uint8_t *src,
				  struct fip_descriptors *descs,
				  unsigned int flags ) {
	struct fip_login *flogi = fip_flogi_request ( descs );
	struct fip_mac_address *mac_address = fip_mac_address ( descs );
	struct fcoed_port *port;
	uint8_t *mac;
	struct {
		struct fip_header hdr;
		struct fip_login ls_acc;
		struct fip_mac_address mac_address;
	} __attribute__ (( packed )) response;

	/* Sanity check */
	if ( ( flogi->len * 4 ) < sizeof ( *flogi ) ) {
		logmsg ( LOG_ERR, "received underlength FLOGI\n" );
		return -1;
	}

	/* Derive MAC address */
	if ( flags & FIP_FP ) {
		mac = NULL;
	} else if ( flags & FIP_SP ) {
		mac = mac_address->mac;
	} else {
		logmsg ( LOG_ERR, "received request for neither SPMA nor "
			 "FPMA\n" );
		return -1;
	}

	/* Add port */
	if ( add_port ( intf, src, mac, &port ) < 0 )
		return -1;

	/* Construct response */
	memset ( &response, 0, sizeof ( response ) );
	response.hdr.version = FIP_VERSION;
	response.hdr.code = htons ( FIP_CODE_ELS );
	response.hdr.subcode = FIP_ELS_RESPONSE;
	response.hdr.len =
		htons ( ( sizeof ( response ) - sizeof ( response.hdr ) ) / 4 );
	response.ls_acc.type = FIP_FLOGI;
	response.ls_acc.len = ( sizeof ( response.ls_acc ) / 4 );
	fip_fc_respond ( port, &flogi->fc, &response.ls_acc.fc );
	response.ls_acc.els.command = FC_ELS_LS_ACC;
	response.ls_acc.els.common.version = htons ( FC_LOGIN_VERSION );
	response.ls_acc.els.common.credit = htons ( FC_LOGIN_DEFAULT_B2B );
	response.ls_acc.els.common.flags =
		htons ( FC_LOGIN_CONTINUOUS_OFFSET | FC_LOGIN_F_PORT );
	response.ls_acc.els.common.mtu = htons ( FC_LOGIN_DEFAULT_MTU );
	memcpy ( &response.ls_acc.els.port_wwn, &fc_f_port_wwn,
		 sizeof ( response.ls_acc.els.port_wwn ) );
	memcpy ( &response.ls_acc.els.node_wwn, &fc_f_node_wwn,
		 sizeof ( response.ls_acc.els.node_wwn ) );
	response.ls_acc.els.class3.flags = htons ( FC_LOGIN_CLASS_VALID |
						   FC_LOGIN_CLASS_SEQUENTIAL );
	response.mac_address.type = FIP_MAC_ADDRESS;
	response.mac_address.len = ( sizeof ( response.mac_address ) / 4 );
	memcpy ( response.mac_address.mac, port->mac,
		 sizeof ( response.mac_address.mac ) );
	
	return fip_tx ( intf, src, &response.hdr, sizeof ( response ) );
}

/**
 * Receive FIP NPIV FDISC request frame
 *
 * @v intf		Interface
 * @v src		Source address
 * @v descs		Descriptor list
 * @v flags		Flags
 * @ret rc		Return status code
 */
static int fip_rx_npiv_fdisc_request ( struct fcoed_interface *intf,
				       uint8_t *src,
				       struct fip_descriptors *descs,
				       unsigned int flags ) {
	struct fip_login *npiv_fdisc = fip_npiv_fdisc_request ( descs );
	struct fip_mac_address *mac_address = fip_mac_address ( descs );

	logmsg ( LOG_ERR, "received unsupported NPIV FDISC from " MAC_FMT "\n",
		 MAC_ARGS ( mac_address->mac ) );
	( void ) intf;
	( void ) src;
	( void ) npiv_fdisc;
	( void ) flags;
	return -1;
}

/**
 * Receive FIP LOGO request frame
 *
 * @v intf		Interface
 * @v src		Source address
 * @v descs		Descriptor list
 * @v flags		Flags
 * @ret rc		Return status code
 */
static int fip_rx_logo_request ( struct fcoed_interface *intf,
				 uint8_t *src,
				 struct fip_descriptors *descs,
				 unsigned int flags ) {
	struct fip_logo_request *logo = fip_logo_request ( descs );
	struct fip_mac_address *mac_address = fip_mac_address ( descs );

	logmsg ( LOG_ERR, "received unsupported LOGO from " MAC_FMT "\n",
		 MAC_ARGS ( mac_address->mac ) );
	( void ) intf;
	( void ) src;
	( void ) logo;
	( void ) flags;
	return -1;
}

/**
 * Receive FIP ELP request frame
 *
 * @v intf		Interface
 * @v src		Source address
 * @v descs		Descriptor list
 * @v flags		Flags
 * @ret rc		Return status code
 */
static int fip_rx_elp_request ( struct fcoed_interface *intf,
				uint8_t *src,
				struct fip_descriptors *descs,
				unsigned int flags ) {
	struct fip_elp *elp = fip_elp_request ( descs );
	struct fip_mac_address *mac_address = fip_mac_address ( descs );

	logmsg ( LOG_ERR, "received unsupported ELP from " MAC_FMT "\n",
		 MAC_ARGS ( mac_address->mac ) );
	( void ) intf;
	( void ) src;
	( void ) elp;
	( void ) flags;
	return -1;
}

/**
 * Receive FIP ELS request frame
 *
 * @v intf		Interface
 * @v src		Source address
 * @v descs		Descriptor list
 * @v flags		Flags
 * @ret rc		Return status code
 */
static int fip_rx_els_request ( struct fcoed_interface *intf,
				uint8_t *src,
				struct fip_descriptors *descs,
				unsigned int flags ) {
	struct fip_mac_address *mac_address = fip_mac_address ( descs );

	/* Sanity check */
	if ( ! mac_address ) {
		logmsg ( LOG_ERR, "received ELS missing MAC address\n" );
		return -1;
	}

	/* Hand off to appropriate ELS handler */
	if ( fip_flogi_request ( descs ) ) {
		return fip_rx_flogi_request ( intf, src, descs, flags );
	} else if ( fip_npiv_fdisc_request ( descs ) ) {
		return fip_rx_npiv_fdisc_request ( intf, src, descs, flags );
	} else if ( fip_logo_request ( descs ) ) {
		return fip_rx_logo_request ( intf, src, descs, flags );
	} else if ( fip_elp_request ( descs ) ) {
		return fip_rx_elp_request ( intf, src, descs, flags );
	} else {
		logmsg ( LOG_ERR, "received ELS missing FC frame\n" );
		return -1;
	}
}

/**
 * Receive FIP keepalive frame
 *
 * @v intf		Interface
 * @v src		Source address
 * @v descs		Descriptor list
 * @v flags		Flags
 * @ret rc		Return status code
 */
static int fip_rx_keep_alive ( struct fcoed_interface *intf,
			       uint8_t *src,
			       struct fip_descriptors *descs,
			       unsigned int flags ) {
	/* Do nothing */
	( void ) intf;
	( void ) src;
	( void ) descs;
	( void ) flags;
	return 0;
}

/**
 * Receive FIP VLAN request
 *
 * @v intf		Interface
 * @v src		Source address
 * @v descs		Descriptor list
 * @v flags		Flags
 * @ret rc		Return status code
 */
static int fip_rx_vlan_request ( struct fcoed_interface *intf,
				 uint8_t *src,
				 struct fip_descriptors *descs,
				 unsigned int flags __unused ) {
	struct fip_mac_address *mac_address = fip_mac_address ( descs );
	struct {
		struct fip_header hdr;
		struct fip_mac_address mac_address;
		struct fip_vlan vlan;
	} __attribute__ (( packed )) response;

	/* Sanity check */
	if ( ! mac_address ) {
		logmsg ( LOG_ERR, "received FIP VLAN request missing MAC "
			 "address\n" );
		return -1;
	}

	logmsg ( LOG_INFO, "received FIP VLAN request from MAC " MAC_FMT "\n",
		 MAC_ARGS ( mac_address->mac ) );

	/* Ignore request unless we are supporting VLAN discovery */
	if ( ! fc_vlan )
		return 0;

	/* Construct response */
	memset ( &response, 0, sizeof ( response ) );
	response.hdr.version = FIP_VERSION;
	response.hdr.code = htons ( FIP_CODE_VLAN );
	response.hdr.subcode = FIP_VLAN_NOTIFY;
	response.hdr.len =
		htons ( ( sizeof ( response ) - sizeof ( response.hdr ) ) / 4 );
	response.mac_address.type = FIP_MAC_ADDRESS;
	response.mac_address.len = ( sizeof ( response.mac_address ) / 4 );
	memcpy ( response.mac_address.mac, &fc_f_mac,
		 sizeof ( response.mac_address.mac ) );
	response.vlan.type = FIP_VLAN;
	response.vlan.len = ( sizeof ( response.vlan ) / 4 );
	response.vlan.vlan = htons ( fc_vlan );

	return fip_tx ( intf, src, &response.hdr, sizeof ( response ) );
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
	 * @v src		Source address
	 * @v descs		Descriptor list
	 * @v flags		Flags
	 * @ret rc		Return status code
	 */
	int ( * rx ) ( struct fcoed_interface *intf, uint8_t *src,
		       struct fip_descriptors *descs, unsigned int flags );
};

/** FIP handlers */
static struct fip_handler fip_handlers[] = {
	{ FIP_CODE_DISCOVERY, FIP_DISCOVERY_SOLICIT,
	  fip_rx_discovery_solicitation },
	{ FIP_CODE_ELS, FIP_ELS_REQUEST,
	  fip_rx_els_request },
	{ FIP_CODE_MAINTAIN, FIP_MAINTAIN_KEEP_ALIVE,
	  fip_rx_keep_alive },
	{ FIP_CODE_VLAN, FIP_VLAN_REQUEST,
	  fip_rx_vlan_request },
};

/**
 * Receive FIP packet
 *
 * @v intf		Interface
 * @v src		Source address
 * @v data		FIP payload
 * @v len		Length of data
 * @ret rc		Return status code
 */
int fip_rx ( struct fcoed_interface *intf, uint8_t *src,
	     void *data, size_t len ) {
	struct fip_header *fiphdr = data;
	struct fip_descriptors descs;
	struct fip_handler *handler;
	unsigned int i;

	/* Parse FIP packet */
	if ( fip_parse ( fiphdr, len, &descs ) < 0 )
		return -1;

	/* Find a suitable handler */
	for ( i = 0 ; i < ( sizeof ( fip_handlers ) /
			    sizeof ( fip_handlers[0] ) ) ; i++ ) {
		handler = &fip_handlers[i];
		if ( ( handler->code == ntohs ( fiphdr->code ) ) &&
		     ( handler->subcode == fiphdr->subcode ) ) {
			return handler->rx ( intf, src, &descs,
					     ntohs ( fiphdr->flags ) );
		}
	}

	logmsg ( LOG_ERR, "received unsupported FIP code %04x.%02x\n",
		 ntohs ( fiphdr->code ), fiphdr->subcode );
	return -1;
}
