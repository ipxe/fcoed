#ifndef _FCOE_H
#define _FCOE_H

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

#include <stdint.h>
#include <net/if.h>
#include <netinet/if_ether.h>

/** An FCoE MAC address prefix (FC-MAP) */
struct fc_map {
	uint8_t bytes[3];
} __attribute__ (( packed ));

/** A Fibre Channel name */
struct fc_name {
	uint8_t bytes[8];
} __attribute__ (( packed ));

/** An FCoE name */
union fcoe_name {
	/** Fibre Channel name */
	struct fc_name fc;
	/** FCoE name */
	struct {
		/** Naming authority */
		uint16_t authority;
		/** MAC address */
		uint8_t mac[ETH_ALEN];
	} __attribute__ (( packed )) fcoe;
};

/** IEEE 48-bit address */
#define FCOE_AUTHORITY_IEEE 0x1000

/** IEEE extended */
#define FCOE_AUTHORITY_IEEE_EXTENDED 0x2000

/** A Fibre Channel port identifier */
struct fc_port_id {
	uint8_t bytes[3];
} __attribute__ (( packed ));

/** An FCoE (fabric-assigned) MAC address */
struct fcoe_mac {
	/** MAC address prefix */
	struct fc_map fc_map;
	/** Port ID */
	struct fc_port_id id;
} __attribute__ (( packed ));

/** An FCoE frame header */
struct fcoe_header {
	/** FCoE frame version */
	uint8_t version;
	/** Reserved */
	uint8_t reserved[12];
	/** Start of Frame marker */
	uint8_t sof;
} __attribute__ (( packed ));

/** A Fibre Channel Frame Header */
struct fc_frame_header {
	/** Routing control */
	uint8_t r_ctl;
	/** Destination ID */
	struct fc_port_id d_id;
	/** Class-specific control / Priority */
	uint8_t cs_ctl_prio;
	/** Source ID */
	struct fc_port_id s_id;
	/** Data structure type */
	uint8_t type;
	/** Frame control - exchange and sequence */
	uint8_t f_ctl_es;
	/** Frame control - acknowledgements  */
	uint8_t f_ctl_ack;
	/** Frame control - miscellaneous */
	uint8_t f_ctl_misc;
	/** Sequence ID */
	uint8_t seq_id;
	/** Data field control */
	uint8_t df_ctl;
	/** Sequence count */
	uint16_t seq_cnt;
	/** Originator exchange ID */
	uint16_t ox_id;
	/** Responder exchange ID */
	uint16_t rx_id;
	/** Parameter */
	uint32_t parameter;
} __attribute__ (( packed ));

struct fcoed_interface;
extern int receive_fcoe ( struct fcoed_interface *intf, void *data,
			  size_t len );

#endif /* _FCOE_H */
