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
#include "fc.h"

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

/** An FCoE MAC address prefix (FC-MAP) */
struct fc_map {
	uint8_t bytes[3];
} __attribute__ (( packed ));

/** An FCoE (fabric-assigned) MAC address */
struct fcoe_mac {
	/** MAC address prefix */
	struct fc_map fc_map;
	/** Port ID */
	struct fc_port_id port_id;
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

/** Start of Frame marker values */
enum fcoe_sof {
	FCOE_SOF_F = 0x28,	/**< Start of Frame Class F */
	FCOE_SOF_I2 = 0x2d,	/**< Start of Frame Initiate Class 2 */
	FCOE_SOF_N2 = 0x35,	/**< Start of Frame Normal Class 2 */
	FCOE_SOF_I3 = 0x2e,	/**< Start of Frame Initiate Class 3 */
	FCOE_SOF_N3 = 0x36,	/**< Start of Frame Normal Class 3 */
};

/** An FCoE footer */
struct fcoe_footer {
	/** CRC */
	uint32_t crc;
	/** End of frame marker */
	uint8_t eof;
	/** Reserved */
	uint8_t reserved[3];
} __attribute__ (( packed ));

/** End of Frame marker value */
enum fcoe_eof {
	FCOE_EOF_N = 0x41,	/**< End of Frame Normal */
	FCOE_EOF_T = 0x42,	/**< End of Frame Terminate */
	FCOE_EOF_NI = 0x49,	/**< End of Frame Invalid */
	FCOE_EOF_A = 0x50,	/**< End of Frame Abort */
};

struct fcoed_interface;
extern int fc_tx ( struct fc_frame_header *fchdr, size_t len );
extern int fcoe_rx ( struct fcoed_interface *intf, uint8_t *src,
		     void *data, size_t len );

#endif /* _FCOE_H */
