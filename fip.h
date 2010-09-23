#ifndef _FIP_H
#define _FIP_H

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
#include "fcoe.h"

union fip_descriptor;

/** A FIP frame header */
struct fip_header {
	/** Frame version */
	uint8_t version;
	/** Reserved */
	uint8_t reserved_a;
	/** Protocol code */
	uint16_t code;
	/** Reserved */
	uint8_t reserved_b;
	/** Subcode */
	uint8_t subcode;
	/** Descriptor list length in 32-bit words */
	uint16_t len;
	/** Flags */
	uint16_t flags;
} __attribute__ (( packed ));

/** FIP frame version */
#define FIP_VERSION 0x10

/** FIP protocol code */
enum fip_code {
	FIP_CODE_DISCOVERY = 0x0001,	/**< Discovery */
	FIP_CODE_VIRTUAL_LINK = 0x0002,	/**< Virtual link instantiation */
	FIP_CODE_VITALITY = 0x0003,	/**< Keep alive / clear links */
	FIP_CODE_VLAN = 0x0004,		/**< VLAN */
};

/** FIP protocol subcode for discovery */
enum fip_discovery_subcode {
	FIP_DISCOVERY_SOLICITATION = 0x01,	/**< Discovery solicitation */
	FIP_DISCOVERY_ADVERTISEMENT = 0x02,	/**< Discovery advertisement */
};

/** FIP protocol subcode for virtual link instantiation */
enum fip_virtual_link_subcode {
	FIP_VIRTUAL_LINK_REQUEST = 0x01,	/**< Instantiation request */
	FIP_VIRTUAL_LINK_REPLY = 0x02,		/**< Instantiation reply */
};

/** FIP protocol subcode for keep alive / clear links */
enum fip_vitality_subcode {
	FIP_VITALITY_KEEP_ALIVE = 0x01,		/**< Keep alive */
	FIP_VITALITY_CLEAR_LINKS = 0x02,	/**< Clear virtual links */
};

/** FIP protocol subcode for VLAN */
enum fip_vlan_subcode {
	FIP_VLAN_REQUEST = 0x01,		/**< VLAN request */
	FIP_VLAN_NOTIFICATION = 0x02,		/**< VLAN notification */
};

/** FIP flags */
enum fip_flags {
	FIP_FP	= 0x8000,		/**< Fabric-provided MAC address */
	FIP_SP	= 0x4000,		/**< Server-provided MAC address */
	FIP_A	= 0x0004,		/**< Available for login */
	FIP_S	= 0x0002,		/**< Solicited */
	FIP_F	= 0x0001,		/**< Forwarder */
};

/** FIP descriptor common fields */
struct fip_descriptor_common {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved[2];
} __attribute__ (( packed ));

/** FIP descriptor types */
enum fip_type {
	FIP_PRIORITY = 0x01,		/**< Priority */
	FIP_MAC_ADDRESS = 0x02,		/**< MAC address */
	FIP_FC_MAP = 0x03,		/**< FC-MAP */
	FIP_NAME_ID = 0x04,		/**< Name identifier */
	FIP_FABRIC = 0x05,		/**< Fabric */
	FIP_MAX_FCOE_SIZE = 0x06,	/**< Max FCoE size */
	FIP_FLOGI = 0x07,		/**< FLOGI */
	FIP_NPIV_FDISC = 0x08,		/**< NPIV FDISC */
	FIP_LOGO = 0x09,		/**< LOGO */
	FIP_ELP = 0x0a,			/**< ELP */
	FIP_VX_PORT_ID = 0x0b,		/**< Vx port identification */
	FIP_FKA_ADV_P = 0x0c,		/**< FKA ADV period */
	FIP_VENDOR_ID = 0x0d,		/**< Vendor ID */
	FIP_VLAN = 0x0e,		/**< VLAN */
};

/** FIP descriptor type is critical */
#define FIP_IS_CRITICAL( type ) ( (type) <= 0x7f )

/** A FIP priority descriptor */
struct fip_descriptor_priority {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved;
	/** Priority
	 *
	 * A higher value indicates a lower priority.
	 */
	uint8_t priority;
} __attribute__ (( packed ));

/** Default FIP priority */
#define FIP_DEFAULT_PRIORITY 128

/** A FIP MAC address descriptor */
struct fip_descriptor_mac_address {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** MAC address */
	uint8_t mac[ETH_ALEN];
} __attribute__ (( packed ));

/** A FIP FC-MAP descriptor */
struct fip_descriptor_fc_map {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved[3];
	/** FC-MAP */
	struct fc_map fc_map;
} __attribute__ (( packed ));

/** A FIP name identifier descriptor */
struct fip_descriptor_name_id {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved[2];
	/** Name identifier */
	struct fc_name name;
} __attribute__ (( packed ));

/** A FIP fabric descriptor */
struct fip_descriptor_fabric {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Virtual Fabric ID, if any */
	uint16_t vf_id;
	/** Reserved */
	uint8_t reserved;
	/** FC-MAP */
	struct fc_map fc_map;
	/** Fabric name */
	struct fc_name name;
} __attribute__ (( packed ));

/** A FIP max FCoE size descriptor */
struct fip_descriptor_max_fcoe_size {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Maximum FCoE size */
	uint16_t mtu;
} __attribute__ (( packed ));

/** A FIP descriptor containing an encapsulated Fibre Channel frame */
struct fip_descriptor_fc_frame {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved[2];
	/** Payload */
	uint8_t payload[0];
} __attribute__ (( packed ));

/** A FIP Vx port identification descriptor */
struct fip_descriptor_vx_port_id {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** MAC address */
	uint8_t mac[ETH_ALEN];
	/** Reserved */
	uint8_t reserved;
	/** Address identifier */
	struct fc_port_id id;
	/** Port name */
	struct fc_name name;
} __attribute__ (( packed ));

/** A FIP FKA ADV period descriptor */
struct fip_descriptor_fka_adv_p {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved;
	/** Flags */
	uint8_t flags;
	/** Keep alive advertisement period in milliseconds */
	uint32_t period;
} __attribute__ (( packed ));

/** FIP FKA ADV period flags */
enum fip_descriptor_fka_adv_p_flags {
	FIP_NO_KEEPALIVE = 0x01,	/**< Do not send keepalives */
};

/** A FIP vendor ID descriptor */
struct fip_descriptor_vendor_id {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved[2];
	/** Vendor ID */
	uint8_t vendor[8];
} __attribute__ (( packed ));

/** A FIP VLAN descriptor */
struct fip_descriptor_vlan {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** VLAN ID */
	uint16_t vlan;
} __attribute__ (( packed ));

/** A FIP descriptor */
union fip_descriptor {
	/** Common fields */
	struct fip_descriptor_common common;
	/** Priority descriptor */
	struct fip_descriptor_priority priority;
	/** MAC address descriptor */
	struct fip_descriptor_mac_address mac_address;
	/** FC-MAP descriptor */
	struct fip_descriptor_fc_map fc_map;
	/** Name identifier descriptor */
	struct fip_descriptor_name_id name_id;
	/** Fabric descriptor */
	struct fip_descriptor_fabric fabric;
	/** Max FCoE size descriptor */
	struct fip_descriptor_max_fcoe_size max_fcoe_size;
	/** FLOGI descriptor */
	struct fip_descriptor_fc_frame flogi;
	/** NPIV FDISC descriptor */
	struct fip_descriptor_fc_frame npiv_fdisc;
	/** LOGO descriptor */
	struct fip_descriptor_fc_frame logo;
	/** ELP descriptor */
	struct fip_descriptor_fc_frame elp;
	/** Vx port identification descriptor */
	struct fip_descriptor_vx_port_id vx_port_id;
	/** FKA ADV period descriptor */
	struct fip_descriptor_fka_adv_p fka_adv_p;
	/** Vendor ID descriptor */
	struct fip_descriptor_vendor_id vendor_id;
	/** VLAN descriptor */
	struct fip_descriptor_vlan vlan;
} __attribute__ (( packed ));

struct fcoed_interface;
extern int fip_send_discovery_advertisement ( struct fcoed_interface *intf,
					      uint8_t dst[ETH_ALEN] );
extern int receive_fip ( struct fcoed_interface *intf, void *data, size_t len );

#endif /* _FIP_H */
