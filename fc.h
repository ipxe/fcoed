#ifndef _FC_H
#define _FC_H

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

/** A Fibre Channel name */
struct fc_name {
	uint8_t bytes[8];
} __attribute__ (( packed ));

/** printf() arguments for FC names */
#define FC_NAME_FMT "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"

/** printf() arguments for FC names */
#define FC_NAME_ARGS(name)						       \
	(name)->bytes[0], (name)->bytes[1], (name)->bytes[2], (name)->bytes[3],\
	(name)->bytes[4], (name)->bytes[5], (name)->bytes[6], (name)->bytes[7]

/** A Fibre Channel port identifier */
struct fc_port_id {
	uint8_t bytes[3];
} __attribute__ (( packed ));

/** printf() format for FC port IDs */
#define FC_PORT_ID_FMT "%02x.%02x.%02x"

/** printf() arguments for FC port IDs */
#define FC_PORT_ID_ARGS(port_id) \
	(port_id)->bytes[0], (port_id)->bytes[1], (port_id)->bytes[2]

/** A Fibre Channel Frame Header */
struct fc_frame_header {
	/** Routing control
	 *
	 * This is the bitwise OR of one @c fc_r_ctl_routing value and
	 * one @c fc_r_ctl_info value.
	 */
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
	/** Parameter
	 *
	 * Contains the relative offset when @c FC_F_CTL_MISC_REL_OFF
	 * is set.
	 */
	uint32_t parameter;
} __attribute__ (( packed ));

/** Fibre Channel Routing Control Routing */
enum fc_r_ctl_routing {
	FC_R_CTL_DATA = 0x00,		/**< Device Data */
	FC_R_CTL_ELS = 0x20,		/**< Extended Link Services */
	FC_R_CTL_FC4_LINK = 0x30,	/**< FC-4 Link Data */
	FC_R_CTL_VIDEO = 0x40,		/**< Video Data */
	FC_R_CTL_EH = 0x50,		/**< Extended Headers */
	FC_R_CTL_BLS = 0x80,		/**< Basic Link Services */
	FC_R_CTL_LINK_CTRL = 0xc0,	/**< Link Control */
	FC_R_CTL_EXT_ROUTE = 0xf0,	/**< Extended Routing */
};

/** Fibre Channel Routing Control Routing mask */
#define FC_R_CTL_ROUTING_MASK 0xf0

/** Fibre Channel Routing Control Information */
enum fc_r_ctl_info {
	FC_R_CTL_UNCAT = 0x00,		/**< Uncategorized */
	FC_R_CTL_SOL_DATA = 0x01,	/**< Solicited Data */
	FC_R_CTL_UNSOL_CTRL = 0x02,	/**< Unsolicited Control */
	FC_R_CTL_SOL_CTRL = 0x03,	/**< Solicited Control */
	FC_R_CTL_UNSOL_DATA = 0x04,	/**< Unsolicited Data */
	FC_R_CTL_DATA_DESC = 0x05,	/**< Data Descriptor */
	FC_R_CTL_UNSOL_CMD = 0x06,	/**< Unsolicited Command */
	FC_R_CTL_CMD_STAT = 0x07,	/**< Command Status */
};

/** Fibre Channel Routing Control Information mask */
#define FC_R_CTL_INFO_MASK 0x07

/** Fibre Channel Data Structure Type */
enum fc_type {
	FC_TYPE_BLS = 0x00,		/**< Basic Link Service */
	FC_TYPE_ELS = 0x01,		/**< Extended Link Service */
	FC_TYPE_FCP = 0x08,		/**< Fibre Channel Protocol */
};

/** Fibre Channel Frame Control - Exchange and Sequence */
enum fc_f_ctl_es {
	FC_F_CTL_ES_RESPONDER = 0x80,	/**< Responder of Exchange */
	FC_F_CTL_ES_RECIPIENT = 0x40,	/**< Sequence Recipient */
	FC_F_CTL_ES_FIRST = 0x20,	/**< First Sequence of Exchange */
	FC_F_CTL_ES_LAST = 0x10,	/**< Last Sequence of Exchange */
	FC_F_CTL_ES_END = 0x08,		/**< Last Data Frame of Sequence */
	FC_F_CTL_ES_TRANSFER = 0x01,	/**< Transfer Sequence Initiative */
};

/** Fibre Channel Frame Control - Miscellaneous */
enum fc_f_ctl_misc {
	FC_F_CTL_MISC_REL_OFF = 0x08,	/**< Relative Offset Present */
};

/** Responder exchange identifier used before first response */
#define FC_RX_ID_UNKNOWN 0xffff

#endif /* _FC_H */
