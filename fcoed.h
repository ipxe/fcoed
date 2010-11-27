#ifndef _FCOED_H
#define _FCOED_H

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
#include <pcap.h>
#include "list.h"

/** PID file name */
#define PIDFILE_NAME "/var/run/fcoed.pid"

/** Maximum capture length */
#define PCAP_LEN 65535 /* Maximum possible packet length */

/** Advertisement period in milliseconds */
#define FKA_ADV_PERIOD 8000

/** printf() format for MAC addresses */
#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

/** printf() arguments for MAC addresses */
#define MAC_ARGS(mac) \
	(mac)[0], (mac)[1], (mac)[2], (mac)[3], (mac)[4], (mac)[5]

/** Mark an argument as unused */
#define __unused __attribute__ (( unused ))

/** An interface on which fcoed operates */
struct fcoed_interface {
	/** List of interfaces */
	struct list_head list;
	/** Interface name */
	char name[IF_NAMESIZE];
	/** Packet capture interface */
	pcap_t *pcap;
	/** Packet capture file descriptor */
	int fd;

	/** List of FCoE N_Ports */
	struct list_head ports;
};

/** An FCoE N_Port */
struct fcoed_port {
	/** List of FCoE N_Ports on this interface */
	struct list_head list;
	/** Port ID */
	struct fc_port_id port_id;
	/** FCoE MAC address */
	uint8_t mac[ETH_ALEN];
	/** Real MAC address */
	uint8_t real_mac[ETH_ALEN];
};

extern struct fc_map fc_map;
extern struct fc_port_id fc_f_port_id;
extern uint8_t fc_f_mac[ETH_ALEN];
extern union fcoe_name fc_f_node_wwn;
extern union fcoe_name fc_f_port_wwn;
extern struct fc_port_id fc_gs_port_id;
extern int allow_spma;
extern int fc_vlan;

extern void logmsg ( int level, const char *format, ... )
	__attribute__ (( format ( printf, 2, 3 ) ));
extern void random_ether_addr ( uint8_t *mac );
extern int add_port ( struct fcoed_interface *intf, uint8_t *real_mac,
		      uint8_t *mac, struct fcoed_port **port );
extern int find_port_by_mac ( uint8_t *mac, struct fcoed_interface **intf,
			      struct fcoed_port **port );
extern int find_port_by_real_mac ( uint8_t *real_mac,
				   struct fcoed_interface **intf,
				   struct fcoed_port **port );
extern int find_port_by_id ( struct fc_port_id *port_id,
			     struct fcoed_interface **intf,
			     struct fcoed_port **port );
extern void remove_port ( struct fcoed_port *port );

#endif /* _FCOED_H */
