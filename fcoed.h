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

/** printf() arguments for FC names */
#define FC_NAME_FMT "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"

/** printf() arguments for FC names */
#define FC_NAME_ARGS(name)						       \
	(name)->bytes[0], (name)->bytes[1], (name)->bytes[2], (name)->bytes[3],\
	(name)->bytes[4], (name)->bytes[5], (name)->bytes[6], (name)->bytes[7]

/** printf() format for FC port IDs */
#define FC_PORT_ID_FMT "%02x.%02x.%02x"

/** printf() arguments for FC port IDs */
#define FC_PORT_ID_ARGS(port_id) \
	(port_id)->bytes[0], (port_id)->bytes[1], (port_id)->bytes[2]

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
	/** MAC address */
	uint8_t mac[ETH_ALEN];
};

extern struct fc_map fc_map;
extern uint8_t fc_f_mac[ETH_ALEN];
extern struct list_head interfaces;

extern void logmsg ( int level, const char *format, ... )
	__attribute__ (( format ( printf, 2, 3 ) ));
extern int add_port ( struct fcoed_interface *intf, struct fc_port_id *port_id,
		      uint8_t mac[ETH_ALEN] );
extern void remove_port ( struct fcoed_port *port );

#endif /* _FCOED_H */
