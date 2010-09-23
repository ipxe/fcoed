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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <byteswap.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pcap.h>
#include <syslog.h>
#include <getopt.h>
#include <libgen.h>
#include "fcoe.h"
#include "fip.h"
#include "fcoed.h"

/** We are going to daemonise */
static int will_daemonise = 1;

/** We are running daemonised */
static int daemonised = 0;

/** FCoE MAC address prefix */
struct fc_map fc_map = { { 0x0e, 0xfc, 0x00 } };

/** FCoE MAC address */
uint8_t fc_f_mac[ETH_ALEN];

/** FCoE All-FCoE-MACs address */
static uint8_t all_fcoe_macs[ETH_ALEN] =
	{ 0x01, 0x10, 0x18, 0x01, 0x00, 0x00 };

/** FCoE All-ENode-MACs address */
static uint8_t all_enode_macs[ETH_ALEN] =
	{ 0x01, 0x10, 0x18, 0x01, 0x00, 0x01 };

/** FCoE All-FCF-MACs address */
static uint8_t all_fcf_macs[ETH_ALEN] =
	{ 0x01, 0x10, 0x18, 0x01, 0x00, 0x02 };

/** List of interfaces */
LIST_HEAD ( interfaces );

/**
 * Log error message
 *
 * @v level		Severity level
 * @v format		Format string
 * @v ...		Arguments
 */
void logmsg ( int level, const char *format, ... ) {
	va_list ap;

	va_start ( ap, format );
	if ( daemonised ) {
		vsyslog ( ( LOG_DAEMON | level ), format, ap );
	} else {
		vfprintf ( stderr, format, ap );
	}
	va_end ( ap );
}

/**
 * Generate MAC address
 *
 */
static void set_fc_f_mac ( void ) {
	struct timeval tv;
	unsigned int i;

	/* Generate random initial MAC */
	gettimeofday ( &tv, NULL );
	srand ( tv.tv_usec );
	for ( i = 0 ; i < sizeof ( fc_f_mac ) ; i++ )
		fc_f_mac[i] = random();

	/* Clear multicast bit */
	fc_f_mac[0] &= ~0x01;

	/* Set locally-assigned bit */
	fc_f_mac[0] |= 0x02;
}

/**
 * Set Fibre Channel MAC prefix
 *
 * @v map_text		MAP as text
 * @ret rc		Return status code
 */
static int set_fcmap ( const char *map_text ) {
	char *ptr = ( ( char * ) map_text );
	unsigned int i = 0;

	while ( 1 ) {
		fc_map.bytes[i++] = strtoul ( ptr, &ptr, 16 );
		if ( i == sizeof ( fc_map.bytes ) )
			return ( ( *ptr == '\0' ) ? 0 : -1 );
		if ( ! ( ( *ptr == '.' ) || ( *ptr ==':' ) ) )
			return -1;
		ptr++;
	}

	return 0;
}

/**
 * Add FCoE interface
 *
 * @v name		Interface name
 * @ret rc		Return status code
 */
static int add_interface ( const char *name ) {
	char errbuf[PCAP_ERRBUF_SIZE];
	struct fcoed_interface *intf;
	char filter[256];
	struct bpf_program program;

	/* Allocate and initialise structure */
	intf = malloc ( sizeof ( *intf ) );
	if ( ! intf )
		goto err_malloc;
	memset ( intf, 0, sizeof ( *intf ) );
	snprintf ( intf->name, sizeof ( intf->name ), "%s", name );
	INIT_LIST_HEAD ( &intf->ports );

	/* Open packet capture interface */
	errbuf[0] = '\0';
	intf->pcap = pcap_open_live ( intf->name, PCAP_LEN, 1, 0, errbuf );
	if ( ! intf->pcap ) {
		logmsg ( LOG_ERR, "Failed to open %s: %s\n",
			 intf->name, errbuf );
		goto err_open_live;
	}
	if ( errbuf[0] )
		logmsg ( LOG_WARNING, "Warning: %s\n", errbuf );

	/* Set capture interface to non-blocking mode */
	if ( pcap_setnonblock ( intf->pcap, 1, errbuf ) < 0 ) {
		logmsg ( LOG_ERR, "Could not make %s non-blocking: %s\n",
			 intf->name, errbuf );
		goto err_setnonblock;
	}

	/* Get file descriptor for select() */
	intf->fd = pcap_get_selectable_fd ( intf->pcap );
	if ( intf->fd < 0 ) {
		logmsg ( LOG_ERR, "Cannot get selectable file descriptor "
			 "for %s\n", intf->name );
		goto err_get_fd;
	}

	/* Get link layer type */
	if ( pcap_datalink ( intf->pcap ) != DLT_EN10MB ) {
		logmsg ( LOG_ERR, "%s is not an Ethernet interface\n",
			 intf->name );
		goto err_datalink;
	}

	/* Build filter */
	snprintf ( filter, sizeof ( filter ),
		   "( ether proto %#04x or ether proto %#04x ) and "
		   "( ether dst " MAC_FMT " or "
		   "  ether dst " MAC_FMT " or "
		   "  ether dst " MAC_FMT " or "
		   "  ether dst " MAC_FMT " )",
		   ETH_P_FCOE, ETH_P_FIP, MAC_ARGS ( fc_f_mac ),
		   MAC_ARGS ( all_fcoe_macs ), MAC_ARGS ( all_enode_macs ),
		   MAC_ARGS ( all_fcf_macs ) );

	/* Compile filter */
	if ( pcap_compile ( intf->pcap, &program, filter, 1, 0 ) < 0 ) {
		logmsg ( LOG_ERR, "Could not compile filter \"%s\": %s\n",
			 filter, pcap_geterr ( intf->pcap ) );
		goto err_compile;
	}

	/* Install filter */
	if ( pcap_setfilter ( intf->pcap, &program ) < 0 ) {
		logmsg ( LOG_ERR, "Could not install filter \"%s\": %s\n",
			 filter, pcap_geterr ( intf->pcap ) );
		goto err_setfilter;
	}

	/* Add to list of interfaces and return */
	list_add ( &intf->list, &interfaces );

	pcap_freecode ( &program );
	return 0;

 err_setfilter:
	pcap_freecode ( &program );
 err_compile:
 err_datalink:
 err_get_fd:
 err_setnonblock:
	pcap_close ( intf->pcap );
 err_open_live:
	free ( intf );
 err_malloc:
	return -1;
}

/**
 * Add port to FCoE interface
 *
 * @v intf		Interface
 * @v port_id		Port ID
 * @v mac		MAC address
 * @ret rc		Return status code
 */
int add_port ( struct fcoed_interface *intf, struct fc_port_id *port_id,
	       uint8_t mac[ETH_ALEN] ) {
	struct fcoed_port *port;

	/* Allocate and initialise structure */
	port = malloc ( sizeof ( *port ) );
	if ( ! port )
		return -1;
	memset ( port, 0, sizeof ( *port ) );
	memcpy ( &port->port_id, port_id, sizeof ( port->port_id ) );
	memcpy ( port->mac, mac, sizeof ( port->mac ) );
	list_add ( &port->list, &intf->ports );
	return 0;
}

/**
 * Remove port from FCoE interface
 *
 * @v port		Port
 */
void remove_port ( struct fcoed_port *port ) {

	list_del ( &port->list );
	free ( port );
}

/**
 * Remove FCoE interfaces
 *
 * @v intf		Interface
 */
static void remove_interface ( struct fcoed_interface *intf ) {
	struct fcoed_port *port;
	struct fcoed_port *tmp;

	list_for_each_entry_safe ( port, tmp, &intf->ports, list )
		remove_port ( port );

	pcap_close ( intf->pcap );
	list_del ( &intf->list );
	free ( intf );
}

/**
 * Remove all FCoE interfaces
 *
 */
static void remove_all_interfaces ( void ) {
	struct fcoed_interface *intf;
	struct fcoed_interface *tmp;

	list_for_each_entry_safe ( intf, tmp, &interfaces, list )
		remove_interface ( intf );
}

/**
 * Add all possible FCoE interfaces
 *
 * @ret rc		Return status code
 */
static int add_all_interfaces ( void ) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	pcap_if_t *dev;
	unsigned int opened = 0;

	/* Get list of all devices */
	if ( pcap_findalldevs ( &alldevs, errbuf ) < 0 ) {
		logmsg ( LOG_ERR, "Cannot enumerate network devices: %s\n",
			 errbuf );
		goto err_findalldevs;
	}

	/* Try all devices in the list.  Treat failures as non-fatal,
	 * since the list may include non-Ethernet devices.
	 */
	for ( dev = alldevs ; dev ; dev = dev->next ) {
		if ( dev->flags & PCAP_IF_LOOPBACK )
			continue;
		if ( strcmp ( dev->name, "any" ) == 0 )
			continue;
		if ( add_interface ( dev->name ) == 0 ) {
			logmsg ( LOG_INFO, "Listening on %s\n", dev->name );
			opened++;
		}
	}

	/* Fail if no interfaces were opened */
	if ( opened == 0 ) {
		logmsg ( LOG_ERR, "Could not listen on any interfaces\n" );
		goto err_nodevs;
	}

	pcap_freealldevs ( alldevs );
	return 0;

 err_nodevs:
	pcap_freealldevs ( alldevs );
 err_findalldevs:
	return -1;
}

/**
 * Print usage
 *
 * @v argv		Argument list
 */
static void usage ( char **argv ) {
	logmsg ( LOG_ERR,
		 "Usage: %s [options] interface [interface...]\n"
		 "\n"
		 "Options:\n"
		 "  -h|--help               Print this help message\n"
		 "  -n|--nodaemon           Run in foreground\n"
		 "  -m|--map=XX.XX.XX       Specify FC-MAP\n",
		 argv[0] );
}

/**
 * Parse command-line options
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret optind		Index of first non-option, or negative error
 */
static int parse_options ( int argc, char **argv ) {
	static struct option longopts[] = {
		{ "help", 0, NULL, 'h' },
		{ "nodaemon", 0, NULL, 'n' },
		{ "map", required_argument, NULL, 'm' },
		{ NULL, 0, NULL, 0 },
	};
	int longidx;
	int c;

	/* Parse command-line options */
	while ( 1 ) {
		c = getopt_long ( argc, argv, "hn", longopts, &longidx );
		if ( c < 0 )
			break;

		switch ( c ) {
		case 'h':
			usage( argv );
			return -1;
		case 'n':
			will_daemonise = 0;
			break;
		case 'm':
			if ( set_fcmap ( optarg ) < 0 )
				return -1;
			break;
		default:
			logmsg ( LOG_ERR, "Unrecognised option '-%c'\n", c );
			return -1;
		}
	}

	return optind;
}

/**
 * Daemonise
 *
 * @ret rc		Return status code
 */
static int daemonise ( void ) {
	char pid[16];
	int pidlen;
	int fd;

	/* Open pid file */
	fd = open ( PIDFILE_NAME, ( O_WRONLY | O_CREAT | O_TRUNC ),
		    ( S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH ) );
	if ( fd < 0 ) {
		logmsg ( LOG_ERR, "Could not open %s for writing: %s\n",
			 PIDFILE_NAME, strerror ( errno ) );
		goto err_open;
	}

	/* Daemonise */
	if ( daemon ( 0, 0 ) < 0 ) {
		logmsg ( LOG_ERR, "Could not daemonise: %s\n",
			 strerror ( errno ) );
		goto err_daemon;
	}
	daemonised = 1; /* Direct messages to syslog now */

	/* Write pid to file */
	pidlen = snprintf ( pid, sizeof ( pid ), "%d\n", getpid() );
	if ( write ( fd, pid, pidlen ) != pidlen ) {
		logmsg ( LOG_ERR, "Could not write %s: %s\n",
			 PIDFILE_NAME, strerror ( errno ) );
		goto err_write;
	}

	close ( fd );
	return 0;

 err_write:
 err_daemon:
	close ( fd );
 err_open:
	return -1;
}

/**
 * Receive data on an interface
 *
 * @v intf		Interface
 * @ret rc		Return status code
 */
static int receive ( struct fcoed_interface *intf ) {
	struct pcap_pkthdr *pkt_header;
	const unsigned char *pkt_data;
	struct ethhdr *ethhdr;
	size_t pkt_len;

	/* Receive packet from network */
	if ( pcap_next_ex ( intf->pcap, &pkt_header, &pkt_data ) < 0 ) {
		logmsg ( LOG_ERR, "read from %s failed: %s\n",
			 intf->name, pcap_geterr ( intf->pcap ) );
		goto error;
	}
	if ( pkt_header->caplen != pkt_header->len ) {
		logmsg ( LOG_ERR, "read partial packet (%d of %d bytes)\n",
			 pkt_header->caplen, pkt_header->len );
		goto discard;
	}
	if ( pkt_header->len == 0 )
		goto discard;
	pkt_len = pkt_header->len;

	/* Hand off packet to appropriate protocol */
	ethhdr = ( ( void * ) pkt_data );
	if ( pkt_len < sizeof ( *ethhdr ) ) {
		logmsg ( LOG_ERR, "received truncated Ethernet header (%zd "
			 "bytes)\n", pkt_len );
		goto discard;
	}
	switch ( ntohs ( ethhdr->h_proto ) ) {
	case ETH_P_FCOE :
		if ( receive_fcoe ( intf, ethhdr, pkt_len ) < 0 )
			goto discard;
		break;
	case ETH_P_FIP :
		if ( receive_fip ( intf, ethhdr, pkt_len ) < 0 )
			goto discard;
		break;
	default:
		logmsg ( LOG_ERR, "read unknown protocol %#04x\n",
			 ntohs ( ethhdr->h_proto ) );
		goto discard;
	}

	return 0;

 discard:
	/* Discard packet, but don't abort */
	return 0;

 error:
	return -1;
}

/**
 * Send discovery advertisement on all interfaces
 *
 */
static void advertise ( void ) {
	struct fcoed_interface *intf;

	list_for_each_entry ( intf, &interfaces, list )
		fip_send_discovery_advertisement ( intf, all_enode_macs );
}

/**
 * Main loop
 *
 * @v intfs		Array of interfaces, indexed by file descriptor
 * @v numfds		Maximum file descriptor plus one
 * @ret rc		Return status code
 */
static int main_loop ( struct fcoed_interface **intfs, int numfds ) {
	struct timeval tv = { 0, 0 };
	fd_set fdset;
	int fd;

	while ( 1 ) {

		/* Send unsolicited discovery advertisement every
		 * FKA_ADV_PERIOD milliseconds.
		 */
		if ( ( tv.tv_sec == 0 ) && ( tv.tv_usec == 0 ) ) {
			advertise();
			tv.tv_sec = ( FKA_ADV_PERIOD / 1000 );
			tv.tv_usec = ( ( FKA_ADV_PERIOD % 1000 ) * 1000 );
		}

		/* Build file descriptor set for select() */
		FD_ZERO ( &fdset );
		for ( fd = 0 ; fd < numfds ; fd++ ) {
			if ( intfs[fd] )
				FD_SET ( fd, &fdset );
		}

		/* Wait for activity */
		if ( select ( numfds, &fdset, NULL, NULL, &tv ) < 0 ) {
			logmsg ( LOG_ERR, "select() failed: %s\n",
				 strerror ( errno ) );
			return -1;
		}

		/* Process any received data */
		for ( fd = 0 ; fd < numfds ; fd++ ) {
			if ( ! FD_ISSET ( fd, &fdset ) )
				continue;

			/* Receieve data */
			if ( receive ( intfs[fd] ) < 0 ) {
				logmsg ( LOG_ERR, "removing interface %s\n",
					 intfs[fd]->name );
				remove_interface ( intfs[fd] );
				intfs[fd] = NULL;
			}
		}
	}
}

/**
 * Main program
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret exit		Exit code
 */
int main ( int argc, char **argv ) {
	struct fcoed_interface *intf;
	struct fcoed_interface **intfs;
	int ifidx;
	int numfds = 0;

	/* Set MAC address */
	set_fc_f_mac();

	/* Parse command-line options */
	if ( ( ifidx = parse_options ( argc, argv ) ) < 0 )
		goto err_options;

	/* Add interfaces as specified */
	if ( ifidx < argc ) {
		for ( ; ifidx < argc ; ifidx++ ) {
			if ( add_interface ( argv[ifidx] ) < 0 ) {
				remove_all_interfaces();
				goto err_add_interfaces;
			}
		}
	} else {
		if ( add_all_interfaces() < 0 )
			goto err_add_interfaces;
	}

	/* Set up syslog connection */
	openlog ( basename ( argv[0] ), LOG_PID, LOG_DAEMON );

	/* Build list of interfaces indexed by file descriptor */
	list_for_each_entry ( intf, &interfaces, list ) {
		if ( numfds <= intf->fd )
			numfds = ( intf->fd + 1 );
	}
	intfs = malloc ( numfds * sizeof ( intfs[0] ) );
	if ( ! intfs ) {
		logmsg ( LOG_ERR, "Cannot allocate interface array\n" );
		goto err_array;
	}
	memset ( intfs, 0, numfds * sizeof ( intfs[0] ) );
	list_for_each_entry ( intf, &interfaces, list ) {
		intfs[intf->fd] = intf;
	}

	/* Daemonise on demand */
	if ( will_daemonise ) {
		if ( daemonise() < 0 )
			goto err_daemonise;
	}

	/* Run main loop */
	main_loop ( intfs, numfds );

 err_daemonise:
 err_array:
	remove_all_interfaces();
 err_add_interfaces:
 err_options:
	return 1;
}
