#ifndef _FCDS_H
#define _FCDS_H

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
#include <stddef.h>
#include "list.h"
#include "fc.h"

/** A Fibre Channel Common Transport header */
struct fc_ct_header {
	/** Revision */
	uint8_t revision;
	/** Original requestor ID */
	struct fc_port_id in_id;
	/** Generic service type */
	uint8_t type;
	/** Generic service subtype */
	uint8_t subtype;
	/** Options */
	uint8_t options;
	/** Reserved */
	uint8_t reserved;
	/** Command/response code */
	uint16_t code;
	/** Maximum/residual size */
	uint16_t size;
	/** Fragment ID */
	uint8_t fragment;
	/** Reason code */
	uint8_t reason;
	/** Reason code explanation */
	uint8_t explanation;
	/** Vendor specific */
	uint8_t vendor;
} __attribute__ (( packed ));

/** Fibre Channel Common Transport revision */
#define FC_CT_REVISION 1

/** Fibre Channel generic service type */
enum fc_gs_type {
	/** Directory service */
	FC_GS_TYPE_DS = 0xfc,
};

/** Fibre Channel generic service response codes */
enum fc_gs_response_code {
	/** Accepted */
	FC_GS_ACCEPT = 0x8002,
	/** Rejected */
	FC_GS_REJECT = 0x8001,
};

/** Fibre Channel generic service rejection reason codes */
enum fc_gs_reason_code {
	/** Invalid command code */
	FC_GS_BAD_COMMAND = 0x01,
	/** Invalid version level */
	FC_GS_BAD_VERSION = 0x02,
	/** Logical error */
	FC_GS_ERROR = 0x03,
	/** Invalid CT_IU size */
	FC_GS_BAD_SIZE = 0x04,
	/** Logical busy */
	FC_GS_BUSY = 0x05,
	/** Protocol error */
	FC_GS_EPROTO = 0x07,
	/** Unable to perform command request */
	FC_GS_UNABLE = 0x09,
	/** Command not supported */
	FC_GS_ENOTSUP = 0x0b,
	/** Server not available */
	FC_GS_UNAVAILABLE = 0x0d,
	/** Session could not be established */
	FC_GS_SESSION = 0x0e,
};

/** Fibre Channel directory service subtype */
enum fc_ds_subtype {
	/** Name server */
	FC_DS_SUBTYPE_NAME = 0x02,
};

/** Fibre Channel name server commands */
enum fc_ns_command_nibble {
	/** Get */
	FC_NS_GET = 0x1,
	/** Register */
	FC_NS_REGISTER = 0x2,
	/** De-register */
	FC_NS_DEREGISTER = 0x3,
};

/** Fibre Channel name server objects */
enum fc_ns_object_nibble {
	/** Port ID */
	FC_NS_PORT_ID = 0x1,
	/** Port name */
	FC_NS_PORT_NAME = 0x2,
	/** Node name */
	FC_NS_NODE_NAME = 0x3,
	/** FC-4 types */
	FC_NS_FC4_TYPES = 0x7,
	/** Symbolic port name */
	FC_NS_SYM_PORT_NAME = 0x8,
	/** Symbolic node name */
	FC_NS_SYM_NODE_NAME = 0x9,
	/** FC-4 features */
	FC_NS_FC4_FEATURES = 0xf,
};

/** Construct Fibre Channel name server command code
 *
 * @v command		Name server command
 * @v key		Name server key
 * @v value		Name server value
 * @ret code		Name server command code
 */
#define FC_NS_CODE( command, key, value )				\
	( ( (command) << 8 ) | ( (key) << 4 ) | ( (value) << 0 ) )

/** Construct Fibre Channel name server "get" command code
 *
 * @v key		Name server key
 * @v value		Name server value to get
 * @ret code		Name server command code
 */
#define FC_NS_GET( key, value ) FC_NS_CODE ( FC_NS_GET, key, value )

/** Construct Fibre Channel name server "register" command code
 *
 * @v key		Name server key
 * @v value		Name server value to register
 * @ret code		Name server command code
 */
#define FC_NS_REGISTER( key, value ) FC_NS_CODE ( FC_NS_REGISTER, key, value )

/** Extract Fibre Channel name server command
 *
 * @v code		Name server command code
 * @ret command		Name server command
 */
#define FC_NS_COMMAND( code ) ( ( (code) >> 8 ) & 0xf )

/** Extract Fibre Channel name server key
 *
 * @v code		Name server command code
 * @ret key		Name server key
 */
#define FC_NS_KEY( code ) ( ( (code) >> 4 ) & 0xf )

/** Extract Fibre Channel name server value
 *
 * @v code		Name server command code
 * @ret value		NAme server value
 */
#define FC_NS_VALUE( code ) ( ( (code) >> 0 ) & 0xf )

/** A Fibre Channel name server port ID */
struct fc_ns_port_id {
	/** Reserved */
	uint8_t reserved;
	/** Port ID */
	struct fc_port_id port_id;
} __attribute__ (( packed ));

/** A Fibre Channel name server symbolic name */
struct fc_ns_symbolic_name {
	/** Length */
	uint8_t len;
	/** Text */
	char text[255];
} __attribute__ (( packed ));

/** A Fibre Channel name server FC-4 type key */
struct fc_ns_fc4_type_key {
	/** Flags */
	uint8_t flags;
	/** Domain ID scope */
	uint8_t domain;
	/** Area ID scope */
	uint8_t area;
	/** FC-4 type */
	uint8_t type;
} __attribute__ (( packed ));

/** Fibre Channel name server FC-4 type key flags */
enum fc_ns_fc4_type_key_flags {
	/** Area ID is valid */
	FC_NS_FC4_TYPE_AREA_ID = 0x80,
};

/** A Fibre Channel name server FC-4 type list */
struct fc_ns_fc4_types {
	/** Types */
	uint32_t types[8];
} __attribute__ (( packed ));

/** A Fibre Channel name server FC-4 feature key */
struct fc_ns_fc4_feature_key {
	/** Flags */
	uint8_t flags;
	/** Domain ID scope */
	uint8_t domain;
	/** Area ID scope */
	uint8_t area;
	/** Reserved */
	uint8_t reserved[3];
	/** FC-4 feature bits */
	uint8_t features;
	/** FC-4 type */
	uint8_t type;	
} __attribute__ (( packed ));

/** Fibre Channel name server FC-4 feature key flags */
enum fc_ns_fc4_feature_key_flags {
	/** Area ID is valid */
	FC_NS_FC4_FEATURE_AREA_ID = 0x80,
};

/** A Fibre Channel name server FC-4 feature value */
struct fc_ns_fc4_feature_value {
	/** Reserved */
	uint8_t reserved[2];
	/** FC-4 feature bits */
	uint8_t features;
	/** FC-4 type */
	uint8_t type;	
} __attribute__ (( packed ));

/** A Fibre Channel name server FC-4 feature list */
struct fc_ns_fc4_features {
	/** Features */
	uint32_t features[32];
} __attribute__ (( packed ));

/** A Fibre Channel name server object set */
struct fc_ns_object_set {
	/** List of all object sets */
	struct list_head list;
	/** Port ID */
	struct fc_port_id port_id;
	/** Port name */
	struct fc_name port_name;
	/** Node name */
	struct fc_name node_name;
	/** FC-4 types */
	struct fc_ns_fc4_types fc4_types;
	/** Symbolic port name */
	struct fc_ns_symbolic_name sym_port_name;
	/** Symbolic node name */
	struct fc_ns_symbolic_name sym_node_name;
	/** FC-4 features */
	struct fc_ns_fc4_features fc4_features;
};

/** Fibre Channel name server packet data */
union fc_ns_data {
	/** Port ID */
	struct fc_ns_port_id port_id;
	/** Name */
	struct fc_name name;
	/** Symbolic name */
	struct fc_ns_symbolic_name sym_name;
	/** FC-4 type key */
	struct fc_ns_fc4_type_key fc4_type_key;
	/** FC-4 type list */
	struct fc_ns_fc4_types fc4_types;
	/** FC-4 feature key */
	struct fc_ns_fc4_feature_key fc4_feature_key;
	/** FC-4 feature value */
	struct fc_ns_fc4_feature_value fc4_feature_value;
};

/** A Fibre Channel name server multiple-response prefix */
struct fc_ns_multi {
	/** Control */
	uint8_t control;
	/** Port ID */
	struct fc_port_id port_id;
} __attribute__ (( packed ));

/** Fibre Channel name server multiple-response prefix control */
enum fc_ns_multi_control {
	/** Last response */
	FC_NS_MULTI_LAST = 0x80,
};

/** Fibre Channel name server multiple-response prefix padding */
#define FC_NS_MULTI_PAD_LEN 4

/** Fibre Channel name server object specificity */
enum fc_ns_object_specificity {
	FC_NS_NON_SPECIFIC = 0,
	FC_NS_PER_NODE,
	FC_NS_PER_PORT,
};

/** A Fibre Channel name server object type */
struct fc_ns_object_type {
	/** Name */
	const char *name;
	/** Code */
	unsigned int code;
	/** Specificity */
	enum fc_ns_object_specificity specificity;
	/** Parse key
	 *
	 * @v key		Key
	 * @v len		Maximum length of key
	 * @ret len		Length consumed, or negative error
	 */
	int ( * parse_key ) ( const union fc_ns_data *key, size_t len );
	/** Transcribe key
	 *
	 * @v key		Key
	 * @v buf		Transcription buffer
	 * @v len		Length of transcription buffer
	 * @ret len		Length of transcribed string
	 */
	int ( * transcribe_key ) ( const union fc_ns_data *key,
				   char *buf, size_t len );
	/** Compare key
	 *
	 * @v key		Key
	 * @v objects		Object set
	 * @ret cmp		Comparison result (0 = match)
	 */
	int ( * compare_key ) ( const union fc_ns_data *key,
				struct fc_ns_object_set *objects );
	/** Parse value
	 *
	 * @v value		Value
	 * @v len		Maximum length of value
	 * @ret len		Length consumed, or negative error
	 */
	int ( * parse_value ) ( const union fc_ns_data *value, size_t len );
	/** Transcribe value
	 *
	 * @v value		Value
	 * @v buf		Transcription buffer
	 * @v len		Length of transcription buffer
	 * @ret len		Length of transcribed string
	 */
	int ( * transcribe_value ) ( const union fc_ns_data *value,
				     char *buf, size_t len );
	/** Store value
	 *
	 * @v objects		Object set
	 * @v value		Value
	 * @ret rc		Return status code
	 */
	int ( * store_value ) ( const union fc_ns_data *value,
				struct fc_ns_object_set *objects );
	/** Fetch value
	 *
	 * @v objects		Object set
	 * @v value		Value
	 * @v len		Maximum length of value
	 * @ret len		Length consumed, or negative error
	 */
	int ( * fetch_value ) ( struct fc_ns_object_set *objects,
				union fc_ns_data *value, size_t len );
};

struct fc_frame_header;
extern int fc_gs_rx ( struct fc_frame_header *fchdr, size_t len );

#endif /* _FCDS_H */
