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
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <netinet/in.h>
#include "fc.h"
#include "fcds.h"
#include "fcels.h"
#include "fcoed.h"

/** Maximum size of name server responses
 *
 * This is a policy decision.
 */
#define FC_NS_BUFSIZE 1024

/**
 * Parse port ID
 *
 * @v data		Data
 * @v len		Maximum length of data
 * @ret len		Length consumed, or negative error
 */
static int fc_ns_port_id_parse ( const union fc_ns_data *data, size_t len ) {
	if ( len < sizeof ( data->port_id ) )
		return -EINVAL;
	return sizeof ( data->port_id );
}

/**
 * Transcribe port ID
 *
 * @v data		Data
 * @v buf		Transcription buffer
 * @v len		Length of transcription buffer
 * @ret len		Length of transcribed string
 */
static int fc_ns_port_id_transcribe ( const union fc_ns_data *data,
				      char *buf, size_t len ) {
	return snprintf ( buf, len, FC_PORT_ID_FMT,
			  FC_PORT_ID_ARGS ( &data->port_id.port_id ) );
}

/**
 * Compare port ID
 *
 * @v key		Key
 * @v objects		Object set
 * @ret cmp		Comparison result (0 = match)
 */
static int fc_ns_port_id_compare ( const union fc_ns_data *key,
				   struct fc_ns_object_set *objects ) {
	return memcmp ( &objects->port_id, &key->port_id.port_id,
			sizeof ( objects->port_id ) );
}

/**
 * Fetch port ID
 *
 * @v objects		Object set
 * @v value		Value
 * @v len		Maximum length of value
 * @ret len		Length consumed, or negative error
 */
static int fc_ns_port_id_fetch ( struct fc_ns_object_set *objects,
				 union fc_ns_data *value, size_t len ) {

	if ( len < sizeof ( value->port_id ) )
		return -EINVAL;
	memcpy ( &value->port_id.port_id, &objects->port_id,
		 sizeof ( value->port_id.port_id ) );
	return sizeof ( value->port_id );
}

/** Port ID object type */
static struct fc_ns_object_type fc_ns_port_id_type = {
	.name = "ID",
	.code = FC_NS_PORT_ID,
	.specificity = FC_NS_PER_PORT,
	.parse_key = fc_ns_port_id_parse,
	.transcribe_key = fc_ns_port_id_transcribe,
	.compare_key = fc_ns_port_id_compare,
	.parse_value = fc_ns_port_id_parse,
	.transcribe_value = fc_ns_port_id_transcribe,
	.fetch_value = fc_ns_port_id_fetch,
};

/**
 * Parse name
 *
 * @v data		Data
 * @v len		Maximum length of data
 * @ret len		Length consumed, or negative error
 */
static int fc_ns_name_parse ( const union fc_ns_data *data, size_t len ) {
	if ( len < sizeof ( data->name ) )
		return -EINVAL;
	return sizeof ( data->name );
}

/**
 * Transcribe name
 *
 * @v data		Data
 * @v buf		Transcription buffer
 * @v len		Length of transcription buffer
 * @ret len		Length of transcribed string
 */
static int fc_ns_name_transcribe ( const union fc_ns_data *data,
				   char *buf, size_t len ) {
	return snprintf ( buf, len, FC_NAME_FMT, FC_NAME_ARGS ( &data->name ) );
}

/**
 * Compare port name
 *
 * @v key		Key
 * @v objects		Object set
 * @ret cmp		Comparison result (0 = match)
 */
static int fc_ns_port_name_compare ( const union fc_ns_data *key,
				     struct fc_ns_object_set *objects ) {
	return memcmp ( &objects->port_name, &key->name,
			sizeof ( objects->port_name ) );
}

/**
 * Store port name
 *
 * @v value		Value
 * @v objects		Object set
 * @ret rc		Return status code
 */
static int fc_ns_port_name_store ( const union fc_ns_data *value,
				   struct fc_ns_object_set *objects ) {
	memcpy ( &objects->port_name, &value->name,
		 sizeof ( objects->port_name ) );
	return 0;
}

/**
 * Compare node name
 *
 * @v key		Key
 * @v objects		Object set
 * @ret cmp		Comparison result (0 = match)
 */
static int fc_ns_node_name_compare ( const union fc_ns_data *key,
				     struct fc_ns_object_set *objects ) {
	return memcmp ( &objects->node_name, &key->name,
			sizeof ( objects->node_name ) );
}

/**
 * Store node name
 *
 * @v value		Value
 * @v objects		Object set
 * @ret rc		Return status code
 */
static int fc_ns_node_name_store ( const union fc_ns_data *value,
				   struct fc_ns_object_set *objects ) {
	memcpy ( &objects->node_name, &value->name,
		 sizeof ( objects->node_name ) );
	return 0;
}

/** Port name object type */
static struct fc_ns_object_type fc_ns_port_name_type = {
	.name = "PN",
	.code = FC_NS_PORT_NAME,
	.specificity = FC_NS_PER_PORT,
	.parse_key = fc_ns_name_parse,
	.transcribe_key = fc_ns_name_transcribe,
	.compare_key = fc_ns_port_name_compare,
	.parse_value = fc_ns_name_parse,
	.transcribe_value = fc_ns_name_transcribe,
	.store_value = fc_ns_port_name_store,
};

/** Node name object type */
static struct fc_ns_object_type fc_ns_node_name_type = {
	.name = "NN",
	.code = FC_NS_NODE_NAME,
	.specificity = FC_NS_PER_NODE,
	.parse_key = fc_ns_name_parse,
	.transcribe_key = fc_ns_name_transcribe,
	.compare_key = fc_ns_node_name_compare,
	.parse_value = fc_ns_name_parse,
	.transcribe_value = fc_ns_name_transcribe,
	.store_value = fc_ns_node_name_store,
};

/**
 * Parse symbolic name
 *
 * @v data		Data
 * @v len		Maximum length of data
 * @ret len		Length consumed, or negative error
 */
static int fc_ns_sym_name_parse ( const union fc_ns_data *data, size_t len ) {
	
	if ( len < offsetof ( typeof ( data->sym_name ), text ) )
		return -EINVAL;
	if ( len < offsetof ( typeof ( data->sym_name ),
			      text[data->sym_name.len] ) )
		return -EINVAL;
	return offsetof ( typeof ( data->sym_name ), text[data->sym_name.len] );
}

/**
 * Transcribe symbolic name
 *
 * @v data		Data
 * @v buf		Transcription buffer
 * @v len		Length of transcription buffer
 * @ret len		Length of transcribed string
 */
static int fc_ns_sym_name_transcribe ( const union fc_ns_data *data,
				       char *buf, size_t len ) {
	char tmp[ data->sym_name.len + 1 /* NUL */ ];

	memcpy ( tmp, data->sym_name.text, data->sym_name.len );
	tmp[data->sym_name.len] = '\0';
	return snprintf ( buf, len, "\"%s\"", tmp );
}

/**
 * Store symbolic port name
 *
 * @v value		Value
 * @v objects		Object set
 * @ret rc		Return status code
 */
static int fc_ns_sym_port_name_store ( const union fc_ns_data *data,
				       struct fc_ns_object_set *objects ) {
	memcpy ( &objects->sym_port_name, &data->sym_name,
		 offsetof ( typeof ( data->sym_name ),
			    text[data->sym_name.len] ) );
	return 0;
}

/**
 * Store symbolic node name
 *
 * @v value		Value
 * @v objects		Object set
 * @ret rc		Return status code
 */
static int fc_ns_sym_node_name_store ( const union fc_ns_data *data,
				       struct fc_ns_object_set *objects ) {
	memcpy ( &objects->sym_node_name, &data->sym_name,
		 offsetof ( typeof ( data->sym_name ),
			    text[data->sym_name.len] ) );
	return 0;
}

/** Symbolic port name object type */
static struct fc_ns_object_type fc_ns_sym_port_name_type = {
	.name = "SPN",
	.code = FC_NS_SYM_PORT_NAME,
	.specificity = FC_NS_PER_PORT,
	.parse_key = fc_ns_sym_name_parse,
	.transcribe_key = fc_ns_sym_name_transcribe,
	.parse_value = fc_ns_sym_name_parse,
	.transcribe_value = fc_ns_sym_name_transcribe,
	.store_value = fc_ns_sym_port_name_store,
};

/** Symbolic node name object type */
static struct fc_ns_object_type fc_ns_sym_node_name_type = {
	.name = "SNN",
	.code = FC_NS_SYM_NODE_NAME,
	.specificity = FC_NS_PER_NODE,
	.parse_key = fc_ns_sym_name_parse,
	.transcribe_key = fc_ns_sym_name_transcribe,
	.parse_value = fc_ns_sym_name_parse,
	.transcribe_value = fc_ns_sym_name_transcribe,
	.store_value = fc_ns_sym_node_name_store,
};

/**
 * Parse FC-4 type key
 *
 * @v data		Data
 * @v len		Maximum length of data
 * @ret len		Length consumed, or negative error
 */
static int fc_ns_fc4_type_key_parse ( const union fc_ns_data *data,
				      size_t len ) {
	if ( len < sizeof ( data->fc4_type_key ) )
		return -EINVAL;
	return sizeof ( data->fc4_type_key );
}

/**
 * Transcribe FC-4 type key
 *
 * @v data		Data
 * @v buf		Transcription buffer
 * @v len		Length of transcription buffer
 * @ret len		Length of transcribed string
 */
static int fc_ns_fc4_type_key_transcribe ( const union fc_ns_data *data,
					   char *buf, size_t len ) {
	char domain[5]; /* "0xXX" */
	char area[5]; /* "0xXX" */

	snprintf ( domain, sizeof ( domain ), "0x%02x",
		   data->fc4_type_key.domain );
	snprintf ( area, sizeof ( area ), "0x%02x",
		   data->fc4_type_key.area );
	return snprintf ( buf, len, "0x%02x (domain %s area %s)",
			  data->fc4_type_key.type,
			  ( data->fc4_type_key.domain ? domain : "any" ),
			  ( ( data->fc4_type_key.flags &
			      FC_NS_FC4_TYPE_AREA_ID ) ? area : "any" ) );
}

/**
 * Compare FC-4 type key
 *
 * @v key		Key
 * @v objects		Object set
 * @ret cmp		Comparison result (0 = match)
 */
static int fc_ns_fc4_type_key_compare ( const union fc_ns_data *key,
					struct fc_ns_object_set *objects ) {
	unsigned int word;
	unsigned int bit;

	word = ( key->fc4_type_key.type / 32 );
	bit = ( key->fc4_type_key.type % 32 );
	if ( ! ( ntohl ( objects->fc4_types.types[word] ) & ( 1 << bit ) ) )
		return -1;
	return 0;
}

/**
 * Parse FC-4 type list
 *
 * @v value		Value
 * @v len		Maximum length of value
 * @ret len		Length consumed, or negative error
 */
static int fc_ns_fc4_types_parse ( const union fc_ns_data *value, size_t len ) {

	if ( len < sizeof ( value->fc4_types ) )
		return -EINVAL;
	return sizeof ( value->fc4_types );
}

/**
 * Transcribe FC-4 type list
 *
 * @v value		Value
 * @v buf		Transcription buffer
 * @v len		Length of transcription buffer
 * @ret len		Length of transcribed string
 */
static int fc_ns_fc4_types_transcribe ( const union fc_ns_data *value,
					char *buf, size_t len ) {
	const struct fc_ns_fc4_types *types = &value->fc4_types;
	char tmp[len];
	unsigned int word;
	unsigned int bit;
	unsigned int index = 0;
	uint32_t data;
	int rlen = 0;

	buf[0] = '\0';
	for ( word = 0 ;
	      word < ( sizeof ( types->types ) /
		       sizeof ( types->types[0] ) ) ;
	      word++ ) {
		data = ntohl ( types->types[word] );
		for ( bit = 0 ;
		      bit < ( 8 * sizeof ( types->types[0] ) ) ;
		      bit++, index++, data >>= 1 ) {
			if ( data & 0x1 ) {
				strcpy ( tmp, buf );
				rlen = snprintf ( buf, len, "%s%s0x%02x",
						  tmp, ( tmp[0] ? "," : "" ),
						  index );
			}
		}
	}
	return rlen;
}

/**
 * Store FC-4 type list
 *
 * @v value		Value
 * @v objects		Object set
 * @ret rc		Return status code
 */
static int fc_ns_fc4_types_store ( const union fc_ns_data *data,
				   struct fc_ns_object_set *objects ) {
	memcpy ( &objects->fc4_types, &data->fc4_types,
		 sizeof ( objects->fc4_types ) );
	return 0;
}

/** FC-4 types object type */
static struct fc_ns_object_type fc_ns_fc4_types_type = {
	.name = "FT",
	.code = FC_NS_FC4_TYPES,
	.parse_key = fc_ns_fc4_type_key_parse,
	.transcribe_key = fc_ns_fc4_type_key_transcribe,
	.compare_key = fc_ns_fc4_type_key_compare,
	.parse_value = fc_ns_fc4_types_parse,
	.transcribe_value = fc_ns_fc4_types_transcribe,
	.store_value = fc_ns_fc4_types_store,
};

/**
 * Parse FC-4 feature key
 *
 * @v data		Data
 * @v len		Maximum length of data
 * @ret len		Length consumed, or negative error
 */
static int fc_ns_fc4_feature_key_parse ( const union fc_ns_data *data,
					 size_t len ) {
	if ( len < sizeof ( data->fc4_feature_key ) )
		return -EINVAL;
	return sizeof ( data->fc4_feature_key );
}

/**
 * Transcribe FC-4 feature key
 *
 * @v data		Data
 * @v buf		Transcription buffer
 * @v len		Length of transcription buffer
 * @ret len		Length of transcribed string
 */
static int fc_ns_fc4_feature_key_transcribe ( const union fc_ns_data *data,
					      char *buf, size_t len ) {
	char domain[5]; /* "0xXX" */
	char area[5]; /* "0xXX" */

	snprintf ( domain, sizeof ( domain ), "0x%02x",
		   data->fc4_feature_key.domain );
	snprintf ( area, sizeof ( area ), "0x%02x",
		   data->fc4_feature_key.area );
	return snprintf ( buf, len, "0x%02x;[0x%x] (domain %s area %s)",
			  data->fc4_feature_key.type,
			  data->fc4_feature_key.features,
			  ( data->fc4_feature_key.domain ? domain : "any" ),
			  ( ( data->fc4_feature_key.flags &
			      FC_NS_FC4_FEATURE_AREA_ID ) ? area : "any" ) );
}

/**
 * Compare FC-4 feature key
 *
 * @v key		Key
 * @v objects		Object set
 * @ret cmp		Comparison result (0 = match)
 */
static int fc_ns_fc4_feature_key_compare ( const union fc_ns_data *key,
					   struct fc_ns_object_set *objects ) {
	unsigned int types_word;
	unsigned int types_bit;
	unsigned int features_word;
	unsigned int features_nibble;
	uint32_t features;

	/* Check type is supported */
	types_word = ( key->fc4_feature_key.type / 32 );
	types_bit = ( key->fc4_feature_key.type % 32 );
	if ( ! ( ntohl ( objects->fc4_types.types[types_word] ) &
		 ( 1 << types_bit ) ) ) {
		return -1;
	}

	/* Check all requested features are supported */
	features_word = ( key->fc4_feature_key.type / 8 );
	features_nibble = ( key->fc4_feature_key.type % 8 );
	features = ( key->fc4_feature_key.features << ( 4 * features_nibble ));
	if ( ( ntohl ( objects->fc4_features.features[features_word] ) &
	       features ) != features ) {
		return -1;
	}

	return 0;
}

/**
 * Parse FC-4 feature value
 *
 * @v data		Data
 * @v len		Maximum length of data
 * @ret len		Length consumed, or negative error
 */
static int fc_ns_fc4_feature_value_parse ( const union fc_ns_data *data,
					   size_t len ) {
	if ( len < sizeof ( data->fc4_feature_value ) )
		return -EINVAL;
	return sizeof ( data->fc4_feature_value );
}

/**
 * Transcribe FC-4 feature value
 *
 * @v data		Data
 * @v buf		Transcription buffer
 * @v len		Length of transcription buffer
 * @ret len		Length of transcribed string
 */
static int fc_ns_fc4_feature_value_transcribe ( const union fc_ns_data *data,
						char *buf, size_t len ) {
	return snprintf ( buf, len, "0x%02x:[0x%x]",
			  data->fc4_feature_value.type,
			  data->fc4_feature_value.features );
}

/**
 * Store FC-4 feature value
 *
 * @v value		Value
 * @v objects		Object set
 * @ret rc		Return status code
 */
static int fc_ns_fc4_feature_value_store ( const union fc_ns_data *value,
					   struct fc_ns_object_set *objects ) {
	unsigned int word;
	unsigned int nibble;
	uint32_t features;
	uint32_t mask;

	word = ( value->fc4_feature_value.type / 8 );
	nibble = ( value->fc4_feature_value.type % 8 );
	features = ( value->fc4_feature_value.features << ( 4 * nibble ));
	mask = ( 0xf << ( 4 * nibble ) );
	objects->fc4_features.features[word] &= ~mask;
	objects->fc4_features.features[word] |= features;
	return 0;
}

/** FC-4 features object type */
static struct fc_ns_object_type fc_ns_fc4_features_type = {
	.name = "FF",
	.code = FC_NS_FC4_FEATURES,
	.parse_key = fc_ns_fc4_feature_key_parse,
	.transcribe_key = fc_ns_fc4_feature_key_transcribe,
	.compare_key = fc_ns_fc4_feature_key_compare,
	.parse_value = fc_ns_fc4_feature_value_parse,
	.transcribe_value = fc_ns_fc4_feature_value_transcribe,
	.store_value = fc_ns_fc4_feature_value_store,
};

/** Fibre Channel name server object types */
static struct fc_ns_object_type * fc_ns_object_types[16] = {
	[FC_NS_PORT_ID] = &fc_ns_port_id_type,
	[FC_NS_PORT_NAME] = &fc_ns_port_name_type,
	[FC_NS_NODE_NAME] = &fc_ns_node_name_type,
	[FC_NS_FC4_TYPES] = &fc_ns_fc4_types_type,
	[FC_NS_SYM_PORT_NAME] = &fc_ns_sym_port_name_type,
	[FC_NS_SYM_NODE_NAME] = &fc_ns_sym_node_name_type,
	[FC_NS_FC4_FEATURES] = &fc_ns_fc4_features_type,
};

/** List of all name server object sets */
static LIST_HEAD ( fc_ns_object_sets );

/**
 * Add name server object set
 *
 * @v port_id		Port ID
 * @v port_wwn		Port name
 * @ret objects		Object set
 */
static struct fc_ns_object_set *
fc_ns_add_object_set ( struct fc_port_id *port_id, struct fc_name *port_wwn ) {
	struct fc_ns_object_set *objects;

	objects = malloc ( sizeof ( *objects ) );
	if ( ! objects )
		return NULL;
	memset ( objects, 0, sizeof ( *objects ) );
	list_add ( &objects->list, &fc_ns_object_sets );
	memcpy ( &objects->port_id, port_id, sizeof ( objects->port_id ) );
	memcpy ( &objects->port_name, port_wwn,
		 sizeof ( objects->port_name ) );

	return objects;
}

/**
 * Remove name server object set
 *
 * @v port_id		Port ID
 */
static void fc_ns_remove_object_set ( struct fc_port_id *port_id ) {
	struct fc_ns_object_set *objects;

	list_for_each_entry ( objects, &fc_ns_object_sets, list ) {
		if ( memcmp ( &objects->port_id, port_id,
			      sizeof ( objects->port_id ) ) == 0 ) {
			list_del ( &objects->list );
			free ( objects );
			return;
		}
	}
}

/**
 * Describe name service code
 *
 * @v code		Name service code
 * @ret code_text	Name service code name
 */
static const __attribute__ (( unused )) char *
fc_ns_code_text ( unsigned int code ) {
	static const char * fc_ns_commands[16] = {
		[FC_NS_GET] = "G",
		[FC_NS_REGISTER] = "R",
		[FC_NS_DEREGISTER] = "D",
	};
	const char *command;
	struct fc_ns_object_type *key_type;
	struct fc_ns_object_type *value_type;
	static char buf[16];

	command = fc_ns_commands[ FC_NS_COMMAND ( code ) ];
	key_type = fc_ns_object_types[ FC_NS_KEY ( code ) ];
	value_type = fc_ns_object_types[ FC_NS_VALUE ( code ) ];
	snprintf ( buf, sizeof ( buf ), "%s%s_%s",
		   ( command ? command : "?" ),
		   ( value_type ? value_type->name : "??" ),
		   ( key_type ? key_type->name : "??" ) );
	return buf;
}

/**
 * Receive name service REGISTER frame
 *
 * @v fchdr		Fibre Channel frame
 * @v key_type		Name server key type
 * @v key		Name server key
 * @v value_type	Name server value type
 * @v value		Name server value
 * @ret rc		Return status code
 */
static int fc_ns_rx_register ( struct fc_frame_header *fchdr,
			       struct fc_ns_object_type *key_type, void *key,
			       struct fc_ns_object_type *value_type,
			       void *value ) {
	struct fc_ns_object_set *objects;
	struct {
		struct fc_frame_header fchdr;
		struct fc_ct_header cthdr;
	} __attribute__ (( packed )) frame;

	/* Locate object set */
	list_for_each_entry ( objects, &fc_ns_object_sets, list ) {
		if ( key_type->compare_key ( key, objects ) != 0 )
			continue;

		/* Register object */
		if ( value_type->store_value ( value, objects ) != 0 ) {
			logmsg ( LOG_ERR, "FC NS could not register %s\n",
				 value_type->name );
			return -1;
		}
	}

	/* Construct response frame */
	memset ( &frame, 0, sizeof ( frame ) );
	frame.fchdr.r_ctl = ( FC_R_CTL_DATA | FC_R_CTL_SOL_CTRL );
	memcpy ( &frame.fchdr.d_id, &fchdr->s_id,
		 sizeof ( frame.fchdr.d_id ) );
	memcpy ( &frame.fchdr.s_id, &fc_gs_port_id,
		 sizeof ( frame.fchdr.s_id ) );
	frame.fchdr.type = FC_TYPE_CT;
	frame.fchdr.f_ctl_es = ( FC_F_CTL_ES_RESPONDER |
				 FC_F_CTL_ES_END | FC_F_CTL_ES_LAST );
	frame.fchdr.ox_id = fchdr->ox_id;
	frame.fchdr.rx_id = random();
	frame.cthdr.revision = FC_CT_REVISION;
	frame.cthdr.type = FC_GS_TYPE_DS;
	frame.cthdr.subtype = FC_DS_SUBTYPE_NAME;
	frame.cthdr.code = htons ( FC_GS_ACCEPT );

	/* Transmit frame */
	return fc_tx ( &frame.fchdr, sizeof ( frame ) );
}

/**
 * Receive name service GET frame
 *
 * @v fchdr		Fibre Channel frame
 * @v key_type		Name server key type
 * @v key		Name server key
 * @v value_type	Name server value type
 * @ret rc		Return status code
 */
static int fc_ns_rx_get ( struct fc_frame_header *fchdr,
			  struct fc_ns_object_type *key_type, void *key,
			  struct fc_ns_object_type *value_type ) {
	struct fc_ct_header *cthdr = ( ( void * ) ( fchdr + 1 ) );
	struct fc_ns_object_set *objects;
	size_t cthdrsize = ntohs ( cthdr->size );
	size_t bufsize = ( (( cthdrsize > 0 ) && ( cthdrsize < FC_NS_BUFSIZE ))
			   ? cthdrsize : FC_NS_BUFSIZE );
	struct {
		struct fc_frame_header fchdr;
		struct fc_ct_header cthdr;
		char buf[bufsize];
	} __attribute__ (( packed )) frame;
	struct fc_ns_multi *multi = NULL;
	void *data = &frame.buf;
	size_t len = sizeof ( frame.buf );
	size_t used = 0;
	int value_len;

	/* Fetch all values */
	memset ( &frame, 0, sizeof ( frame ) );
	list_for_each_entry ( objects, &fc_ns_object_sets, list ) {
		if ( key_type->compare_key ( key, objects ) != 0 )
			continue;
		/* Add multi-response prefix if applicable */
		if ( value_type->specificity > key_type->specificity ) {
			if ( len < sizeof ( *multi ) ) {
				logmsg ( LOG_ERR, "FC NS out of space "
					 "fetching %s for " FC_PORT_ID_FMT "\n",
					 value_type->name,
					 FC_PORT_ID_ARGS ( &objects->port_id ));
				return -1;
			}
			multi = data;
			memcpy ( &multi->port_id, &objects->port_id,
				 sizeof ( multi->port_id ) );
			data += sizeof ( *multi );
			len -= sizeof ( *multi );
			used += sizeof ( *multi );
		}
		/* Add padding if necessary */
		if ( multi && ( value_type != &fc_ns_port_id_type ) ) {
			if ( len < FC_NS_MULTI_PAD_LEN ) {
				logmsg ( LOG_ERR, "FC NS out of space "
					 "fetching %s for " FC_PORT_ID_FMT "\n",
					 value_type->name,
					 FC_PORT_ID_ARGS ( &objects->port_id ));
				return -1;
			}
			data += FC_NS_MULTI_PAD_LEN;
			len -= FC_NS_MULTI_PAD_LEN;
			used += FC_NS_MULTI_PAD_LEN;
		}
		/* Add value if necessary */
		if ( ( value_type != &fc_ns_port_id_type ) || ( ! multi ) ) {
			value_len = value_type->fetch_value ( objects, data,
							      len );
			if ( value_len < 0 ) {
				logmsg ( LOG_ERR, "FC NS could not fetch %s "
					 "for " FC_PORT_ID_FMT "\n",
					 value_type->name,
					 FC_PORT_ID_ARGS ( &objects->port_id ));
			}
			data += value_len;
			len -= value_len;
			used += value_len;
		}
	}
	if ( multi )
		multi->control = FC_NS_MULTI_LAST;

	/* Construct response frame */
	frame.fchdr.r_ctl = ( FC_R_CTL_DATA | FC_R_CTL_SOL_CTRL );
	memcpy ( &frame.fchdr.d_id, &fchdr->s_id,
		 sizeof ( frame.fchdr.d_id ) );
	memcpy ( &frame.fchdr.s_id, &fc_gs_port_id,
		 sizeof ( frame.fchdr.s_id ) );
	frame.fchdr.type = FC_TYPE_CT;
	frame.fchdr.f_ctl_es = ( FC_F_CTL_ES_RESPONDER |
				 FC_F_CTL_ES_END | FC_F_CTL_ES_LAST );
	frame.fchdr.ox_id = fchdr->ox_id;
	frame.fchdr.rx_id = random();
	frame.cthdr.revision = FC_CT_REVISION;
	frame.cthdr.type = FC_GS_TYPE_DS;
	frame.cthdr.subtype = FC_DS_SUBTYPE_NAME;
	frame.cthdr.code =
		( used ? htons ( FC_GS_ACCEPT ) : htons ( FC_GS_REJECT ) );
	frame.cthdr.reason = FC_GS_UNABLE;
	frame.cthdr.explanation = key_type->code;

	/* Transmit frame */
	return fc_tx ( &frame.fchdr,
		       ( offsetof ( typeof ( frame ), buf ) + used ) );
}

/**
 * Receive name service frame
 *
 * @v fchdr		Fibre Channel frame
 * @v len		Length of Fibre Channel frame
 * @ret rc		Return status code
 */
static int fc_ns_rx ( struct fc_frame_header *fchdr, size_t len ) {
	struct fc_ct_header *cthdr = ( ( void * ) ( fchdr + 1 ) );
	unsigned int code = ntohs ( cthdr->code );
	unsigned int command = FC_NS_COMMAND ( code );
	struct fc_ns_object_type *key_type;
	struct fc_ns_object_type *value_type;
	void *data;
	void *key;
	void *value;
	int key_len;
	int value_len;
	char key_buf[256];
	char value_buf[256];

	/* Extract key */
	data = ( cthdr + 1 );
	len = ( len - sizeof ( *fchdr ) - sizeof ( *cthdr ) );
	key_type = fc_ns_object_types[ FC_NS_KEY ( code ) ];
	if ( ! key_type ) {
		logmsg ( LOG_ERR, "FC NS received %s for unknown key "
			 "type 0x%x\n", fc_ns_code_text ( code ),
			 FC_NS_KEY ( code ) );
		return -1;
	}
	if ( ! key_type->parse_key ) {
		logmsg ( LOG_ERR, "FC NS received %s for unsupported key "
			 "type 0x%x\n", fc_ns_code_text ( code ),
			 FC_NS_KEY ( code ) );
		return -1;
	}
	if ( ! key_type->compare_key ) {
		logmsg ( LOG_ERR, "FC NS received %s for unusable key type "
			 "0x%x\n", fc_ns_code_text ( code ),
			 FC_NS_KEY ( code ) );
		return -1;
	}
	key = data;
	key_len = key_type->parse_key ( key, len );
	if ( key_len < 0 ) {
		logmsg ( LOG_ERR, "FC NS received %s with invalid key type "
			 "0x%x\n", fc_ns_code_text ( code ),
			 FC_NS_KEY ( code ) );
		return -1;
	}
	data += key_len;
	len -= key_len;
	assert ( key_type->transcribe_key );
	key_type->transcribe_key ( key, key_buf, sizeof ( key_buf ) );

	/* Extract value */
	value_type = fc_ns_object_types[ FC_NS_VALUE ( code ) ];
	if ( ! value_type ) {
		logmsg ( LOG_ERR, "FC NS received %s for unknown value "
			 "type 0x%x\n", fc_ns_code_text ( code ),
			 FC_NS_VALUE ( code ) );
		return -1;
	}
	if ( command == FC_NS_GET ) {
		if ( ! value_type->fetch_value ) {
			logmsg ( LOG_ERR, "FC NS received %s for unusable "
				 "value type 0x%x\n", fc_ns_code_text ( code ),
				 FC_NS_VALUE ( code ) );
			return -1;
		}
		logmsg ( LOG_INFO, "FC NS get %s for %s %s\n",
			 value_type->name, key_type->name, key_buf );
		return fc_ns_rx_get ( fchdr, key_type, key, value_type );
	} else if ( command == FC_NS_REGISTER ) {
		if ( ! value_type->parse_value ) {
			logmsg ( LOG_ERR, "FC NS received %s for unsupported "
				 "value type 0x%x\n", fc_ns_code_text ( code ),
				 FC_NS_VALUE ( code ) );
			return -1;
		}
		value = data;
		value_len = value_type->parse_value ( value, len );
		if ( value_len < 0 ) {
			logmsg ( LOG_ERR, "FC NS received %s with invalid "
				 "value type 0x%x\n", fc_ns_code_text ( code ),
				 FC_NS_VALUE ( code ) );
			return -1;
		}
		if ( ! value_type->store_value ) {
			logmsg ( LOG_ERR, "FC NS cannot register %s\n",
				 value_type->name );
			return -1;
		}
		data += value_len;
		len -= value_len;
		assert ( value_type->transcribe_value );
		value_type->transcribe_value ( value, value_buf,
					       sizeof ( value_buf ) );
		logmsg ( LOG_INFO, "FC NS register %s %s for %s %s\n",
			 value_type->name, value_buf, key_type->name,
			 key_buf );
		return fc_ns_rx_register ( fchdr, key_type, key, value_type,
					   value );
	} else {
		logmsg ( LOG_ERR, "FC NS received unsupported code %#04x "
			 "(%s)\n", code, fc_ns_code_text ( code ) );
		return -1;
	}
}

/**
 * Receive directory service frame
 *
 * @v fchdr		Fibre Channel frame
 * @v len		Length of Fibre Channel frame
 * @ret rc		Return status code
 */
static int fc_ds_rx ( struct fc_frame_header *fchdr, size_t len ) {
	struct fc_ct_header *cthdr = ( ( void * ) ( fchdr + 1 ) );

	switch ( cthdr->subtype ) {
	case FC_DS_SUBTYPE_NAME:
		return fc_ns_rx ( fchdr, len );
	default:
		logmsg ( LOG_ERR, "FC DS received unsupported subtype 0x%02x\n",
			 cthdr->subtype );
		return -1;
	}
}

/**
 * Receive generic service CT frame
 *
 * @v fchdr		Fibre Channel frame
 * @v len		Length of Fibre Channel frame
 * @ret rc		Return status code
 */
static int fc_gs_rx_ct ( struct fc_frame_header *fchdr, size_t len ) {
	struct fc_ct_header *cthdr = ( ( void * ) ( fchdr + 1 ) );

	switch ( cthdr->type ) {
	case FC_GS_TYPE_DS:
		return fc_ds_rx ( fchdr, len );
	default:
		logmsg ( LOG_ERR, "FC GS received unsupported type 0x%02x\n",
			 cthdr->type );
		return -1;
	}
}

/**
 * Receive generic service PLOGI frame
 *
 * @v fchdr		Fibre Channel frame
 * @v len		Length of Fibre Channel frame
 * @ret rc		Return status code
 */
static int fc_gs_rx_plogi ( struct fc_frame_header *fchdr,
			    size_t len __unused ) {
	struct fc_login_frame *plogi = ( ( void * ) ( fchdr + 1 ) );
	struct {
		struct fc_frame_header fchdr;
		struct fc_login_frame plogi;
	} __attribute__ (( packed )) frame;

	logmsg ( LOG_INFO, "FC GS PLOGI from ID " FC_PORT_ID_FMT " PN "
		 FC_NAME_FMT "\n", FC_PORT_ID_ARGS ( &fchdr->s_id ),
		 FC_NAME_ARGS ( &plogi->port_wwn ) );

	/* Remove any existing name server object set */
	fc_ns_remove_object_set ( &fchdr->s_id );

	/* Create name server object set */
	if ( ! fc_ns_add_object_set ( &fchdr->s_id, &plogi->port_wwn ) ) {
		logmsg ( LOG_ERR, "FC GS could not create NS object group for "
			 FC_PORT_ID_FMT "\n",
			 FC_PORT_ID_ARGS ( &fchdr->s_id ) );
		return -1;
	}

	/* Construct response frame */
	memset ( &frame, 0, sizeof ( frame ) );
	frame.fchdr.r_ctl = ( FC_R_CTL_ELS | FC_R_CTL_SOL_CTRL );
	memcpy ( &frame.fchdr.d_id, &fchdr->s_id,
		 sizeof ( frame.fchdr.d_id ) );
	memcpy ( &frame.fchdr.s_id, &fc_gs_port_id,
		 sizeof ( frame.fchdr.s_id ) );
	frame.fchdr.type = FC_TYPE_ELS;
	frame.fchdr.f_ctl_es = ( FC_F_CTL_ES_RESPONDER |
				 FC_F_CTL_ES_END | FC_F_CTL_ES_LAST );
	frame.fchdr.ox_id = fchdr->ox_id;
	frame.fchdr.rx_id = random();
	frame.plogi.command = FC_ELS_LS_ACC;
	frame.plogi.common.version = htons ( FC_LOGIN_VERSION );
	frame.plogi.common.credit = htons ( FC_LOGIN_DEFAULT_B2B );
	frame.plogi.common.flags = htons ( FC_LOGIN_CONTINUOUS_OFFSET );
	frame.plogi.common.mtu = htons ( FC_LOGIN_DEFAULT_MTU );
	frame.plogi.common.u.plogi.max_seq =
		htons ( FC_LOGIN_DEFAULT_MAX_SEQ );
	frame.plogi.common.u.plogi.rel_offs =
		htons ( FC_LOGIN_DEFAULT_REL_OFFS );
	frame.plogi.common.e_d_tov = htonl ( FC_LOGIN_DEFAULT_E_D_TOV );
	memcpy ( &frame.plogi.port_wwn, &fc_f_port_wwn,
		 sizeof ( frame.plogi.port_wwn ) );
	memcpy ( &frame.plogi.node_wwn, &fc_f_node_wwn,
		 sizeof ( frame.plogi.node_wwn ) );
	frame.plogi.class3.flags = htons ( FC_LOGIN_CLASS_VALID |
					   FC_LOGIN_CLASS_SEQUENTIAL );
	frame.plogi.class3.mtu = htons ( FC_LOGIN_DEFAULT_MTU );
	frame.plogi.class3.max_seq = htons ( FC_LOGIN_DEFAULT_MAX_SEQ );
	frame.plogi.class3.max_seq_per_xchg = 1;

	/* Transmit frame */
	return fc_tx ( &frame.fchdr, sizeof ( frame ) );
}

/**
 * Receive generic service ELS frame
 *
 * @v fchdr		Fibre Channel frame
 * @v len		Length of Fibre Channel frame
 * @ret rc		Return status code
 */
static int fc_gs_rx_els ( struct fc_frame_header *fchdr, size_t len ) {
	struct fc_els_frame_common *fcels = ( ( void * ) ( fchdr + 1 ) );

	switch ( fcels->command ) {
	case FC_ELS_PLOGI:
		return fc_gs_rx_plogi ( fchdr, len );
	default:
		logmsg ( LOG_ERR, "FC GS received unsupported ELS command "
			 "0x%02x\n", fcels->command );
		return -1;
	}
}

/**
 * Receive generic service frame
 *
 * @v fchdr		Fibre Channel frame
 * @v len		Length of Fibre Channel frame
 * @ret rc		Return status code
 */
int fc_gs_rx ( struct fc_frame_header *fchdr, size_t len ) {

	switch ( fchdr->type ) {
	case FC_TYPE_ELS :
		return fc_gs_rx_els ( fchdr, len );
	case FC_TYPE_CT :
		return fc_gs_rx_ct ( fchdr, len );
	default:
		logmsg ( LOG_ERR, "FC GS received unsupported frame type "
			 "0x%02x\n", fchdr->type );
		return -1;
	}
}
