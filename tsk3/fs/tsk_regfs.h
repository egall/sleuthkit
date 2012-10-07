/*
** The Sleuth Kit 
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
** 
** This software is distributed under the Common Public License 1.0 
*/

/*
 * Contains the structures and function APIs for Windows Registry support.
 */

#ifndef _TSK_REGFS_H
#define _TSK_REGFS_H

#ifdef __cplusplus
extern "C" {
#endif


/** \internal
 * Only used to extract fields from a bufffer.
 */
typedef struct {
/* 0x00 */    uint8_t magic[4];    ///< "REGF", or 0x66676572
/* 0x04 */    uint8_t seq1[4];     ///< if seq1 == seq2, then the Registry is syncronized
/* 0x08 */    uint8_t seq2[4];     ///< if seq1 == seq2, then the Registry is syncronized
/* 0x0C */    uint8_t ignored0[4]; ///< Unusued for parsing.
/* 0x10 */    uint8_t ignored1[4]; ///< Unusued for parsing.
/* 0x14 */    uint8_t major_version[4];
/* 0x18 */    uint8_t minor_version[4];
/* 0x1C */    uint8_t ignored2[4]; ///< Unusued for parsing.
/* 0x20 */    uint8_t ignored3[4]; ///< Unusued for parsing.
/* 0x24 */    uint8_t first_key_offset[4]; ///< HBIN[1] + first_key_offset == first key
/* 0x28 */    uint8_t last_hbin_offset[4];
/* 0x2C */    uint8_t ignored4[4];    ///< Unusued for parsing.
/* 0x30 */    uint8_t hive_name[64]; ///< in unicode. TODO(wb): find exact length
} REGF_template;

typedef struct {
    uint32_t magic;    ///< "REGF", or 0x66676572
    uint32_t seq1;     ///< if seq1 == seq2, then the Registry is syncronized
    uint32_t seq2;     ///< if seq1 == seq2, then the Registry is syncronized
    uint32_t major_version;
    uint32_t minor_version;
    uint32_t first_key_offset; ///< HBIN[1] + first_key_offset == first key
    uint32_t last_hbin_offset;
    uint8_t hive_name[64]; ///< in unicode. TODO(wb): find exact length
} REGF;

typedef struct {
    TSK_FS_INFO fs_info;    /* super class */
    REGF regf;
} REGFS_INFO;

#ifdef __cplusplus
}
#endif
#endif
