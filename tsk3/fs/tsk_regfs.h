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

#define REG_REGF_MAGIC 0x66676572


#define HBIN_SIZE 4096



  enum TSK_REGFS_RECORD_TYPE_ENUM {
    TSK_REGFS_RECORD_TYPE_VK,  ///< "vk" 0x766b
    TSK_REGFS_RECORD_TYPE_NK,  ///< "nk" 0x6e6b 
    TSK_REGFS_RECORD_TYPE_LF,  ///< "lf" 0x6c66 
    TSK_REGFS_RECORD_TYPE_LH,  ///< "lh" 0x6c68  
    TSK_REGFS_RECORD_TYPE_LI,  ///< "li" 0x6c69   
    TSK_REGFS_RECORD_TYPE_RI,  ///< "ri" 0x7269    
    TSK_REGFS_RECORD_TYPE_SK,  ///< "sk" 0x736b     
    TSK_REGFS_RECORD_TYPE_DB,  ///< "db" 0x6462      
    TSK_REGFS_RECORD_TYPE_UNKNOWN,  ///< Unknown type, of course.
  };
  typedef enum TSK_REGFS_RECORD_TYPE_ENUM TSK_REGFS_RECORD_TYPE_ENUM;

  typedef struct REGFS_CELL {
    uint8_t  is_allocated;
    uint32_t length;
    TSK_REGFS_RECORD_TYPE_ENUM type;
  } REGFS_CELL;


  /** \internal
   * Total size: 4096 bytes.
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
/* 0x70 */    uint8_t ignored[HBIN_SIZE - 0x70];
  } REGF;

  typedef struct {
    TSK_FS_INFO fs_info;    /* super class */
    REGF regf;
    
    uint8_t synchronized;
    TSK_DADDR_T first_key_offset;
    TSK_DADDR_T last_hbin_offset;
  } REGFS_INFO;

#ifdef __cplusplus
}
#endif
#endif
