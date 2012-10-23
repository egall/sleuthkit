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
#define FIRST_HBIN_OFFSET 4096


  enum TSK_REGFS_RECORD_TYPE_ENUM {
    TSK_REGFS_RECORD_TYPE_NK,  ///< "nk" 0x6b6e The main nodes in the tree. 
    TSK_REGFS_RECORD_TYPE_VK,  ///< "vk" 0x6b76
    TSK_REGFS_RECORD_TYPE_LF,  ///< "lf" 0x666c
    TSK_REGFS_RECORD_TYPE_LH,  ///< "lh" 0x686c
    TSK_REGFS_RECORD_TYPE_LI,  ///< "li" 0x696c
    TSK_REGFS_RECORD_TYPE_RI,  ///< "ri" 0x6972
    TSK_REGFS_RECORD_TYPE_SK,  ///< "sk" 0x6b73
    TSK_REGFS_RECORD_TYPE_DB,  ///< "db" 0x6264
    TSK_REGFS_RECORD_TYPE_UNKNOWN,  ///< Unknown type, or data block.
  };
  typedef enum TSK_REGFS_RECORD_TYPE_ENUM TSK_REGFS_RECORD_TYPE_ENUM;

  typedef struct REGFS_CELL {
    TSK_INUM_T inum;  ///< Inode number (address) of cell.
    uint8_t  is_allocated; ///< 1 if active, 0 otherwise.
    uint32_t length; ///< Length of cell, including all headers.
    TSK_REGFS_RECORD_TYPE_ENUM type;  ///< The type of the contents of the cell.
  } REGFS_CELL;

    typedef struct REGFS_CELL_NK {
/*  0x00 */  uint8_t magic[0x2];    ///< "nk"
/*  0x02 */  uint8_t is_root[0x2];  ///< if == 0x2C, then a root key
/*  0x04 */  uint8_t timestamp[0x8];
/*  0x0C */  uint8_t unused1[0x4];
/*  0x10 */  uint8_t parent_nk_offset[0x4]; ///< Offset relative to first HBIN start
/*  0x14 */  uint8_t num_subkeys[0x4]; ///< 0xFFFFFFFF == 0
/*  0x18 */  uint8_t unused4[0x4];
/*  0x1C */  uint8_t subkey_list_offset[0x4]; ///< Offset relative to first HBIN start
/*  0x20 */  uint8_t unused6[0x4];
/*  0x24 */  uint8_t num_values[0x4];
/*  0x28 */  uint8_t values_list_offset[0x4]; ///< Offset relative to first HBIN start
/*  0x2C */  uint8_t sk_record_offset[0x4]; ///< Offset relative to first HBIN start
/*  0x30 */  uint8_t classname_offset[0x4]; ///< Offset relative to first HBIN start to a data record containing the classname in Unicode
/*  0x34 */  uint8_t unused7[0x4];
/*  0x38 */  uint8_t unused8[0x4];
/*  0x3C */  uint8_t unused9[0x4];
/*  0x40 */  uint8_t unused10[0x4];
/*  0x44 */  uint8_t unused11[0x4];
/*  0x48 */  uint8_t name_length[0x2];
/*  0x4A */  uint8_t classname_length[0x2]; ///< In bytes, but classname is Unicode
/*  0x4C */  uint8_t name_offset[0x4]; ///< Offset relative to record start
    } REGFS_CELL_NK;

  /** \internal
   * Total size: 4096 bytes.
   */
  typedef struct {
/* 0x00 */    uint8_t magic[4];    ///< "REGF", or 0x66676572
/* 0x04 */    uint8_t seq1[4];     ///< if seq1 == seq2, then the Registry is sync'd
/* 0x08 */    uint8_t seq2[4];     ///< if seq1 == seq2, then the Registry is sync'd
/* 0x0C */    uint8_t ignored0[4]; ///< Unusued for parsing.
/* 0x10 */    uint8_t ignored1[4]; ///< Unusued for parsing.
/* 0x14 */    uint8_t major_version[4];
/* 0x18 */    uint8_t minor_version[4];
/* 0x1C */    uint8_t ignored2[4]; ///< Unusued for parsing.
/* 0x20 */    uint8_t ignored3[4]; ///< Unusued for parsing.
/* 0x24 */    uint8_t first_key_offset[4]; ///< Relative to start of first HBIN
/* 0x28 */    uint8_t last_hbin_offset[4]; ///< Absolute file offset
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
