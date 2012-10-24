/*
** The Sleuth Kit 
**
** Willi Ballenthin [william.ballenthin <at> mandiant [dot] com]
** Copyright (c) 2012 Willi Ballenthin.  All rights reserved
**
** This software is distributed under the Common Public License 1.0 
*/

/*
 * Contains the structures and function APIs for Windows Registry support.
 * 
 * HACKING
 *   Blocks --> Cells
 *   Inodes --> Records
 *   Now, Records are typically stored in one Cell, and the cell consists
 *     of nothing extra besides the `length` header.  Both Cells and 
 *     Records may have dynamic sizes (eg. not fixed at 0x20, or 0x30).
 *     A large record, such as a data record, may be split among a few
 *     Cells.  
 *   The Registry provides offsets to structures as Cell offsets.
 *     The context of the function call or data structure will determine
 *     if an offset refers to a Cell or Record.
 *   Use `tsk_malloc` over `malloc`. It zeros memory, too.
 *   Use `tsk_remalloc` over `remalloc`.
 *   Use `free` as usual.
 * 
 *   Functions, and their uses:
 *     fs->open
 *       Allocates a REGFS_INFO structure on the heap.
 *       Sets the appropriate function pointers.
 *       Sets basic file system metadata in the REGFS_INFO structure.
 *     fs->close
 *       Frees a REGFS_INFO structure.
 *     fs->block_walk
 *       Iterates through each Cell, and calls a callback function 
 *       with the TSK_FS_BLOCK pointer for the Cell. Only Cells whose
 *       attributes match a set of filter flags are passed to the 
 *       callback.  Flags include ALLOC'd and UNALLOC'd.
 *     fs->block_getflags
 *       Get the flags associated with a particular Cell.
 *       Flags include ALLOC'd and UNALLOC'd.
 *     fs->inode_walk
 *       Iterates through each Record, and calls a callback function 
 *       with the TSK_FS_FILE pointer for the Record. Only Records whose
 *       attributes match a set of filter flags are passed to the 
 *       callback.  Flags include ALLOC'd and UNALLOC'd.
 *     fs->istat
 *       Use tsk_fs_file_open_meta to acquire a TSK_FS_FILE pointer
 *       for the requested Record.  Then, print out relevant data.
 *     fs->file_add_meta
 *       Given a TSK_FS_FILE, allocate memory (if necessary) for the
 *       metadata stored in TSK_FS_META substructure using 
 *       tsk_fs_meta_alloc.  This structure may also be reset by 
 *       tsk_fs_meta_reset.  Then, set relevant metadata for the
 *       TSK_FS_META substructure.
 *     fs->get_default_attr_type
 *       Given a TSK_FS_FILE, return the default attribute type.
 *       This is probably TSK_FS_ATTR_TYPE_DEFAULT.
 *     fs->load_attrs
 *       Load data locations for a Record into runs.  This is how TSK will 
 *       access the data for a Record if you request it.
 *     fs->dir_open_meta
 *       Allocate (with tsk_fs_dir_alloc) or reset a TSK_FS_DIR structure,
 *       set the TSK_FS_FILE substructure, and add the names of entries
 *       in the directory as TSK_FS_NAME structures (which have inode
 *       numbers).
 *     fs->name_cmp
 *       Compare two key names or value names case insensitively.
 *     fs->fsstat
 *       Print relevant information about the Registry file.
 *     fs->fscheck
 *       Unsupported.
 *     fs->jblk_walk
 *       There is no journal in the Registry. Unsupported.
 *     fs->jentry_walk
 *       There is no journal in the Registry. Unsupported.
 *     fs->jopen
 *       There is no journal in the Registry. Unsupported.
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
/*  0x4C */  uint8_t name[0x4]; ///< This may have a variable length
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
