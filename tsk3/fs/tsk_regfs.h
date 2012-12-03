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
 *   Blocks --> HBINS
 *   Inodes --> Cells (that contain Records)
 *   Once upon a time Blocks were translated to Cells, and Inodes to 
 *     Records.  This didn't work in TSK, because the framework expects
 *     filesystems to have a constant blocksize.  Rather than retro-fitting
 *     additional support for dynamic blocksizes, we call HBINs Blocks.
 *     HBINS have a constant size (at least, as far as anyone has seen), 
 *     and are the smallest structures in the Registy where this is the case.
 *   Cells are allocation units with dynamic sizes.  They are basically 
 *     just a buffer which an initial 4 byte length field. Records typically
 *     fit within one Cell; however, this is not guaranteed for large values.
 *   Offsets within the Registry point to the start of a Cell.
 *   Block numbers are multiples of 4096, since the size of an HBIN is 4096.
 *   Consider an Inode a Cell that contains a Record. 
 *   Inode numbers are the absolute offset in bytes of the start of a cell.
 *   Use `tsk_malloc` over `malloc`. It zeros memory, too.
 *   Use `tsk_remalloc` over `remalloc`.
 *   Use `free` as usual.
 *   When catching an error from another TSK function, don't reset 
 *     the errno, unless you're changing it. 
 * 
 *   Functions, and their uses:
 *     [x] fs->open
 *       Allocates a REGFS_INFO structure on the heap.
 *       Sets the appropriate function pointers.
 *       Sets basic file system metadata in the REGFS_INFO structure.
 *     [x] fs->close
 *       Frees a REGFS_INFO structure.
 *     [-] fs->block_walk
 *       Iterates through each HBIN, and calls a callback function 
 *       with the TSK_FS_BLOCK pointer for the HBIN. Only HBIN whose
 *       attributes match a set of filter flags are passed to the 
 *       callback.  Flags include ALLOC'd and UNALLOC'd.  
 *       UNALLOC'd block are found at the slack space at the end of
 *       the Registry file, where the magic header doesn match "hbin".
 *     [x] fs->block_getflags
 *       Get the flags associated with a particular Cell.
 *       Flags include ALLOC'd and UNALLOC'd.
 *     [x] fs->inode_walk
 *       Iterates through each Record, and calls a callback function 
 *       with the TSK_FS_FILE pointer for the Record. Only Records whose
 *       attributes match a set of filter flags are passed to the 
 *       callback.  Flags include ALLOC'd and UNALLOC'd.
 *     [-] fs->istat
 *       Use tsk_fs_file_open_meta to acquire a TSK_FS_FILE pointer
 *       for the requested Record.  Then, print out relevant data.
 *     [x] fs->file_add_meta
 *       Given a TSK_FS_FILE, allocate memory (if necessary) for the
 *       metadata stored in TSK_FS_META substructure using 
 *       tsk_fs_meta_alloc.  This structure may also be reset by 
 *       tsk_fs_meta_reset.  Then, set relevant metadata for the
 *       TSK_FS_META substructure.
 *     [x] fs->get_default_attr_type
 *       Given a TSK_FS_FILE, return the default attribute type.
 *       This is probably TSK_FS_ATTR_TYPE_DEFAULT.
 *     [ ] fs->load_attrs
 *       Load data locations for a Record into runs.  This is how TSK will 
 *       access the data for a Record if you request it.
 *       Because we do not use multiples of the block unit for data runs,
 *       all data must be resident.  In the case of the Registry, this is
 *       alright, since we expect to be able to load the Registry into memory.
 *       But it does mean we load all data up for each VK record, even if it
 *       uses DB indirect records (which would more correctly be nonresident).
 *     [x] fs->dir_open_meta
 *       Allocate (with tsk_fs_dir_alloc) or reset a TSK_FS_DIR structure,
 *       set the TSK_FS_FILE substructure, and add the names of entries
 *       in the directory as TSK_FS_NAME structures (which have inode
 *       numbers).
 *     [x] fs->name_cmp
 *       Compare two key names or value names case insensitively.
 *     [x] fs->fsstat
 *       Print relevant information about the Registry file.
 *     [x] fs->fscheck
 *       Unsupported.
 *     [x] fs->jblk_walk
 *       There is no journal in the Registry. Unsupported.
 *     [x] fs->jentry_walk
 *       There is no journal in the Registry. Unsupported.
 *     [x] fs->jopen
 *       There is no journal in the Registry. Unsupported.
 */

#ifndef _TSK_REGFS_H
#define _TSK_REGFS_H

#ifdef __cplusplus
extern "C" {
#endif

#define REG_REGF_MAGIC 0x66676572

/// this is, uhhh, from experience?
#define MAX_KEY_NAME_LENGTH 1024 

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
    TSK_INUM_T inum; ///< Inode number (address) of cell.
    uint8_t  is_allocated; ///< 1 if active, 0 otherwise.
    TSK_REGFS_RECORD_TYPE_ENUM type;  ///< The type of the contents of the cell.
    uint32_t length; ///< Length of cell (not this structure), including all headers.
    uint8_t data;    ///< The data of the cell, with length `.length`. Contains the entire data, including Size, Magic, then Data.
  } REGFS_CELL;

    typedef struct REGFS_CELL_NK {
/* -0x04 */  uint8_t size[0x4];    ///< negative if allocated
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

  typedef enum TSK_REGFS_VALUE_TYPE {
    TSK_REGFS_VALUE_TYPE_REGNONE = 0x0,
    TSK_REGFS_VALUE_TYPE_REGSZ = 0x1,
    TSK_REGFS_VALUE_TYPE_REGEXPANDSZ = 0x2,
    TSK_REGFS_VALUE_TYPE_REGBIN = 0x3,
    TSK_REGFS_VALUE_TYPE_REGDWORD = 0x4,
    TSK_REGFS_VALUE_TYPE_REGBIGENDIAN = 0x5,
    TSK_REGFS_VALUE_TYPE_REGLINK = 0x6,
    TSK_REGFS_VALUE_TYPE_REGMULTISZ = 0x7,
    TSK_REGFS_VALUE_TYPE_REGRESOURCELIST = 0x8,
    TSK_REGFS_VALUE_TYPE_REGFULLRESOURCEDESCRIPTOR = 0x9,
    TSK_REGFS_VALUE_TYPE_REGRESOURCEREQUIREMENTLIST = 0xA,
    TSK_REGFS_VALUE_TYPE_REGQWORD = 0xB,
  } TSK_REGFS_VALUE_TYPE;

  typedef struct REGFS_CELL_VK {
/* -0x04 */  uint8_t size[0x4];         ///< negative if allocated
/*  0x00 */  uint8_t magic[0x2];        ///< "vk"
/*  0x02 */  uint8_t name_length[0x2];
/*  0x04 */  uint8_t value_length[0x4];
/*  0x08 */  uint8_t value_offset[0x4]; ///< relative to first hbin
/*  0x0C */  uint8_t value_type[0x4];   ///< possible values: TSK_REGFS_VALUE_TYPE
/*  0x10 */  uint8_t flags[0x4];
/*  0x14 */  uint8_t name[0x4];
  } REGFS_CELL_VK;

    typedef struct REGFS_CELL_LF {
/* -0x04 */  uint8_t size[0x4];        ///< negative if allocated
/*  0x00 */  uint8_t magic[0x2];       ///< "lf"
/*  0x02 */  uint8_t num_offsets[0x2];
/*  0x04 */  uint8_t offset_list[0x8]; ///< Array of {u32 relative offset, u32 hash} from the first HBIN.
      /* the array will extend here... */
    } REGFS_CELL_LF;

    typedef struct REGFS_CELL_LH {
/* -0x04 */  uint8_t size[0x4];        ///< negative if allocated
/*  0x00 */  uint8_t magic[0x2];       ///< "lh"
/*  0x02 */  uint8_t num_offsets[0x2];
/*  0x04 */  uint8_t offset_list[0x8]; ///< Array of {u32 relative offset, u32 hash} from the first HBIN.
      /* the array will extend here... */
    } REGFS_CELL_LH;

    typedef struct REGFS_CELL_RI {
/* -0x04 */  uint8_t size[0x4];        ///< negative if allocated
/*  0x00 */  uint8_t magic[0x2];       ///< "ri"
/*  0x02 */  uint8_t num_offsets[0x2];
/*  0x04 */  uint8_t offset_list[0x4]; ///< Array of u32 relative offsets from the first HBIN.
      /* the array will extend here... */
    } REGFS_CELL_RI;

    typedef struct REGFS_CELL_LI {
/* -0x04 */  uint8_t size[0x4];        ///< negative if allocated
/*  0x00 */  uint8_t magic[0x2];       ///< "li"
/*  0x02 */  uint8_t num_offsets[0x2];
/*  0x04 */  uint8_t offset_list[0x4]; ///< Array of u32 relative offsets from the first HBIN.
      /* the array will extend here... */
    } REGFS_CELL_LI;

    typedef struct REGFS_CELL_DB {
/* -0x04 */  uint8_t size[0x4];   ///< negative if allocated
/*  0x00 */  uint8_t magic[0x2];  ///< "db"
/*  0x02 */  uint8_t unused[0x2];
/*  0x04 */  uint8_t offset[0x4]; ///< Offset to a DBIndirect block relative to the first HBIN.
    } REGFS_CELL_DB;

    typedef struct REGFS_CELL_DB_INDIRECT {
/* -0x04 */  uint8_t size[0x4];        ///< negative if allocated
/*  0x00 */  uint8_t offset_list[0x4]; ///< Array of u32 relative offsets from the first HBIN to data records of size up to 0x3fd8.
      /* the array will extend here... */
    } REGFS_CELL_DB_INDIRECT;



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
/* 0x00 */    uint8_t magic[4];  ///< "hbin"
/* 0x04 */    uint8_t offset[4]; ///< relative offset from first HBIN (0x1000)
/* 0x08 */    uint8_t length[4]; ///< length of this HBIN.
/* 0x0C */    uint8_t unused[0x14];
  } HBIN;

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
