/*
** The Sleuth Kit 
**
** Willi Ballenthin [william.ballenthin <at> mandiant [dot] com]
** Copyright (c) 2012 Willi Ballenthin.  All rights reserved
**
** This software is distributed under the Common Public License 1.0 
*/

/**
 *\file regfs.c
 * Contains the internal TSK Registry file system functions.
 */

#include "tsk_fs_i.h"
#include "tsk_regfs.h"

/**
 * @see ntfs.c
 */
static uint32_t
nt2unixtime(uint64_t ntdate) {
  #define NSEC_BTWN_1601_1970 (uint64_t)(116444736000000000ULL)
  
  ntdate -= (uint64_t) NSEC_BTWN_1601_1970;
  ntdate /= (uint64_t) 10000000;
  return (uint32_t) ntdate;
}

/**
 * @see ntfs.c
 */
static uint32_t
nt2nano(uint64_t ntdate) {
  return (int32_t) (ntdate % 10000000);
}


static TSK_RETVAL_ENUM
regfs_utf16to8(TSK_ENDIAN_ENUM endian, char *error_class,
	       uint8_t *utf16, ssize_t utf16_length,
	       char *utf8, ssize_t utf8_length) {
  UTF16 *name16;
  UTF8 *name8;
  int retVal;
  
  name16 = (UTF16 *) utf16;
  name8 = (UTF8 *) utf8;
  retVal = tsk_UTF16toUTF8(endian, 
			   (const UTF16 **) &name16,
			   (UTF16 *) ((uintptr_t) name16 + utf16_length),
			   &name8,
			   (UTF8 *) ((uintptr_t) name8 + utf8_length),
			   TSKlenientConversion);
  if (retVal != TSKconversionOK) {
    if (tsk_verbose)
      tsk_fprintf(stderr, "Error converting %s to UTF8: %d",
		  error_class, retVal);
    *name8 = '\0';
  }
  else if ((uintptr_t) name8 >= (uintptr_t) utf8 + utf8_length) {
    /* Make sure it is NULL Terminated */
    utf8[utf8_length - 1] = '\0';
  }
  else {
    *name8 = '\0';
  }
  return TSK_OK;
}

/**
 * Given the address as `inum`, load metadata and the content of the cell
 *   and return this as a new structure. 
 * @return A new REGFS_CELL on success, NULL on error.
 */
static REGFS_CELL *
reg_load_cell(TSK_FS_INFO *fs, TSK_INUM_T inum) {
  ssize_t count;
  uint32_t len;
  uint16_t type;
  uint8_t  buf[6];
  REGFS_CELL *cell;

  if (inum < fs->first_inum || inum > fs->last_inum) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_BLK_NUM);
    tsk_error_set_errstr("Invalid block number to load: %" PRIuDADDR "", inum);
    return NULL;
  }

  // 6 bytes: 4 bytes length, two bytes type
  count = tsk_fs_read(fs, inum, (char *)buf, 6);
  if (count != 6) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_READ);
    tsk_error_set_errstr("Failed to read cell structure (start %llx) (1)", inum);
    return NULL;
  }

  uint8_t is_allocated;
  len = (tsk_getu32(fs->endian, buf));
  if (len & 1 << 31) {
    is_allocated = 1;
    len = (-1 * tsk_gets32(fs->endian, buf));
  } else {
    is_allocated = 0;
    len = (tsk_getu32(fs->endian, buf));
  }

  // this may be a few bytes too long.
  cell = (REGFS_CELL *)tsk_malloc(sizeof(REGFS_CELL) + len);
  if (cell == NULL) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_AUX_MALLOC);
    tsk_error_set_errstr("Failed to malloc new cell structure.");
    return NULL;
  }

  cell->inum = inum;
  cell->length = len;
  cell->is_allocated = is_allocated;

  uint32_t read = 0;
  while (cell->length - read > 0) {
    count = tsk_fs_read(fs, (cell->inum) + read, 
			(char *) ((&cell->data) + read), cell->length - read);
    if (count == -1) {
      free(cell);
      tsk_error_reset();
      tsk_error_set_errno(TSK_ERR_FS_READ);
      tsk_error_set_errstr("Failed to read cell structure (start: %llx length: 0x%x count: 0x%x) (2)", cell->inum, cell->length, read);
      return NULL;
    }
    read += count;
  }

  type = (tsk_getu16(fs->endian, buf + 4));

  switch (type) {
  case 0x6b76:
    cell->type = TSK_REGFS_RECORD_TYPE_VK;
    break;
  case 0x6b6e:
    cell->type = TSK_REGFS_RECORD_TYPE_NK;
    break;
  case 0x666c:
    cell->type = TSK_REGFS_RECORD_TYPE_LF;
    break;
  case 0x686c:
    cell->type = TSK_REGFS_RECORD_TYPE_LH;
    break;
    cell->type = TSK_REGFS_RECORD_TYPE_LI;
    break;
  case 0x6972:
    cell->type = TSK_REGFS_RECORD_TYPE_RI;
    break;
  case 0x6b73:
    cell->type = TSK_REGFS_RECORD_TYPE_SK;
    break;
  case 0x6264:
    cell->type = TSK_REGFS_RECORD_TYPE_DB;
    break;
  default:
    cell->type = TSK_REGFS_RECORD_TYPE_UNKNOWN;
    break;
  }

  return cell;
}

/** 
 * Load the attributes.
 * @param a_fs_file File to load attributes for.
 * @returns 1 on error
 */
static uint8_t
reg_load_attrs(TSK_FS_FILE * a_fs_file)
{
  // TODO(wb): check if allocated

    a_fs_file->meta->attr = 0;
    a_fs_file->meta->attr_state = TSK_FS_META_ATTR_STUDIED;
    return 0;
}

/**
 * reg_file_add_meta
 * Load the associated metadata for the file with inode at `inum`
 * into the file structure `a_fs_file`.
 * 
 * Sets the content_ptr to an instance of REGFS_CELL.
 * 
 * If the `meta` field of `a_fs_file` is already set, it will be
 *   cleared and reset.
 * 
 * As for the `meta.type`:
 *   - vk records --> file
 *   - nk records --> directories
 *   - else       --> virtual files
 * 
 * Until we do some parsing of security info, the mode
 *   is 0777 for all keys and values.
 *
 * 
 * @return 1 on error, 0 otherwise.
 */
uint8_t
reg_file_add_meta(TSK_FS_INFO * fs, TSK_FS_FILE * a_fs_file, TSK_INUM_T inum) {
    REGFS_CELL *cell;

    tsk_error_reset();

    if (inum < fs->first_inum || inum > fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("regfs_file_add_meta: %" 
			       PRIuINUM 
			       " too large/small", 
			     inum);
        return 1;
    }
    if (a_fs_file == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("regfs_inode_lookup: fs_file is NULL");
        return 1;
    }

    if (fs == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("regfs_inode_lookup: fs is NULL");
        return 1;
    }
    a_fs_file->fs_info = fs;

    // we will always reset the meta field
    // because this is simple.
    if (a_fs_file->meta != NULL) {
        tsk_fs_meta_close(a_fs_file->meta);
    }

    a_fs_file->name = NULL;

    cell = reg_load_cell(fs, inum);
    if (cell == NULL) {
      return 1;
    }

    // for the time being, stuff the entire Record into the 
    // meta content field. On average, it won't be very big.
    // And it shouldn't ever be larger than 4096 bytes.
    if ((a_fs_file->meta = tsk_fs_meta_alloc(0)) == NULL) {
        return 1;
    }
    a_fs_file->meta->content_ptr = cell;
    a_fs_file->meta->content_len = sizeof(REGFS_CELL) + cell->length;

    a_fs_file->meta->addr = inum;
    if (cell->is_allocated) {
      a_fs_file->meta->flags = TSK_FS_META_FLAG_ALLOC;
    } else {
      a_fs_file->meta->flags = TSK_FS_META_FLAG_UNALLOC;
    }
    if (cell->type == TSK_REGFS_RECORD_TYPE_VK) {
      a_fs_file->meta->type = TSK_FS_META_TYPE_REG;
    } else if (cell->type == TSK_REGFS_RECORD_TYPE_NK) {
      a_fs_file->meta->type = TSK_FS_META_TYPE_DIR;
    } else {
      a_fs_file->meta->type = TSK_FS_META_TYPE_VIRT;
    }
    a_fs_file->meta->mode = 0007777;
    a_fs_file->meta->nlink = 1;

    // TODO(wb): parse the size of vk record data
    a_fs_file->meta->size = cell->length;

    // TODO(wb): parse security info
    a_fs_file->meta->uid = 0;
    a_fs_file->meta->gid = 0;

    if (cell->type == TSK_REGFS_RECORD_TYPE_NK) {
      REGFS_CELL_NK *nk = (REGFS_CELL_NK *)&cell->data;
      uint64_t nttime = tsk_getu64(fs->endian, nk->timestamp);
      a_fs_file->meta->mtime = nt2unixtime(nttime);
      a_fs_file->meta->mtime_nano = nt2nano(nttime);
    } else {
      a_fs_file->meta->mtime = 0;
      a_fs_file->meta->mtime_nano = 0;
    }

    // The Registry does not have an Access timestamp
    a_fs_file->meta->atime = 0;
    a_fs_file->meta->atime_nano = 0;

    // The Registry does not have a Changed timestamp
    a_fs_file->meta->ctime = 0;
    a_fs_file->meta->ctime_nano = 0;

    // The Registry does not have a Created timestamp
    a_fs_file->meta->crtime = 0;
    a_fs_file->meta->crtime_nano = 0;

    // The Registry does not have a Deleted timestamp
    a_fs_file->meta->time2.ext2.dtime = 0;
    a_fs_file->meta->time2.ext2.dtime_nano = 0;

    a_fs_file->meta->seq = 0;

    a_fs_file->meta->link = 0;

    if (reg_load_attrs(a_fs_file) == 1) {
      return TSK_ERR;
    }

    return TSK_OK;
}

/**
 * @return 1 on error, 0 otherwise.
 */
uint8_t
reg_block_walk(TSK_FS_INFO * fs,
    TSK_DADDR_T a_start_blk, TSK_DADDR_T a_end_blk,
    TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags, TSK_FS_BLOCK_WALK_CB a_action,
    void *a_ptr)
{
    TSK_FS_BLOCK *fs_block;
    REGFS_INFO *reg;
    TSK_DADDR_T blknum;
    uint8_t retval;
    reg = (REGFS_INFO *) fs;
    
    tsk_error_reset();

    if (tsk_verbose) {
      tsk_fprintf(stderr,
		  "regfs_block_walk: Block Walking %" PRIuDADDR " to %"
		  PRIuDADDR "\n", a_start_blk, a_end_blk);
    }

    if (a_start_blk < fs->first_block || a_start_blk > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
	tsk_error_set_errstr("Invalid block walk start block");
        return 1;
    }
    if (a_end_blk < fs->first_block || a_end_blk > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
	tsk_error_set_errstr("Invalid block walk end Block");
        return 1;
    }

    // Sanity check on a_flags -- make sure at least one ALLOC is set 
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC) == 0) &&
        ((a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC) == 0)) {
        a_flags |=
            (TSK_FS_BLOCK_WALK_FLAG_ALLOC |
             TSK_FS_BLOCK_WALK_FLAG_UNALLOC);
    }
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_META) == 0) &&
        ((a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT) == 0)) {
        a_flags |=
            (TSK_FS_BLOCK_WALK_FLAG_CONT | TSK_FS_BLOCK_WALK_FLAG_META);
    }

    if ((fs_block = tsk_fs_block_alloc(fs)) == NULL) {
        return 1;
    }

    blknum = a_start_blk;

    while (blknum < a_end_blk) {
      ssize_t count;
      uint8_t data_buf[HBIN_SIZE];

      if (tsk_verbose) {
	tsk_fprintf(stderr,
		    "\nregfs_block_walk: Reading block %"  PRIuDADDR 
		    " (offset %"  PRIuDADDR  
		    ") for %" PRIuDADDR  " bytes\n",
		    blknum, blknum * 4096, HBIN_SIZE);
      }

      count = tsk_fs_read_block(fs, blknum, (char *)data_buf, HBIN_SIZE);
      if (count != HBIN_SIZE) {
	tsk_fs_block_free(fs_block);
	return 1;
      }

      if (tsk_fs_block_set(fs, fs_block, blknum,
			   TSK_FS_BLOCK_FLAG_ALLOC | 
			   TSK_FS_BLOCK_FLAG_META | 
			   TSK_FS_BLOCK_FLAG_CONT | 
			   TSK_FS_BLOCK_FLAG_RAW,
			   (char *)data_buf) != 0) {
	tsk_fs_block_free(fs_block);
	return 1;
      }

      retval = a_action(fs_block, a_ptr);
      if (retval == TSK_WALK_STOP) {
	tsk_fs_block_free(fs_block);
	return 0;
      }
      else if (retval == TSK_WALK_ERROR) {
	tsk_fs_block_free(fs_block);
	return 1;
      }
      
      blknum += 1;
    }

    tsk_fs_block_free(fs_block);
    return 0;
}

/**
 * HBINs are always allocated, if they exist in the Registry, and they
 *   may contain both value content and key structures.
 */ 
TSK_FS_BLOCK_FLAG_ENUM
reg_block_getflags(TSK_FS_INFO * fs, TSK_DADDR_T a_addr)
{
    return TSK_FS_BLOCK_FLAG_ALLOC | 
      TSK_FS_BLOCK_FLAG_META | 
      TSK_FS_BLOCK_FLAG_CONT;
}

/***
 * @return 0 on success, non-zero on error.
 */
static uint8_t
reg_inode_walk(TSK_FS_INFO * fs, TSK_INUM_T start_inum,
    TSK_INUM_T end_inum, TSK_FS_META_FLAG_ENUM flags,
    TSK_FS_META_WALK_CB a_action, void *ptr)
{
    TSK_FS_FILE *the_file;
    HBIN hbin;
    REGFS_CELL *cell;
    TSK_INUM_T current_inum = start_inum;
    TSK_DADDR_T current_hbin_start = current_inum - (current_inum % HBIN_SIZE);
    uint32_t current_hbin_length;
    char please_continue = 1;
    ssize_t count;

    tsk_error_reset();

    if (start_inum < fs->first_inum || start_inum > fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("reg_inode_walk: Start inode number: %" 
			     PRIuDADDR "",
			     start_inum);
        return 1;
    }

    if (end_inum < fs->first_inum || end_inum > fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("reg_inode_walk: End inode number: %" 
			     PRIuDADDR "",
			     end_inum);
        return 1;
    }

    if (tsk_verbose) {
      tsk_fprintf(stderr,
		  "reg_inode_walk: Inode Walking %" PRIuDADDR " to %"
		  PRIuDADDR "\n", start_inum, end_inum);
    }
    // Sanity check on flags -- make sure at least one ALLOC is set 
    if (((flags & TSK_FS_META_FLAG_ALLOC) == 00) & 
	((flags & TSK_FS_META_FLAG_UNALLOC) == 0)) {
      flags |= TSK_FS_META_FLAG_ALLOC;
      flags |= TSK_FS_META_FLAG_UNALLOC;
    }

    // scan backwards aligned 0x1000 at a time trying to find
    //   the "hbin" magic
    // start at `current_hbin_start`
    // update `current_hbin_start` and `current_hbin_length`
    // break if:
    //   "hbin" magic found
    //   offset falls below lowest possible value
    while (1) {
      if (current_hbin_start < FIRST_HBIN_OFFSET) {
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
	tsk_error_set_errstr("Failed to identify HBIN header");
	return 1;
      }
      count = tsk_fs_read(fs, current_hbin_start, (char *)&hbin, sizeof(HBIN));
      if (count != sizeof(HBIN)) {
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_FS_READ);
	tsk_error_set_errstr("Failed to read HBIN header");
	return 1;
      }
      if (tsk_getu32(fs->endian, &hbin) != 0x6e696268) { // "hbin"
	current_hbin_start -= 0x1000;
      }
      else {
	current_hbin_length = tsk_getu32(fs->endian, &hbin.length);
	break;
      }
    }

    while (current_inum < end_inum       && 
	   current_hbin_start < end_inum &&
           please_continue != 0) {

	  // skip HBIN headers
	  if (current_inum - current_hbin_start < 0x20) {
	    current_inum = current_hbin_start + 0x20;
	  }

          the_file = tsk_fs_file_open_meta(fs, NULL, current_inum);
	  if (the_file == NULL) {
	    return 1;
	  }
	  cell = the_file->meta->content_ptr;

	  if (current_inum + cell->length > 
	      current_hbin_start + current_hbin_length) {
	    // The Cell overran into the next HBIN header
	    tsk_fs_file_close(the_file);
	    tsk_error_reset();
	    tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
	    tsk_error_set_errstr("Cell overran into subsequent HBIN header "
				 "(start: 0x%llx length: 0x%x hbin: 0x%llx", 
				 current_inum, cell->length, current_hbin_start);
	    return 1;
	  }

	  if ((the_file->meta->flags & flags) > 0) {
	    TSK_WALK_RET_ENUM ret = a_action(the_file, ptr);
	    if (ret == TSK_WALK_CONT) {
	      // continue!
	    } else if (ret == TSK_WALK_STOP) {
	      please_continue = 0;
	    } else if (ret == TSK_WALK_ERROR) {
	      tsk_fs_file_close(the_file);
	      return 1;
	    } else {
	      // not sure whats going on, so... continue!
	    }
	  }

	  current_inum += cell->length;
	  if (current_inum >= current_hbin_start + current_hbin_length) {
	    current_hbin_start += current_hbin_length;

	    count = tsk_fs_read(fs, current_hbin_start, (char *)&hbin, sizeof(HBIN));
	    if (count != sizeof(HBIN)) {
	      tsk_error_reset();
	      tsk_error_set_errno(TSK_ERR_FS_READ);
	      tsk_error_set_errstr("Failed to read HBIN header");
	      return 1;
	    }

	    if (tsk_getu32(fs->endian, &hbin) == 0x0) { // last, empty, hbin
	      please_continue = 0;
	    } else if (tsk_getu32(fs->endian, &hbin) != 0x6e696268) { // "hbin"
	      tsk_error_reset();
	      tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
	      tsk_error_set_errstr("Failed to find expected HBIN header");
	      return 1;
	    }
	    current_hbin_length = tsk_getu32(fs->endian, &hbin.length);

	    if (tsk_verbose) {
	      tsk_fprintf(stderr,
			  "reg_inode_walk: Current hbin now 0x%llx\n",
			  current_hbin_start);
	    }
	  }
	  tsk_fs_file_close(the_file);
    }
    return 0;
}

static TSK_FS_ATTR_TYPE_ENUM
reg_get_default_attr_type(const TSK_FS_FILE * a_file)
{
    if ((a_file == NULL) || (a_file->meta == NULL))
        return TSK_FS_ATTR_TYPE_DEFAULT;

    /* Use DATA for files and IDXROOT for dirs */
    if (a_file->meta->type == TSK_FS_META_TYPE_DIR)
        return TSK_FS_ATTR_TYPE_NTFS_IDXROOT;
    else
        return TSK_FS_ATTR_TYPE_NTFS_DATA;
}


TSK_RETVAL_ENUM
reg_dir_open_meta(TSK_FS_INFO * fs, TSK_FS_DIR ** a_fs_dir,
    TSK_INUM_T a_addr)
{
  //    REGFS_INFO *reg = (REGFS_INFO *) fs;
    return 0;
}

typedef struct REGFS_CELL_COUNT {
  unsigned int num_active_cells;
  unsigned int num_inactive_cells;
  unsigned int num_active_bytes;
  unsigned int num_inactive_bytes;
  unsigned int num_active_vk;
  unsigned int num_inactive_vk;
  unsigned int num_active_nk;
  unsigned int num_inactive_nk;
  unsigned int num_active_lf;
  unsigned int num_inactive_lf;
  unsigned int num_active_lh;
  unsigned int num_inactive_lh;
  unsigned int num_active_li;
  unsigned int num_inactive_li;
  unsigned int num_active_ri;
  unsigned int num_inactive_ri;
  unsigned int num_active_sk;
  unsigned int num_inactive_sk;
  unsigned int num_active_db;
  unsigned int num_inactive_db;
  unsigned int num_active_unknown;
  unsigned int num_inactive_unknown;
} REGFS_CELL_COUNT;

static TSK_WALK_RET_ENUM
reg_cell_count_callback(TSK_FS_FILE *the_file, void *ptr) {
  REGFS_CELL_COUNT *cell_count = (REGFS_CELL_COUNT *)ptr;
  REGFS_CELL *cell = the_file->meta->content_ptr;

  if (cell->is_allocated) {
    cell_count->num_active_cells += 1;
    cell_count->num_active_bytes += cell->length;
    switch(cell->type) {
    case TSK_REGFS_RECORD_TYPE_VK:
      cell_count->num_active_vk += 1;
      break;
    case TSK_REGFS_RECORD_TYPE_NK:
      cell_count->num_active_nk += 1;
      break;
    case TSK_REGFS_RECORD_TYPE_LF:
      cell_count->num_active_lf += 1;
      break;
    case TSK_REGFS_RECORD_TYPE_LH:
      cell_count->num_active_lh += 1;
      break;
    case TSK_REGFS_RECORD_TYPE_LI:
      cell_count->num_active_li += 1;
      break;
    case TSK_REGFS_RECORD_TYPE_RI:
      cell_count->num_active_ri += 1;
      break;
    case TSK_REGFS_RECORD_TYPE_SK:
      cell_count->num_active_sk += 1;
      break;
    case TSK_REGFS_RECORD_TYPE_DB:
      cell_count->num_active_db += 1;
      break;
    case TSK_REGFS_RECORD_TYPE_UNKNOWN:
      // fall through intended
    default:
      cell_count->num_active_unknown += 1;
      break;
    }
  } else {
    cell_count->num_inactive_cells += 1;
    cell_count->num_inactive_bytes += cell->length;
    switch(cell->type) {
    case TSK_REGFS_RECORD_TYPE_VK:
      cell_count->num_inactive_vk += 1;
      break;
    case TSK_REGFS_RECORD_TYPE_NK:
      cell_count->num_inactive_nk += 1;
      break;
    case TSK_REGFS_RECORD_TYPE_LF:
      cell_count->num_inactive_lf += 1;
      break;
    case TSK_REGFS_RECORD_TYPE_LH:
      cell_count->num_inactive_lh += 1;
      break;
    case TSK_REGFS_RECORD_TYPE_LI:
      cell_count->num_inactive_li += 1;
      break;
    case TSK_REGFS_RECORD_TYPE_RI:
      cell_count->num_inactive_ri += 1;
      break;
    case TSK_REGFS_RECORD_TYPE_SK:
      cell_count->num_inactive_sk += 1;
      break;
    case TSK_REGFS_RECORD_TYPE_DB:
      cell_count->num_inactive_db += 1;
      break;
    case TSK_REGFS_RECORD_TYPE_UNKNOWN:
      // fall through intended
    default:
      cell_count->num_inactive_unknown += 1;
      break;
    }
  }

  return TSK_WALK_CONT;
}

/**
 * Print details about the file system to a file handle.
 *
 * @param fs File system to print details on
 * @param hFile File handle to print text to
 *
 * @returns 1 on error and 0 on success
 */
static uint8_t
reg_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
    REGFS_INFO *reg = (REGFS_INFO *) fs;
    char asc[512];
    REGFS_CELL_COUNT cell_count;
    
    memset(&cell_count, 0, sizeof(REGFS_CELL_COUNT));

    tsk_fprintf(hFile, "\nFILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "File System Type: Windows Registry\n");

    // TODO(wb): print readable versions
    tsk_fprintf(hFile, "Major Version: %d\n", 
		(tsk_getu32(fs->endian, reg->regf.major_version)));
    tsk_fprintf(hFile, "Minor Version: %d\n", 
		(tsk_getu32(fs->endian, reg->regf.minor_version)));

    if ((tsk_getu32(fs->endian, reg->regf.seq1) == 
	 (tsk_getu32(fs->endian, reg->regf.seq2)))) {
      tsk_fprintf(hFile, "Synchronized: %s\n", "Yes");
    } else {
      tsk_fprintf(hFile, "Synchronized: %s\n", "No");
    }

    if (regfs_utf16to8(fs->endian, "REGF hive name label",
		       reg->regf.hive_name, 64,
		       asc, 512) != TSK_OK) {
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_FS_UNICODE);
	tsk_error_set_errstr("Failed to convert REGF hive name string to UTF-8");
	return 1;
    }
    tsk_fprintf(hFile, "Hive name: %s\n", asc);    

    tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Offset to first key: %" PRIu32 "\n",
		(FIRST_HBIN_OFFSET + 
		 tsk_getu32(fs->endian, reg->regf.first_key_offset)));

    tsk_fprintf(hFile, "Offset to last HBIN: %" PRIu32 "\n",
		(tsk_getu32(fs->endian, reg->regf.last_hbin_offset)));

    cell_count.num_active_bytes = FIRST_HBIN_OFFSET;
    cell_count.num_active_bytes += (fs->last_block_act - 1) * 0x20;
    if(reg_inode_walk(fs, fs->first_inum, fs->last_inum,
		      TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_UNALLOC,
		      reg_cell_count_callback, &cell_count)) {
      return 1;
    }
    cell_count.num_inactive_bytes = fs->img_info->size - cell_count.num_active_bytes;
    
    tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Number of\n");
    tsk_fprintf(hFile, "    cells:   %d/%d (active/inactive)\n", 
		cell_count.num_active_cells, cell_count.num_inactive_cells);
    tsk_fprintf(hFile, "    bytes:   %d/%d (bytes are approx.)\n",
		cell_count.num_active_bytes, cell_count.num_inactive_bytes);
    tsk_fprintf(hFile, "    VK records:   %d/%d\n",
		cell_count.num_active_vk, cell_count.num_inactive_vk);
    tsk_fprintf(hFile, "    NK records:   %d/%d\n",
		cell_count.num_active_nk, cell_count.num_inactive_nk);
    tsk_fprintf(hFile, "    LF records:   %d/%d\n",
		cell_count.num_active_lf, cell_count.num_inactive_lf);
    tsk_fprintf(hFile, "    LH records:   %d/%d\n",
		cell_count.num_active_lh, cell_count.num_inactive_lh);
    tsk_fprintf(hFile, "    LI records:   %d/%d\n",
		cell_count.num_active_li, cell_count.num_inactive_li);
    tsk_fprintf(hFile, "    RI records:   %d/%d\n",
		cell_count.num_active_ri, cell_count.num_inactive_ri);
    tsk_fprintf(hFile, "    SK records:   %d/%d\n",
		cell_count.num_active_sk, cell_count.num_inactive_sk);
    tsk_fprintf(hFile, "    DB records:   %d/%d\n",
		cell_count.num_active_db, cell_count.num_inactive_db);
    tsk_fprintf(hFile, "    unknown records:   %d/%d\n",
		cell_count.num_active_unknown, cell_count.num_inactive_unknown);
    return 0;
}

static uint8_t
reg_fscheck(TSK_FS_INFO * fs, FILE * hFile)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("fscheck not implemented for Windows Registries yet");
    return 1;
}

static TSK_RETVAL_ENUM
reg_istat_vk(TSK_FS_INFO * fs, FILE * hFile,
		  TSK_FS_FILE *the_file, TSK_DADDR_T numblock, int32_t sec_skew) {
    REGFS_CELL *cell;
	cell = (REGFS_CELL *)the_file->meta->content_ptr;
    tsk_fprintf(hFile, "\nRECORD INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Record Type: %s\n", "VK");
    return TSK_OK;
}


static TSK_RETVAL_ENUM
reg_istat_nk(TSK_FS_INFO * fs, FILE * hFile,
		  TSK_FS_FILE *the_file, TSK_DADDR_T numblock, int32_t sec_skew) {
    ssize_t count;
    REGFS_CELL *cell;
    REGFS_CELL_NK *nk;
    char s[512]; // to be used throughout, temporarily
    uint16_t name_length;
    char timeBuf[128];

	cell = (REGFS_CELL *)the_file->meta->content_ptr;
	nk = (REGFS_CELL_NK *)&cell->data;

    tsk_fprintf(hFile, "\nRECORD INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Record Type: %s\n", "NK");

    if ((tsk_gets32(fs->endian, nk->classname_offset)) == 0xFFFFFFFF) {
      tsk_fprintf(hFile, "Class Name: %s\n", "None");
    } else {
      char asc[512];
      uint32_t classname_offset;
      uint32_t classname_length;

      classname_offset = (tsk_gets32(fs->endian, nk->classname_offset));
      classname_length = (tsk_gets16(fs->endian, nk->classname_length));

      if (classname_length > 512) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
		tsk_error_set_errstr("NK classname string too long");
		return TSK_ERR;
      }
	  
      count = tsk_fs_read(fs, FIRST_HBIN_OFFSET + classname_offset + 4, 
						  s, classname_length);
      if (count != classname_length) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_READ);
		tsk_error_set_errstr("Failed to read NK classname string");
		return TSK_ERR;
      }
	  
      if (regfs_utf16to8(fs->endian, "NK class name", (uint8_t *)s, 
						 512, asc, 512) != TSK_OK) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_UNICODE);
		tsk_error_set_errstr("Failed to convert NK classname string to UTF-8");
		return TSK_ERR;
      }

      tsk_fprintf(hFile, "Class Name: %s\n", asc);    
    }

    name_length = (tsk_getu16(fs->endian, nk->name_length));
    if (name_length > 512) {
	  tsk_error_reset();
	  tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
	  tsk_error_set_errstr("NK key name string too long");
	  return TSK_ERR;
    }
	memset(s, 0, sizeof(s));
    strncpy(s, (char *)nk->name, name_length);
    tsk_fprintf(hFile, "Key Name: %s\n", s);

    if ((tsk_getu16(fs->endian, nk->is_root)) == 0x2C) {
      tsk_fprintf(hFile, "Root Record: %s\n", "Yes");
    } else {
      tsk_fprintf(hFile, "Root Record: %s\n", "No");
    }

    if (sec_skew != 0) {
        tsk_fprintf(hFile, "\nAdjusted Entry Times:\n");

        if (the_file->meta->mtime) {
            the_file->meta->mtime -= sec_skew;
		}

        tsk_fprintf(hFile, "Modified:\t%s\n",
            tsk_fs_time_to_str(the_file->meta->mtime, timeBuf));

        if (the_file->meta->mtime == 0) {
            the_file->meta->mtime += sec_skew;
		}

        tsk_fprintf(hFile, "\nOriginal Entry Times:\n");
    }
    else {
        tsk_fprintf(hFile, "\nEntry Times:\n");
    }
    tsk_fprintf(hFile, "Modified:\t%s\n", tsk_fs_time_to_str(the_file->meta->mtime,
            timeBuf));

    if ((tsk_getu16(fs->endian, nk->is_root)) == 0x2C) {
	  tsk_fprintf(hFile, "Parent Record: %s\n", "None (root record)");
    } else {
	  // u32 here, not PRIuINUM since the field is a u32...
	  tsk_fprintf(hFile, "Parent Record: %" PRIu32 "\n", 
				  FIRST_HBIN_OFFSET + (tsk_getu32(fs->endian, nk->parent_nk_offset)));
    }

    return TSK_OK;
}

static TSK_RETVAL_ENUM
reg_istat_lf(TSK_FS_INFO * fs, FILE * hFile,
		  TSK_FS_FILE *the_file, TSK_DADDR_T numblock, int32_t sec_skew) {
    REGFS_CELL *cell;
	cell = (REGFS_CELL *)the_file->meta->content_ptr;

    tsk_fprintf(hFile, "RECORD INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Record Type: %s\n", "LF");
    return TSK_OK;
}

static TSK_RETVAL_ENUM
reg_istat_lh(TSK_FS_INFO * fs, FILE * hFile,
		  TSK_FS_FILE *the_file, TSK_DADDR_T numblock, int32_t sec_skew) {
    REGFS_CELL *cell;
	cell = (REGFS_CELL *)the_file->meta->content_ptr;

    tsk_fprintf(hFile, "RECORD INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Record Type: %s\n", "LH");
    return TSK_OK;
}

static TSK_RETVAL_ENUM
reg_istat_li(TSK_FS_INFO * fs, FILE * hFile,
		  TSK_FS_FILE *the_file, TSK_DADDR_T numblock, int32_t sec_skew) {
    REGFS_CELL *cell;
	cell = (REGFS_CELL *)the_file->meta->content_ptr;

    tsk_fprintf(hFile, "RECORD INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Record Type: %s\n", "LI");
    return TSK_OK;
}

static TSK_RETVAL_ENUM
reg_istat_ri(TSK_FS_INFO * fs, FILE * hFile,
		  TSK_FS_FILE *the_file, TSK_DADDR_T numblock, int32_t sec_skew) {
    REGFS_CELL *cell;
	cell = (REGFS_CELL *)the_file->meta->content_ptr;

    tsk_fprintf(hFile, "RECORD INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Record Type: %s\n", "RI");
    return TSK_OK;
}

static TSK_RETVAL_ENUM
reg_istat_sk(TSK_FS_INFO * fs, FILE * hFile,
		  TSK_FS_FILE *the_file, TSK_DADDR_T numblock, int32_t sec_skew) {
    REGFS_CELL *cell;
	cell = (REGFS_CELL *)the_file->meta->content_ptr;

    tsk_fprintf(hFile, "RECORD INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Record Type: %s\n", "SK");
    return TSK_OK;
}

static TSK_RETVAL_ENUM
reg_istat_db(TSK_FS_INFO * fs, FILE * hFile,
		  TSK_FS_FILE *the_file, TSK_DADDR_T numblock, int32_t sec_skew) {
    REGFS_CELL *cell;
	cell = (REGFS_CELL *)the_file->meta->content_ptr;

    tsk_fprintf(hFile, "RECORD INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Record Type: %s\n", "DB");
    return TSK_OK;
}

static TSK_RETVAL_ENUM
reg_istat_unknown(TSK_FS_INFO * fs, FILE * hFile,
		  TSK_FS_FILE *the_file, TSK_DADDR_T numblock, int32_t sec_skew) {
    REGFS_CELL *cell;
    cell = (REGFS_CELL *)the_file->meta->content_ptr;

    ssize_t count;
    uint8_t buf[6];
    memset(buf, 0, 6);

    count = tsk_fs_read(fs, (cell->inum), (char *)buf, 6);
    if (count != 6) {
      tsk_error_reset();
      tsk_error_set_errno(TSK_ERR_FS_READ);
      tsk_error_set_errstr("Failed to read cell structure (start %llx) (3)", cell->inum);
      return TSK_ERR;
    }

    tsk_fprintf(hFile, "RECORD INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Record Type: %s\n", "Unknown (Data Record?)");
    tsk_fprintf(hFile, "Type identifier: 0x%x%x\n", *(buf + 4), *(buf + 5));

    return TSK_OK;
}





/**
 * Print details on a specific file to a file handle.
 *
 * @param fs File system file is located in
 * @param hFile File name to print text to
 * @param inum Address of file in file system
 * @param numblock The number of blocks in file to force print (can go beyond file size)
 * @param sec_skew Clock skew in seconds to also print times in
 *
 * @returns 1 on error and 0 on success
 */
static uint8_t
reg_istat(TSK_FS_INFO * fs, FILE * hFile,
    TSK_INUM_T inum, TSK_DADDR_T numblock, int32_t sec_skew)
{
  TSK_FS_FILE *the_file;
  REGFS_CELL *cell;


  tsk_fprintf(hFile, "\nCELL INFORMATION\n");
  tsk_fprintf(hFile, "--------------------------------------------\n");

  // we load a TSK_FS_FILE up for consistency, and since
  //   it handles all the cell loading, reading, etc.
  the_file = tsk_fs_file_open_meta(fs, NULL, inum);
  if (the_file == NULL) {
	return 1;
  }
  cell = the_file->meta->content_ptr;
  
  tsk_fprintf(hFile, "Cell: %" PRIuINUM "\n", inum);    
  if (cell->is_allocated) {
    tsk_fprintf(hFile, "Allocated: %s\n", "Yes");    
  } else {
    tsk_fprintf(hFile, "Allocated: %s\n", "No");    
  }
  tsk_fprintf(hFile, "Cell Size: %" PRIu32 "\n", cell->length);

  switch (cell->type) {
  case TSK_REGFS_RECORD_TYPE_VK:
    reg_istat_vk(fs, hFile, the_file, numblock, sec_skew);
    break;
  case TSK_REGFS_RECORD_TYPE_NK:
    reg_istat_nk(fs, hFile, the_file, numblock, sec_skew);
    break;
  case TSK_REGFS_RECORD_TYPE_LF:
    reg_istat_lf(fs, hFile, the_file, numblock, sec_skew);
    break;
  case TSK_REGFS_RECORD_TYPE_LH:
    reg_istat_lh(fs, hFile, the_file, numblock, sec_skew);
    break;
  case TSK_REGFS_RECORD_TYPE_LI:
    reg_istat_li(fs, hFile, the_file, numblock, sec_skew);
    break;
  case TSK_REGFS_RECORD_TYPE_RI:
    reg_istat_ri(fs, hFile, the_file, numblock, sec_skew);
    break;
  case TSK_REGFS_RECORD_TYPE_SK:
    reg_istat_sk(fs, hFile, the_file, numblock, sec_skew);
    break;
  case TSK_REGFS_RECORD_TYPE_DB:
    reg_istat_db(fs, hFile, the_file, numblock, sec_skew);
    break;
  case TSK_REGFS_RECORD_TYPE_UNKNOWN:
    // fall through intended
  default:
    reg_istat_unknown(fs, hFile, the_file, numblock, sec_skew);
    break;
  }

  tsk_fs_file_close(the_file);
  return 0;
}

static void
reg_close(TSK_FS_INFO * fs)
{
  //    REGFS_INFO *reg = (REGFS_INFO *) fs;

    if (fs == NULL)
        return;
    tsk_fs_free(fs);
    return;
}

int
reg_name_cmp(TSK_FS_INFO * a_fs_info, const char *s1, const char *s2)
{
    return strcasecmp(s1, s2);
}

/**
 * @brief reg_journal_unsupported
 */
static void
reg_journal_unsupported() {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("The Windows Registry does not have a journal.\n");
    return;
}

/**
 * @brief reg_jblk_walk
 * @param fs
 * @param start
 * @param end
 * @param flags
 * @param a_action
 * @param ptr
 * @return 1, as this is unsupported.
 */
static uint8_t
reg_jblk_walk(TSK_FS_INFO * fs, TSK_DADDR_T start,
    TSK_DADDR_T end, int flags, TSK_FS_JBLK_WALK_CB a_action, void *ptr)
{
    reg_journal_unsupported();
    return 1;
}

/**
 * @brief reg_jentry_walk
 * @param fs
 * @param flags
 * @param a_action
 * @param ptr
 * @return 1, as this is unsupported.
 */
static uint8_t
reg_jentry_walk(TSK_FS_INFO * fs, int flags,
    TSK_FS_JENTRY_WALK_CB a_action, void *ptr)
{
    reg_journal_unsupported();
    return 1;
}

/**
 * @brief ntfs_jopen
 * @param fs
 * @param inum
 * @return 1, as this is unsupported.
 */
static uint8_t
reg_jopen(TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    reg_journal_unsupported();
    return 1;
}


static uint8_t
reg_file_get_sidstr(TSK_FS_FILE * a_fs_file, char **sid_str)
{
  return 1;
}


















/**
 * reg_load_regf
 *   Read data into the supplied REGF, and do some sanity checking.
 */
TSK_RETVAL_ENUM
reg_load_regf(TSK_FS_INFO *fs_info, REGF *regf) {
    ssize_t count;

    count = tsk_fs_read(fs_info, 0, (char *)regf, sizeof(REGF));
    if (count != sizeof(REGF)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr("Failed to read REGF header structure");
        return TSK_ERR;
    }

    if ((tsk_getu32(fs_info->endian, regf->magic)) != REG_REGF_MAGIC) {
        tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        tsk_error_set_errstr("REGF header has an invalid magic header");
        return TSK_ERR;
    }

    return TSK_OK;
}



/**
 * \internal
 * Open part of a disk image as a Windows Registry.
 *
 * @param img_info Disk image to analyze
 * @param offset Byte offset where file system starts
 * @param ftype Specific type of file system
 * @param test NOT USED 
 * @returns NULL on error or if data is not a Registry
 */
TSK_FS_INFO *
reg_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
    TSK_FS_TYPE_ENUM ftype, uint8_t test)
{
    TSK_FS_INFO *fs;
    REGFS_INFO *reg;

    tsk_error_reset();

    if (TSK_FS_TYPE_ISREG(ftype) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Invalid FS type in reg_open");
        return NULL;
    }

    if ((reg = (REGFS_INFO *) tsk_fs_malloc(sizeof(REGFS_INFO))) == NULL) {
        return NULL;
    }
    fs = &(reg->fs_info);

    fs->ftype = TSK_FS_TYPE_REG;
    fs->duname = "Cell";
    fs->flags = TSK_FS_INFO_FLAG_NONE;
    fs->tag = TSK_FS_INFO_TAG;
    fs->endian = TSK_LIT_ENDIAN;

    fs->img_info = img_info;
    fs->offset = offset;

    if (reg_load_regf(fs, &(reg->regf)) != TSK_OK) {
        free(reg);
        return NULL;
    }

    fs->first_inum = FIRST_HBIN_OFFSET + 0x20;
    fs->last_inum  = (tsk_getu32(fs->endian, reg->regf.last_hbin_offset)) + HBIN_SIZE;
    fs->root_inum = (tsk_getu32(fs->endian, reg->regf.first_key_offset)); 
    
    // TODO(wb): set num inodes
    fs->block_size = HBIN_SIZE;
    fs->first_block = 0;
    // TODO(wb): from where is this offset relative? first hbin or absolute?
    fs->last_block = (tsk_getu32(fs->endian, reg->regf.last_hbin_offset)); 
    fs->last_block_act = (img_info->size - (img_info->size % HBIN_SIZE)) / HBIN_SIZE;

    fs->inode_walk = reg_inode_walk;
    fs->block_walk = reg_block_walk;
    fs->block_getflags = reg_block_getflags;

    fs->get_default_attr_type = reg_get_default_attr_type;
    fs->load_attrs = reg_load_attrs;

    fs->file_add_meta = reg_file_add_meta;
    fs->dir_open_meta = reg_dir_open_meta;
    fs->fsstat = reg_fsstat;
    fs->fscheck = reg_fscheck;
    fs->istat = reg_istat;
    fs->close = reg_close;
    fs->name_cmp = reg_name_cmp;

    fs->fread_owner_sid = reg_file_get_sidstr;
    fs->jblk_walk = reg_jblk_walk;
    fs->jentry_walk = reg_jentry_walk;
    fs->jopen = reg_jopen;
    fs->journ_inum = 0;

    return (fs);
}
