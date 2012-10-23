/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002-2003 Brian Carrier, @stake Inc.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
*/

/**
 *\file regfs.c
 * Contains the internal TSK Registry file system functions.
 */

#include "tsk_fs_i.h"
#include "tsk_regfs.h"





static uint8_t
reg_inode_walk(TSK_FS_INFO * fs, TSK_INUM_T start_inum,
    TSK_INUM_T end_inum, TSK_FS_META_FLAG_ENUM flags,
    TSK_FS_META_WALK_CB a_action, void *ptr)
{
    REGFS_INFO *reg = (REGFS_INFO *) fs;
    return 0;
}

uint8_t
reg_block_walk(TSK_FS_INFO * fs,
    TSK_DADDR_T a_start_blk, TSK_DADDR_T a_end_blk,
    TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags, TSK_FS_BLOCK_WALK_CB a_action,
    void *a_ptr)
{
    REGFS_INFO *reg = (REGFS_INFO *) fs;
    return 0;
}

reg_block_getflags(TSK_FS_INFO * fs, TSK_DADDR_T a_addr)
{
    REGFS_INFO *reg = (REGFS_INFO *) fs;
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

/** \internal
 * Load the attributes.
 * @param a_fs_file File to load attributes for.
 * @returns 1 on error
 */
static uint8_t
reg_load_attrs(TSK_FS_FILE * a_fs_file)
{
    return 0;
}

/**
 * Read an MFT entry and save it in the generic TSK_FS_META format.
 *
 * @param fs File system to read from.
 * @param mftnum Address of mft entry to read
 * @returns 1 on error
 */
static uint8_t
reg_inode_lookup(TSK_FS_INFO * fs, TSK_FS_FILE * a_fs_file,
    TSK_INUM_T mftnum)
{
    REGFS_INFO *reg = (REGFS_INFO *) fs;
    return 0;
}

TSK_RETVAL_ENUM
reg_dir_open_meta(TSK_FS_INFO * fs, TSK_FS_DIR ** a_fs_dir,
    TSK_INUM_T a_addr)
{
    REGFS_INFO *ntfs = (REGFS_INFO *) fs;
    return 0;
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
    UTF16 *name16;
    UTF8 *name8;
    int retVal;

    tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
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

    name16 = (UTF16 *) reg->regf.hive_name;
    name8 = (UTF8 *) asc;
    retVal = tsk_UTF16toUTF8(fs->endian, 
			     (const UTF16 **) &name16,
			     (UTF16 *) ((uintptr_t) name16 + 32),
			     &name8,
			     (UTF8 *) ((uintptr_t) name8 + sizeof(asc)),
			     TSKlenientConversion);
    if (retVal != TSKconversionOK) {
      if (tsk_verbose)
	tsk_fprintf(stderr,
		    "fsstat: Error converting REGF hive name label to UTF8: %d",
		    retVal);
      *name8 = '\0';
    }
    else if ((uintptr_t) name8 >= (uintptr_t) asc + sizeof(asc)) {
      /* Make sure it is NULL Terminated */
      asc[sizeof(asc) - 1] = '\0';
    }
    else {
      *name8 = '\0';
    }
    tsk_fprintf(hFile, "Hive name: %s\n", asc);    


    tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Offset to first key: %" PRIu32 "\n",
		(tsk_getu32(fs->endian, reg->regf.first_key_offset)));

    tsk_fprintf(hFile, "Offset to last HBIN: %" PRIu32 "\n",
		(tsk_getu32(fs->endian, reg->regf.last_hbin_offset)));

    tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Number of active cells: <unknown>\n"); //  TODO(wb)
    tsk_fprintf(hFile, "Number of inactive cells: <unknown>\n"); //  TODO(wb)
    tsk_fprintf(hFile, "Number of active bytes: <unknown>\n"); //  TODO(wb)
    tsk_fprintf(hFile, "Number of inactive bytes: <unknown>\n"); //  TODO(wb)
    tsk_fprintf(hFile, "Number of VK records: <unknown>\n"); //  TODO(wb)
    tsk_fprintf(hFile, "Number of NK records: <unknown>\n"); //  TODO(wb)
    tsk_fprintf(hFile, "Number of LF records: <unknown>\n"); //  TODO(wb)
    tsk_fprintf(hFile, "Number of LH records: <unknown>\n"); //  TODO(wb)
    tsk_fprintf(hFile, "Number of LI records: <unknown>\n"); //  TODO(wb)
    tsk_fprintf(hFile, "Number of RI records: <unknown>\n"); //  TODO(wb)
    tsk_fprintf(hFile, "Number of SK records: <unknown>\n"); //  TODO(wb)
    tsk_fprintf(hFile, "Number of DB records: <unknown>\n"); //  TODO(wb)

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
reg_load_cell(TSK_FS_INFO *fs, REGFS_CELL *cell, TSK_INUM_T inum) {
  ssize_t count;
  uint32_t len;
  uint16_t type;
  uint8_t  buf[4];

  // TODO(wb): Check range of file vs. inum value
  
  count = tsk_fs_read(fs, inum, buf, 4);
  if (count != 4) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_READ);
    tsk_error_set_errstr("Failed to read cell structure");
    return TSK_ERR;
  }

  len = (tsk_getu32(fs->endian, buf));
  if (len & 1 << 31) {
    cell->is_allocated = 1;
    cell->length = (-1 * tsk_gets32(fs->endian, buf));
  } else {
    cell->is_allocated = 0;
    cell->length = (tsk_getu32(fs->endian, buf));
  }
  if (cell->length >= 4096) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
    tsk_error_set_errstr("Registry cell corrupt: size too large");
    return TSK_ERR;
  }

  count = tsk_fs_read(fs, inum + 4, buf, 2);
  if (count != 2) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_READ);
    tsk_error_set_errstr("Failed to read cell structure");
    return TSK_ERR;
  }
  type = (tsk_getu16(fs->endian, buf));

  switch (type) {
  case 0x766b:
    cell->type = TSK_REGFS_RECORD_TYPE_VK;
    break;
  case 0x6e6b:
    cell->type = TSK_REGFS_RECORD_TYPE_NK;
    break;
  case 0x6c66:
    cell->type = TSK_REGFS_RECORD_TYPE_LF;
    break;
  case 0x6c68:
    cell->type = TSK_REGFS_RECORD_TYPE_LH;
    break;
  case 0x6c69:
    cell->type = TSK_REGFS_RECORD_TYPE_LI;
    break;
  case 0x7269:
    cell->type = TSK_REGFS_RECORD_TYPE_RI;
    break;
  case 0x736b:
    cell->type = TSK_REGFS_RECORD_TYPE_SK;
    break;
  case 0x6462:
    cell->type = TSK_REGFS_RECORD_TYPE_DB;
    break;
  default:
    cell->type = TSK_REGFS_RECORD_TYPE_UNKNOWN;
    break;
  }
  
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
    REGFS_INFO *reg = (REGFS_INFO *) fs;
    REGFS_CELL cell;

    tsk_fprintf(hFile, "CELL INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");


    if (reg_load_cell(fs, &cell, inum) != TSK_OK) {
      return 1;
    }

      tsk_fprintf(hFile, "Cell: " PRIuINUM "\n", inum);    
    if (cell.is_allocated) {
      tsk_fprintf(hFile, "Allocated: %s\n", "Yes");    
    } else {
      tsk_fprintf(hFile, "Allocated: %s\n", "No");    
    }
    tsk_fprintf(hFile, "Cell Size: " PRIuINUM "\n", cell.length);

    return 0;
}

static void
reg_close(TSK_FS_INFO * fs)
{
    REGFS_INFO *reg = (REGFS_INFO *) fs;

    if (fs == NULL)
        return;
    tsk_fs_free(fs);
}

int
reg_name_cmp(TSK_FS_INFO * a_fs_info, const char *s1, const char *s2)
{
    return strcasecmp(s1, s2);
}

/** \internal
 * NTFS-specific function (pointed to in FS_INFO) that maps a security ID
 * to an ASCII printable string.
 * Read the contents of the STANDARD_INFORMATION attribute of a file
 * to get the security id. Once we have the security id, we will
 * search $Secure:$SII to find a matching security id. That $SII entry
 * will contain the offset within the $SDS stream for the $SDS entry,
 * which contains the owner SID
 *
 * @param a_fs_file File to get security info on
 * @param sid_str [out] location where string representation of security info will be stored.
 Caller must free the string.
 * @returns 1 on error
 */
static uint8_t
reg_file_get_sidstr(TSK_FS_FILE * a_fs_file, char **sid_str)
{
    return 0;
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
 * @param test NOT USED * @returns NULL on error or if data is not a Registry
 */
TSK_FS_INFO *
regfs_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
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


    fs->first_inum = 4096;
    fs->last_inum  = (tsk_getu32(fs->endian, reg->regf.last_hbin_offset)) + 4096;


    fs->inode_walk = reg_inode_walk;
    fs->block_walk = reg_block_walk;
    fs->block_getflags = reg_block_getflags;

    fs->get_default_attr_type = reg_get_default_attr_type;
    fs->load_attrs = reg_load_attrs;

    fs->file_add_meta = reg_inode_lookup;
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
