/*
** xtaffs_dent
** The Sleuth Kit 
**
** file name layer support for the FAT file system
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2008 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
** Unicode added with support from I.D.E.A.L. Technology Corp (Aug '05)
**
*/

/**
 * \file xtaffs_dent.c
 * Contains the internal TSK FAT file name processing code.
 */

#include "tsk_fs_i.h"
#include "tsk_xtaffs.h"

/*
 * DESIGN NOTES
 *
 * the basic goal of this code is to parse directory entry structures for
 * file names.  The main function is xtaffs_parse_buf, which parses
 * a buffer and stores the entries in FS_DIR.  That structure is then
 * used by dir_get() or dir_walk() to provide the data back to the user. 
 *
 * One of the odd aspects of this code is that the 'inode' values are
 * the 'slot-address'.  Refer to the document on how FAT was implemented
 * for more details. This means that we need to search for the actual
 * 'inode' address for the '.' and '..' entries though!  The search
 * for '..' is quite painful if this code is called from a random 
 * location.  It does save what the parent is though, so the search
 * only has to be done once per session.
 */



/* Special data structure allocated for each directory to hold the long
 * file name entries until all entries have been found */
typedef struct {
    uint8_t name[XTAFFS_MAXNAMLEN_UTF8]; /* buffer for lfn - in reverse order */
    uint16_t start;             /* current start of name */
    uint8_t chk;                /* current checksum */
    uint8_t seq;                /* seq of first entry in lfn */
} XTAFFS_LFN;



/*
 * name_walk callback used when finding the parent directory.  It
 * forces the walking process to stop when we hit a target directory.
 * A list of directory to parent directory mappings is built up during
 * the walk and this function is used to stop that building process.
 */
static TSK_WALK_RET_ENUM
find_parent_act(TSK_FS_FILE * fs_file, const char *a_path, void *ptr)
{
    TSK_INUM_T par_inum = *(TSK_INUM_T *) ptr;

    if ((fs_file->meta == NULL)
        || (fs_file->meta->type != TSK_FS_META_TYPE_DIR))
        return TSK_WALK_CONT;

    if (fs_file->meta->addr == par_inum)
        return TSK_WALK_STOP;

    return TSK_WALK_CONT;
}


uint8_t
xtaffs_dir_buf_add(XTAFFS_INFO * xtaffs, TSK_INUM_T par_inum,
    TSK_INUM_T dir_inum)
{
    size_t q;

    for (q = 0; q < xtaffs->dir_buf_next; q++) {
        if (xtaffs->dir_buf[q] == dir_inum) {
            return 0;
        }
    }


    // make sure we have room
    if (xtaffs->dir_buf_next == xtaffs->dir_buf_size) {
        xtaffs->dir_buf_size += 256;
        if ((xtaffs->dir_buf =
                (TSK_INUM_T *) tsk_realloc(xtaffs->dir_buf,
                    xtaffs->dir_buf_size * sizeof(TSK_INUM_T))) == NULL) {
            return 1;
        }
        if ((xtaffs->par_buf =
                (TSK_INUM_T *) tsk_realloc(xtaffs->par_buf,
                    xtaffs->dir_buf_size * sizeof(TSK_INUM_T))) == NULL) {
            return 1;
        }
    }

    //add them
    xtaffs->dir_buf[xtaffs->dir_buf_next] = dir_inum;
    xtaffs->par_buf[xtaffs->dir_buf_next] = par_inum;
    xtaffs->dir_buf_next++;
    return 0;
}

/* 
 * Process the contents of a directory and add them to FS_DIR. 
 * 
 * @param xtaffs File system information structure
 * @param a_fs_dir Structure to store the files in. 
 * @param list_seen List of directory inodes that have been seen thus far in
 * directory walking (can be a pointer to a NULL pointer on first call). 
 * @param buf Buffer that contains the directory contents. 
 * @param len Length of buffer in bytes (must be a multiple of sector size)
 * @param addrs Array where each element is the original address of the 
 * corresponding block in buf (size of array is number of blocks in directory).
 *
 * @return -1 on error, 0 on success, and 1 to stop
 */
static TSK_RETVAL_ENUM
xtaffs_dent_parse_buf(XTAFFS_INFO * xtaffs, TSK_FS_DIR * a_fs_dir, char *buf,
    TSK_OFF_T len, TSK_DADDR_T * addrs)
{
    unsigned int idx, sidx;
    int a, b;
    TSK_INUM_T inode, ibase;
    xtaffs_dentry *dep;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & xtaffs->fs_info;
    int sectalloc;
    TSK_FS_NAME *fs_name;
    XTAFFS_LFN lfninfo;

    if (buf == NULL) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "xtaffs_dent_parse_buf: buffer is NULL");
        return TSK_ERR;
    }

    dep = (xtaffs_dentry *) buf;

    if ((fs_name = tsk_fs_name_alloc(XTAFFS_MAXNAMLEN_UTF8, 32)) == NULL) {
        return TSK_ERR;
    }

    memset(&lfninfo, 0, sizeof(XTAFFS_LFN));
    lfninfo.start = XTAFFS_MAXNAMLEN_UTF8 - 1;

    for (sidx = 0; sidx < (unsigned int) (len / xtaffs->ssize); sidx++) {

        /* Get the base inode for this sector */
        ibase = XTAFFS_SECT_2_INODE(xtaffs, addrs[sidx]);

        if (ibase > fs->last_inum) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_ARG;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "xtaffs_parse: inode address is too large");
            tsk_fs_name_free(fs_name);
            return TSK_COR;
        }

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "xtaffs_dent_parse_buf: Parsing sector %" PRIuDADDR
                "\n", addrs[sidx]);

        if ((sectalloc = xtaffs_is_sectalloc(xtaffs, addrs[sidx])) == -1) {
            if (tsk_verbose) {
                tsk_fprintf(stderr,
                    "xtaffs_dent_parse_buf: Error looking up sector allocation: %"
                    PRIuDADDR "\n", addrs[sidx]);
                tsk_error_print(stderr);
            }
            tsk_error_reset();
            continue;
        }

        /* cycle through the directory entries */
        for (idx = 0; idx < xtaffs->dentry_cnt_se; idx++, dep++) {
            xtaffs_dentry *dir;

            /* is it a valid dentry? */
            if (0 == xtaffs_isdentry(xtaffs, dep, (sectalloc)?1:0)) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "xtaffs_dent_parse_buf: Entry %u is invalid\n",
                        idx);
                continue;
            }
            

            /* Copy the directory entry into the TSK_FS_NAME structure */
            dir = (xtaffs_dentry *) dep;

            inode = ibase + idx;

            /* Take care of the name 
             * Copy a long name to a buffer and take action if it
             * is a small name 

            if ((dir->attrib & XTAFFS_ATTR_LFN) == XTAFFS_ATTR_LFN) {
                xtaffs_dentry_lfn *dirl = (xtaffs_dentry_lfn *) dir;

                * Store the name in dinfo until we get the 8.3 name 
                 * Use the checksum to identify a new sequence 
                 * *
                if (((dirl->seq & XTAFFS_LFN_SEQ_FIRST)
                        && (dirl->seq != XTAFFS_SLOT_DELETED))
                    || (dirl->chksum != lfninfo.chk)) {
                    // @@@ Do a partial output here


                    * Reset the values *
                    lfninfo.seq = dirl->seq & XTAFFS_LFN_SEQ_MASK;
                    lfninfo.chk = dirl->chksum;
                    lfninfo.start = XTAFFS_MAXNAMLEN_UTF8 - 1;

                }
                else if (dirl->seq != lfninfo.seq - 1) {
                    // @@@ Check the sequence number - the checksum is correct though...

                }

                * Copy the UTF16 values starting at end of buffer *
                for (a = 3; a >= 0; a--) {
                    if ((lfninfo.start > 0))
                        lfninfo.name[lfninfo.start--] = dirl->part3[a];
                }
                for (a = 11; a >= 0; a--) {
                    if ((lfninfo.start > 0))
                        lfninfo.name[lfninfo.start--] = dirl->part2[a];
                }
                for (a = 9; a >= 0; a--) {
                    if ((lfninfo.start > 0))
                        lfninfo.name[lfninfo.start--] = dirl->part1[a];
                }

                // Skip ahead until we get a new sequence num or the 8.3 name
                continue;
            }
*/
            /* Special case for volume label: name does not have an
             * extension and we add a note at the end that it is a label */
            if ((dir->attrib & XTAFFS_ATTR_VOLUME) ==
                XTAFFS_ATTR_VOLUME) {
                a = 0;

                for (b = 0; b < 42; b++) {
                    if(dir->name[b] < 33 || dir->name[b] > 126) break;
                    if ((dir->name[b] >= 0x20) && (dir->name[b] != 0xff)) {
                        fs_name->name[a++] = dir->name[b];
                    }
                    else {
                        fs_name->name[a++] = '^';
                    }
                }

                fs_name->name[a] = '\0';
                /* Append a string to show it is a label */
                if (a + 22 < XTAFFS_MAXNAMLEN_UTF8) {
                    char *volstr = " (Volume Label Entry)";
                    strncat(fs_name->name, volstr,
                        XTAFFS_MAXNAMLEN_UTF8 - a);
                }
            }

            /* A short (8.3) entry */
            else {
                char *name_ptr; // The dest location for the short name
               

                    fs_name->shrt_name[0] = '\0';
                    name_ptr = fs_name->name;   // put 8.3 into normal location

                /* copy in the short name into the place specified above. 
                 * Skip spaces and put in the . */
                a = 0;
                for (b = 0; b < 42; b++) {
                    if(dir->name[b] < 33 || dir->name[b] > 126) break;
                    if ((dir->name[b] != 0) && (dir->name[b] != 0xff) &&
                        (dir->name[b] != 0x20)) {

                        if ((b == 0)
                            && (dir->name[0] == XTAFFS_SLOT_DELETED)) {
                            name_ptr[a++] = '_';
                        }
                        else {
                            name_ptr[a++] = dir->name[b];
                        }
                    }
                }
                name_ptr[a] = '\0';
            }

            /* file type: FAT only knows DIR and FILE */
            if ((dir->attrib & XTAFFS_ATTR_DIRECTORY) ==
                XTAFFS_ATTR_DIRECTORY)
                fs_name->type = TSK_FS_NAME_TYPE_DIR;
            else
                fs_name->type = TSK_FS_NAME_TYPE_REG;

            /* Get inode */
            fs_name->meta_addr = inode;

            /* Handle the . and .. entries specially
             * The current inode 'address' they have is for the current
             * slot in the cluster, but it needs to refer to the original
             * slot 
             */
            if (TSK_FS_ISDOT(fs_name->name)) {
                if (fs_name->name[1] == '\0') {
                    inode = fs_name->meta_addr =
                        a_fs_dir->fs_file->meta->addr;
                }
                /* for the parent directory, look up in the list that 
                 * is maintained in fafs_info */
                else if (fs_name->name[1] == '.') {
                    size_t q;
                    uint8_t dir_found = 0;
                    for (q = 0; q < xtaffs->dir_buf_next; q++) {
                        if (xtaffs->dir_buf[q] ==
                            a_fs_dir->fs_file->meta->addr) {
                            inode = fs_name->meta_addr = xtaffs->par_buf[q];
                            dir_found = 1;
                            break;
                        }
                    }

                    if ((dir_found == 0) && (fs->isOrphanHunting)) {
                        /* if we are currently scanning the fs to determine the orphan files,
                         * then we do not care about the value of '..' and this can only cause
                         * infinite loop problems */
                        inode = fs_name->meta_addr = 0;
                        dir_found = 1;
                    }
                    if ((dir_found == 0)
                        && (addrs[0] == xtaffs->firstdatasect)) {
                        /* if we are currently in the root directory, we aren't going to find
                         * a parent.  This shouldn't happen, but could result in an infinite loop. */
                        inode = fs_name->meta_addr = 0;
                        dir_found = 1;
                    }
                    if (dir_found == 0) {
                        if (tsk_verbose)
                            fprintf(stderr,
                                "xtaffs_dent_parse_buf: Walking directory to find parent\n");

                        /* The parent directory is not in the list.  We are going to walk
                         * the directory until we hit this directory. This process will
                         * populate the buffer table and we will then rescan it */
                        if (tsk_fs_dir_walk(fs, fs->root_inum,
                                TSK_FS_DIR_WALK_FLAG_ALLOC |
                                TSK_FS_DIR_WALK_FLAG_UNALLOC |
                                TSK_FS_DIR_WALK_FLAG_RECURSE,
                                find_parent_act,
                                (void *) &a_fs_dir->fs_file->meta->addr)) {
                            return 0;
                        }

                        if (tsk_verbose)
                            fprintf(stderr,
                                "xtaffs_dent_parse_buf: Finished walking directory to find parent\n");

                        for (q = 0; q < xtaffs->dir_buf_next; q++) {
                            if (xtaffs->dir_buf[q] ==
                                a_fs_dir->fs_file->meta->addr) {
                                inode = fs_name->meta_addr =
                                    xtaffs->par_buf[q];
                                dir_found = 1;
                                break;
                            }
                        }
                        // if we did not find it, then it was probably 
                        // from the orphan directory...
                        if (dir_found == 0)
                            inode = fs_name->meta_addr =
                                TSK_FS_ORPHANDIR_INUM(fs);
                    }
                }
            }
            else {
                /* Save the (non-. or ..) directory to parent directory info to local
                 * structures so that we can later fill into the inode
                 * info for '..' entries */
                if (fs_name->type == TSK_FS_NAME_TYPE_DIR) {
                    if (xtaffs_dir_buf_add(xtaffs,
                            a_fs_dir->fs_file->meta->addr, inode))
                        return TSK_ERR;
                }
            }


            /* The allocation status of an entry is based on the allocation
             * status of the sector it is in and the flag.  Deleted directories
             * do not always clear the flags of each entry
             */
            if (sectalloc == 1) {
                fs_name->flags = (dep->name[0] == XTAFFS_SLOT_DELETED) ?
                    TSK_FS_NAME_FLAG_UNALLOC : TSK_FS_NAME_FLAG_ALLOC;
            }
            else {
                fs_name->flags = TSK_FS_NAME_FLAG_UNALLOC;
            }

            tsk_fs_dir_add(a_fs_dir, fs_name);
        }
    }
    tsk_fs_name_free(fs_name);

    return TSK_OK;
}



/**************************************************************************
 *
 * dent_walk
 *
 *************************************************************************/

/* values used to copy the directory contents into a buffer */


typedef struct {
    /* ptr to the current location in a local buffer */
    char *curdirptr;

    /* number of bytes left in curdirptr */
    size_t dirleft;

    /* ptr to a local buffer for the stack of sector addresses */
    TSK_DADDR_T *addrbuf;

    /* num of entries allocated to addrbuf */
    size_t addrsize;

    /* The current index in the addrbuf stack */
    size_t addridx;

} XTAFFS_LOAD_DIR;



/**
 * file walk callback that is used to load directory contents
 * into a buffer
 */
static TSK_WALK_RET_ENUM
xtaffs_dent_action(TSK_FS_FILE * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr,
    char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    XTAFFS_LOAD_DIR *load = (XTAFFS_LOAD_DIR *) ptr;

    /* how much of the buffer are we copying */
    size_t len = (load->dirleft < size) ? load->dirleft : size;

    /* Copy the sector into a buffer and increment the pointers */
    memcpy(load->curdirptr, buf, len);
    load->curdirptr = (char *) ((uintptr_t) load->curdirptr + len);
    load->dirleft -= len;

    /* fill in the stack of addresses of sectors 
     *
     * if we are at the last entry, then realloc more */
    if (load->addridx == load->addrsize) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "xtaffs_dent_walk: Trying to put more sector address in stack than were allocated (%lu)",
            (long) load->addridx);
        return TSK_WALK_ERROR;
    }

    /* Add this sector to the stack */
    load->addrbuf[load->addridx++] = addr;

    if (load->dirleft)
        return TSK_WALK_CONT;
    else
        return TSK_WALK_STOP;
}


/** \internal
* Process a directory and load up FS_DIR with the entries. If a pointer to
* an already allocated FS_DIR struture is given, it will be cleared.  If no existing
* FS_DIR structure is passed (i.e. NULL), then a new one will be created. If the return 
* value is error or corruption, then the FS_DIR structure could  
* have entries (depending on when the error occured). 
*
* @param a_fs File system to analyze
* @param a_fs_dir Pointer to FS_DIR pointer. Can contain an already allocated
* structure or a new structure. 
* @param a_addr Address of directory to process.
* @returns error, corruption, ok etc. 
*/

TSK_RETVAL_ENUM
xtaffs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir,
    TSK_INUM_T a_addr)
{
    TSK_OFF_T size, len;
    XTAFFS_INFO *xtaffs = (XTAFFS_INFO *) a_fs;
    char *dirbuf;
    TSK_DADDR_T *addrbuf;
    XTAFFS_LOAD_DIR load;
    int retval;

    TSK_FS_DIR *fs_dir;

    if ((a_addr < a_fs->first_inum) || (a_addr > a_fs->last_inum)) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "xtaffs_dir_open_meta: invalid a_addr value: %" PRIuINUM "\n",
            a_addr);
        return TSK_ERR;
    }
    else if (a_fs_dir == NULL) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "xtaffs_dir_open_meta: NULL fs_attr argument given");
        return TSK_ERR;
    }

    fs_dir = *a_fs_dir;
    if (fs_dir) {
        tsk_fs_dir_reset(fs_dir);
    }
    else {
        if ((*a_fs_dir = fs_dir = tsk_fs_dir_alloc(a_fs, a_addr, 128)) == NULL) {
            return TSK_ERR;
        }
    }

    //  handle the orphan directory if its contents were requested
    if (a_addr == TSK_FS_ORPHANDIR_INUM(a_fs)) {
        return tsk_fs_dir_find_orphans(a_fs, fs_dir);
    }

    fs_dir->fs_file = tsk_fs_file_open_meta(a_fs, NULL, a_addr);
    if (fs_dir->fs_file == NULL) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_INODE_NUM;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "xtaffs_dir_open_meta: %" PRIuINUM " is not a valid inode",
            a_addr);
        return TSK_COR;
    }

    size = fs_dir->fs_file->meta->size;
    len = roundup(size, xtaffs->ssize);

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "xtaffs_dir_open_meta: Processing directory %" PRIuINUM "\n",
            a_addr);

    if (size == 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "xtaffs_dir_open_meta: directory has 0 size\n");
        return TSK_OK;
    }

    /* Make a copy of the directory contents using file_walk */
    if ((dirbuf = tsk_malloc((size_t) len)) == NULL) {
        return TSK_ERR;
    }
    load.curdirptr = dirbuf;
    load.dirleft = (size_t) size;

    /* We are going to save the address of each sector in the directory
     * in a stack - they are needed to determine the inode address.  
     */
    load.addrsize = (size_t) (len / xtaffs->ssize);
    addrbuf =
        (TSK_DADDR_T *) tsk_malloc(load.addrsize * sizeof(TSK_DADDR_T));
    if (addrbuf == NULL) {
        free(dirbuf);
        return TSK_ERR;
    }

    /* Set the variables that are used during the copy */
    load.addridx = 0;
    load.addrbuf = addrbuf;

    /* save the directory contents into dirbuf */
    if (tsk_fs_file_walk(fs_dir->fs_file,
            TSK_FS_FILE_WALK_FLAG_SLACK,
            xtaffs_dent_action, (void *) &load)) {
        strncat(tsk_errstr2, " - xtaffs_dir_open_meta",
            TSK_ERRSTR_L - strlen(tsk_errstr2));
        free(dirbuf);
        free(addrbuf);
        return TSK_COR;
    }

    /* We did not copy the entire directory, which occurs if an error occured */
    if (load.dirleft > 0) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_FWALK;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "xtaffs_dir_open_meta: Error reading directory %" PRIuINUM,
            a_addr);

        /* Free the local buffers */
        free(dirbuf);
        free(addrbuf);
        return TSK_COR;
    }

    if (tsk_verbose)
        fprintf(stderr,
            "xtaffs_dir_open_meta: Parsing directory %" PRIuINUM "\n",
            a_addr);

    retval = xtaffs_dent_parse_buf(xtaffs, fs_dir, dirbuf, len, addrbuf);

    free(dirbuf);
    free(addrbuf);

    // if we are listing the root directory, add the Orphan directory and special FAT file entries
    if (a_addr == a_fs->root_inum) {
        TSK_FS_NAME *fs_name = tsk_fs_name_alloc(256, 0);
        if (fs_name == NULL)
            return TSK_ERR;

        // MBR Entry 
        strncpy(fs_name->name, XTAFFS_MBRNAME, fs_name->name_size);
        fs_name->meta_addr = XTAFFS_MBRINO(a_fs);
        fs_name->type = TSK_FS_NAME_TYPE_VIRT;
        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        // FAT1 Entry 
        strncpy(fs_name->name, XTAFFS_FAT1NAME, fs_name->name_size);
        fs_name->meta_addr = XTAFFS_FAT1INO(a_fs);
        fs_name->type = TSK_FS_NAME_TYPE_VIRT;
        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        // FAT2 Entry 
        strncpy(fs_name->name, XTAFFS_FAT2NAME, fs_name->name_size);
        fs_name->meta_addr = XTAFFS_FAT2INO(a_fs);
        fs_name->type = TSK_FS_NAME_TYPE_VIRT;
        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        // orphan directory
        if (tsk_fs_dir_make_orphan_dir_name(a_fs, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }
        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }
        tsk_fs_name_free(fs_name);
    }

    return retval;
}

int
xtaffs_name_cmp(TSK_FS_INFO * a_fs_info, const char *s1, const char *s2)
{
    return strcasecmp(s1, s2);
}
