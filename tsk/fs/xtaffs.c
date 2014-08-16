/*
** xtaffs
** The Sleuth Kit 
**
** Content and meta data layer support for the XTAF file system 
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
 * \file xtaffs.c
 * Contains the internal TSK FAT file system code to handle basic file system 
 * processing for opening file system, processing sectors, and directory entries. 
 */
#include "tsk_fs_i.h"
#include "tsk_xtaffs.h"

#define XTAF_SECTOR_SIZE 512
#define XTAF_FIRST_FAT_SECT 8
#define HD_VOID_AREA 8

/*
 * Implementation NOTES 
 *
 * TSK_FS_META contains the first cluster.  file_walk will return sector
 * values though because the cluster numbers do not start until after
 * the FAT.  That makes it very hard to address the first few blocks!
 *
 * Inodes numbers do not exist in FAT.  To make up for this we will count
 * directory entries as the inodes.   As the root directory does not have
 * any records in FAT, we will give it times of 0 and call it inode 2 to
 * keep consistent with UNIX.  After that, each 32-byte slot is numbered
 * as though it were a directory entry (even if it is not).  Therefore,
 * when an inode walk is performed, not all inode values will be displayed
 * even when '-e' is given for ils. 
 *
 * Progs like 'ils -e' are very slow because we have to look at each
 * block to see if it is a file system structure.
 */




/* TTL is 0 if the entry has not been used.  TTL of 1 means it was the
 * most recently used, and TTL of FAT_CACHE_N means it was the least 
 * recently used.  This function has a LRU replacement algo
 *
 * Note: This routine assumes &xtaffs->cache_lock is locked by the caller.
 */
// return -1 on error, or cache index on success (0 to FAT_CACHE_N)

static int getFATCacheIdx(XTAFFS_INFO * xtaffs, TSK_DADDR_T sect){
    int i, cidx;
    ssize_t cnt;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & xtaffs->fs_info;

    // see if we already have it in the cache
    for (i = 0; i < FAT_CACHE_N; i++) {
        if ((xtaffs->fatc_ttl[i] > 0) &&
            (sect >= xtaffs->fatc_addr[i]) &&
            (sect < (xtaffs->fatc_addr[i] + FAT_CACHE_S))) {
            int a;

            // update the TTLs to push i to the front
            for (a = 0; a < FAT_CACHE_N; a++) {
                if (xtaffs->fatc_ttl[a] == 0)
                    continue;

                if (xtaffs->fatc_ttl[a] < xtaffs->fatc_ttl[i])
                    xtaffs->fatc_ttl[a]++;
            }
            xtaffs->fatc_ttl[i] = 1;
//          fprintf(stdout, "FAT Hit: %d\n", sect);
//          fflush(stdout);
            return i;
        }
    }

//    fprintf(stdout, "FAT Miss: %d\n", (int)sect);
//    fflush(stdout);

    // Look for an unused entry or an entry with a TTL of FAT_CACHE_N
    cidx = 0;
    for (i = 0; i < FAT_CACHE_N; i++) {
        if ((xtaffs->fatc_ttl[i] == 0) ||
            (xtaffs->fatc_ttl[i] >= FAT_CACHE_N)) {
            cidx = i;
        }
    }
//    fprintf(stdout, "FAT Removing: %d\n", (int)xtaffs->fatc_addr[cidx]);
    //   fflush(stdout);

    // read the data
    cnt =
        tsk_fs_read(fs, sect * fs->block_size, xtaffs->fatc_buf[cidx],
        FAT_CACHE_B);
    if (cnt != FAT_CACHE_B) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("getFATCacheIdx: FAT: %" PRIuDADDR, sect);
        return -1;
    }

    // update the TTLs
    if (xtaffs->fatc_ttl[cidx] == 0)     // special case for unused entry
        xtaffs->fatc_ttl[cidx] = FAT_CACHE_N + 1;

    for (i = 0; i < FAT_CACHE_N; i++) {
        if (xtaffs->fatc_ttl[i] == 0)
            continue;

        if (xtaffs->fatc_ttl[i] < xtaffs->fatc_ttl[cidx])
            xtaffs->fatc_ttl[i]++;
    }

    xtaffs->fatc_ttl[cidx] = 1;
    xtaffs->fatc_addr[cidx] = sect;

    return cidx;
}


/*
 * Set *value to the entry in the File Allocation Table (FAT) 
 * for the given cluster
 *
 * *value is in clusters and may need to be coverted to
 * sectors by the calling function
 *
 * Invalid values in the FAT (i.e. greater than the largest
 * cluster have a value of 0 returned and a 0 return value.
 *
 * Return 1 on error and 0 on success
 */
uint8_t
xtaffs_getFAT(XTAFFS_INFO * xtaffs, TSK_DADDR_T clust, TSK_DADDR_T * value)
{
    uint8_t *a_ptr;
    uint16_t tmp16;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & xtaffs->fs_info;
    TSK_DADDR_T sect, offs;
    ssize_t cnt;
    int cidx;

    /* Sanity Check */
    if (clust > xtaffs->lastclust) {
        /* silently ignore requests for the unclustered sectors... */
        if ((clust == xtaffs->lastclust + 1) &&
            ((xtaffs->firstclustsect + xtaffs->csize * xtaffs->clustcnt -
                    1) != fs->last_block)) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "xtaffs_getFAT: Ignoring request for non-clustered sector\n");
            return 0;
        }

        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("xtaffs_getFAT: invalid cluster address: %"
            PRIuDADDR " (last cluster of FS: %" PRIuDADDR ")", clust, xtaffs->lastclust);
        return 1;
    }

    switch (xtaffs->fs_info.ftype) {
    case TSK_FS_TYPE_XTAF12:
        if (clust & 0xf000) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_ARG);
            tsk_error_set_errstr
                ("xtaffs_getFAT: TSK_FS_TYPE_XTAF12 Cluster %" PRIuDADDR
                " too large", clust);
            return 1;
        }

        /* id the sector in the FAT */
        sect = xtaffs->firstfatsect +
            ((clust + (clust >> 1)) >> xtaffs->ssize_sh);

        tsk_take_lock(&xtaffs->cache_lock);

        /* Load the FAT if we don't have it */
        // see if it is in the cache
        if (-1 == (cidx = getFATCacheIdx(xtaffs, sect))) {
            tsk_release_lock(&xtaffs->cache_lock);
            return 1;
        }

        /* get the offset into the cache */
        offs = ((sect - xtaffs->fatc_addr[cidx]) << xtaffs->ssize_sh) +
            (clust + (clust >> 1)) % xtaffs->ssize;

        /* special case when the 12-bit value goes across the cache
         * we load the cache to start at this sect.  The cache
         * size must therefore be at least 2 sectors large 
         */
        if (offs == (FAT_CACHE_B - 1)) {

            // read the data -- TTLs will already have been updated
            cnt =
                tsk_fs_read(fs, sect * fs->block_size,
                xtaffs->fatc_buf[cidx], FAT_CACHE_B);
            if (cnt != FAT_CACHE_B) {
                tsk_release_lock(&xtaffs->cache_lock);
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2
                    ("xtaffs_getFAT: TSK_FS_TYPE_XTAF12 FAT overlap: %"
                    PRIuDADDR, sect);
                return 1;
            }
            xtaffs->fatc_addr[cidx] = sect;

            offs = (clust + (clust >> 1)) % xtaffs->ssize;
        }

        /* get pointer to entry in current buffer */
        a_ptr = (uint8_t *) xtaffs->fatc_buf[cidx] + offs;

        tmp16 = tsk_getu16(fs->endian, a_ptr);

        tsk_release_lock(&xtaffs->cache_lock);

        /* slide it over if it is one of the odd clusters */
        if (clust & 1)
            tmp16 >>= 4;

        *value = tmp16 & XTAFFS_12_MASK;

        /* sanity check */
        if ((*value > (xtaffs->lastclust)) &&
            (*value < (0x0ffffff7 & XTAFFS_12_MASK))) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "xtaffs_getFAT: TSK_FS_TYPE_XTAF12 cluster (%" PRIuDADDR
                    ") too large (%" PRIuDADDR ") - resetting\n", clust,
                    *value);
            *value = 0;
        }
        return 0;

    case TSK_FS_TYPE_XTAF16:
        /* Get sector in FAT for cluster and load it if needed */
        sect = xtaffs->firstfatsect + ((clust << 1) >> xtaffs->ssize_sh);

        tsk_take_lock(&xtaffs->cache_lock);

        if (-1 == (cidx = getFATCacheIdx(xtaffs, sect))) {
            tsk_release_lock(&xtaffs->cache_lock);
            return 1;
        }


        /* get pointer to entry in the cache buffer */
        a_ptr = (uint8_t *) xtaffs->fatc_buf[cidx] +
            ((sect - xtaffs->fatc_addr[cidx]) << xtaffs->ssize_sh) +
            ((clust << 1) % xtaffs->ssize);

        *value = tsk_getu16(fs->endian, a_ptr) & XTAFFS_16_MASK;

        tsk_release_lock(&xtaffs->cache_lock);

        /* sanity check */
        if ((*value > (xtaffs->lastclust)) &&
            (*value < (0x0ffffff7 & XTAFFS_16_MASK))) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "xtaffs_getFAT: contents of TSK_FS_TYPE_XTAF16 entry %"
                    PRIuDADDR " too large - resetting\n", clust);
            *value = 0;
        }
        return 0;

    case TSK_FS_TYPE_XTAF32:
        /* Get sector in FAT for cluster and load if needed */
        sect = xtaffs->firstfatsect + ((clust << 2) >> xtaffs->ssize_sh);

        tsk_take_lock(&xtaffs->cache_lock);

        if (-1 == (cidx = getFATCacheIdx(xtaffs, sect))) {
            tsk_release_lock(&xtaffs->cache_lock);
            return 1;
        }


        /* get pointer to entry in current buffer */
        a_ptr = (uint8_t *) xtaffs->fatc_buf[cidx] +
            ((sect - xtaffs->fatc_addr[cidx]) << xtaffs->ssize_sh) +
            (clust << 2) % xtaffs->ssize;

        *value = tsk_getu32(fs->endian, a_ptr) & XTAFFS_32_MASK;

        tsk_release_lock(&xtaffs->cache_lock);

        /* sanity check */
        if ((*value > xtaffs->lastclust) &&
            (*value < (0x0ffffff7 & XTAFFS_32_MASK))) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "xtaffs_getFAT: contents of entry %" PRIuDADDR
                    " too large - resetting\n", clust);

            *value = 0;
        }
        return 0;

    default:
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("xtaffs_getFAT: Unknown FAT type: %d",
            xtaffs->fs_info.ftype);
        return 1;
    }
}


/* Return 1 if allocated, 0 if unallocated, and -1 if error */
int8_t
xtaffs_is_clustalloc(XTAFFS_INFO * xtaffs, TSK_DADDR_T clust)
{
    TSK_DADDR_T content;
    if (xtaffs_getFAT(xtaffs, clust, &content))
        return -1;
    else if (content == XTAFFS_UNALLOC)
        return 0;
    else
        return 1;
}


/* 
 * Identifies if a sector is allocated
 *
 * If it is less than the data area, then it is allocated
 * else the FAT table is consulted
 *
 * Return 1 if allocated, 0 if unallocated, and -1 if error 
 */
int8_t
xtaffs_is_sectalloc(XTAFFS_INFO * xtaffs, TSK_DADDR_T sect)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) xtaffs;
    /* If less than the first cluster sector, then it is allocated 
     * otherwise check the FAT
     */
    if (sect < xtaffs->firstclustsect)
        return 1;

    /* If we are in the unused area, then we are "unalloc" */
    if ((sect <= fs->last_block) &&
        (sect >= (xtaffs->firstclustsect + xtaffs->csize * xtaffs->clustcnt)))
        return 0;

    return xtaffs_is_clustalloc(xtaffs, XTAFFS_SECT_2_CLUST(xtaffs, sect));
}




TSK_FS_BLOCK_FLAG_ENUM
xtaffs_block_getflags(TSK_FS_INFO * a_fs, TSK_DADDR_T a_addr)
{
    XTAFFS_INFO *xtaffs = (XTAFFS_INFO *) a_fs;
    int flags = 0;

    // FATs and boot sector
    if (a_addr < xtaffs->firstdatasect) {
        flags = TSK_FS_BLOCK_FLAG_META | TSK_FS_BLOCK_FLAG_ALLOC;
    }
    // root directory for FAT12/16
    else if (a_addr < xtaffs->firstclustsect) {
        flags = TSK_FS_BLOCK_FLAG_CONT | TSK_FS_BLOCK_FLAG_ALLOC;
    }
    else {
        int retval;
        flags = TSK_FS_BLOCK_FLAG_CONT;

        /* Identify its allocation status */
        retval = xtaffs_is_sectalloc(xtaffs, a_addr);
        if (retval != -1) {
            if (retval == 1)
                flags |= TSK_FS_BLOCK_FLAG_ALLOC;
            else
                flags |= TSK_FS_BLOCK_FLAG_UNALLOC;
        }
    }
    return flags;
}



/**************************************************************************
 *
 * BLOCK WALKING
 * 
 *************************************************************************/
/* 
** Walk the sectors of the partition. 
**
** NOTE: This is by SECTORS and not CLUSTERS
** _flags: TSK_FS_BLOCK_FLAG_ALLOC, TSK_FS_BLOCK_FLAG_UNALLOC, TSK_FS_BLOCK_FLAG_META
**  TSK_FS_BLOCK_FLAG_CONT
**
*/
uint8_t
xtaffs_block_walk(TSK_FS_INFO * fs, TSK_DADDR_T a_start_blk,
    TSK_DADDR_T a_end_blk, TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags,
    TSK_FS_BLOCK_WALK_CB a_action, void *a_ptr)
{
    char *myname = "xtaffs_block_walk";
    XTAFFS_INFO *xtaffs = (XTAFFS_INFO *) fs;
    char *data_buf = NULL;
    ssize_t cnt;
    TSK_FS_BLOCK *fs_block;

    TSK_DADDR_T addr;
    int myflags;
    unsigned int i;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity checks.
     */
    if (a_start_blk < fs->first_block || a_start_blk > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: Start block: %" PRIuDADDR "", myname,
            a_start_blk);
        return 1;
    }
    if (a_end_blk < fs->first_block || a_end_blk > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: End block: %" PRIuDADDR "", myname,
            a_end_blk);
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "xtaffs_block_walk: Block Walking %" PRIuDADDR " to %"
            PRIuDADDR "\n", a_start_blk, a_end_blk);


    /* Sanity check on a_flags -- make sure at least one ALLOC is set */
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

    /* cycle through the sectors.  We do the sectors before the first
     * cluster seperate from the data area */
    addr = a_start_blk;

    /* Before the data area beings (FAT, root directory etc.) */
    if ((a_start_blk < xtaffs->firstclustsect)
        && (a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)) {

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "xtaffs_block_walk: Walking non-data area (pre %"
                PRIuDADDR "\n", xtaffs->firstclustsect);

        if ((data_buf = (char *) tsk_malloc(fs->block_size * 8)) == NULL) {
            tsk_fs_block_free(fs_block);
            return 1;
        }

        /* Read 8 sectors at a time to be faster */
        for (; addr < xtaffs->firstclustsect && addr <= a_end_blk;) {

            if ((a_flags & TSK_FS_BLOCK_WALK_FLAG_AONLY) == 0) {
                cnt =
                    tsk_fs_read_block(fs, addr, data_buf, fs->block_size * 8);
                if (cnt != fs->block_size * 8) {
                    if (cnt >= 0) {
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_FS_READ);
                    }
                    tsk_error_set_errstr2
                        ("xtaffs_block_walk: pre-data area block: %" PRIuDADDR,
                        addr);
                    free(data_buf);
                    tsk_fs_block_free(fs_block);
                    return 1;
                }
            }

            /* Process the sectors until we get to the clusters, 
             * end of target, or end of buffer */
            for (i = 0;
                i < 8 && (addr) <= a_end_blk
                && (addr) < xtaffs->firstclustsect; i++, addr++) {
                int retval;

                myflags = TSK_FS_BLOCK_FLAG_ALLOC;

                /* stuff before the first data sector is the 
                 * FAT and boot sector */
                if (addr < xtaffs->firstdatasect)
                    myflags |= TSK_FS_BLOCK_FLAG_META;
                /* This must be the root directory for FAT12/16 */
                else
                    myflags |= TSK_FS_BLOCK_FLAG_CONT;

                // test this sector (we already tested ALLOC)
                if ((myflags & TSK_FS_BLOCK_FLAG_META)
                    && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_META)))
                    continue;
                else if ((myflags & TSK_FS_BLOCK_FLAG_CONT)
                    && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT)))
                    continue;

                if (a_flags & TSK_FS_BLOCK_WALK_FLAG_AONLY)
                    myflags |= TSK_FS_BLOCK_FLAG_AONLY;

                tsk_fs_block_set(fs, fs_block, addr,
                    myflags | TSK_FS_BLOCK_FLAG_RAW,
                    &data_buf[i * fs->block_size]);

                retval = a_action(fs_block, a_ptr);
                if (retval == TSK_WALK_STOP) {
                    free(data_buf);
                    tsk_fs_block_free(fs_block);
                    return 0;
                }
                else if (retval == TSK_WALK_ERROR) {
                    free(data_buf);
                    tsk_fs_block_free(fs_block);
                    return 1;
                }
            }
        }

        free(data_buf);

        /* Was that it? */
        if (addr >= a_end_blk) {
            tsk_fs_block_free(fs_block);
            return 0;
        }
    }
    /* Reset the first sector to the start of the data area if we did
     * not examine it - the next calculation will screw up otherwise */
    else if (addr < xtaffs->firstclustsect) {
        addr = xtaffs->firstclustsect;
    }


    /* Now we read in the clusters in cluster-sized chunks,
     * sectors are too small
     */

    /* Determine the base sector of the cluster where the first 
     * sector is located */
    addr = XTAFFS_CLUST_2_SECT(xtaffs, (XTAFFS_SECT_2_CLUST(xtaffs, addr)));

    if ((data_buf = tsk_malloc(fs->block_size * xtaffs->csize)) == NULL) {
        tsk_fs_block_free(fs_block);
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "xtaffs_block_walk: Walking data area blocks (%" PRIuDADDR
            " to %" PRIuDADDR ")\n", addr, a_end_blk);

    for (; addr <= a_end_blk; addr += xtaffs->csize) {
        int retval;
        size_t read_size;

        /* Identify its allocation status */
        retval = xtaffs_is_sectalloc(xtaffs, addr);
        if (retval == -1) {
            free(data_buf);
            tsk_fs_block_free(fs_block);
            return 1;
        }
        else if (retval == 1) {
            myflags = TSK_FS_BLOCK_FLAG_ALLOC;
        }
        else {
            myflags = TSK_FS_BLOCK_FLAG_UNALLOC;
        }

        /* At this point, there should be no more meta - just content */
        myflags |= TSK_FS_BLOCK_FLAG_CONT;

        // test if we should call the callback with this one
        if ((myflags & TSK_FS_BLOCK_FLAG_CONT)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_ALLOC)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_UNALLOC)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC)))
            continue;

        if (a_flags & TSK_FS_BLOCK_WALK_FLAG_AONLY)
            myflags |= TSK_FS_BLOCK_FLAG_AONLY;


        /* The final cluster may not be full */
        if (a_end_blk - addr + 1 < xtaffs->csize)
            read_size = (size_t) (a_end_blk - addr + 1);
        else
            read_size = xtaffs->csize;

        if ((a_flags & TSK_FS_BLOCK_WALK_FLAG_AONLY) == 0) {
            cnt = tsk_fs_read_block
                (fs, addr, data_buf, fs->block_size * read_size);
            if (cnt != fs->block_size * read_size) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2("xtaffs_block_walk: block: %" PRIuDADDR,
                    addr);
                free(data_buf);
                tsk_fs_block_free(fs_block);
                return 1;
            }
        }

        /* go through each sector in the cluster */
        for (i = 0; i < read_size; i++) {
            int retval;

            if (addr + i < a_start_blk)
                continue;
            else if (addr + i > a_end_blk)
                break;

            tsk_fs_block_set(fs, fs_block, addr + i,
                myflags | TSK_FS_BLOCK_FLAG_RAW,
                &data_buf[i * fs->block_size]);

            retval = a_action(fs_block, a_ptr);
            if (retval == TSK_WALK_STOP) {
                free(data_buf);
                tsk_fs_block_free(fs_block);
                return 0;
            }
            else if (retval == TSK_WALK_ERROR) {
                free(data_buf);
                tsk_fs_block_free(fs_block);
                return 1;
            }
        }
    }

    free(data_buf);
    tsk_fs_block_free(fs_block);
    return 0;
}





/* return 1 on error and 0 on success */
static uint8_t
xtaffs_fscheck(TSK_FS_INFO * fs, FILE * hFile)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("fscheck not implemented for XTAF yet");
    return 1;

    /* Check that allocated dentries point to start of allcated cluster chain */


    /* Size of file is consistent with cluster chain length */


    /* Allocated cluster chains have a corresponding alloc dentry */


    /* Non file dentries have no clusters */


    /* Only one volume label */


    /* Dump Bad Sector Addresses */


    /* Dump unused sector addresses 
     * Reserved area, end of FAT, end of Data Area */

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
xtaffs_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
    unsigned int i;
    int a;
    TSK_DADDR_T next, snext, sstart, send;
    XTAFFS_INFO *xtaffs = (XTAFFS_INFO *) fs;
    xtaffs_sb *sb = xtaffs->sb;
    char *data_buf;
    xtaffs_dentry *de;
    ssize_t cnt;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((data_buf = (char *) tsk_malloc(fs->block_size)) == NULL) {
        return 1;
    }


    /* AJN TODO Replace this with an XTAF function that reads name.txt */
    /* Read the root directory sector so that we can get the volume
     * label from it */
    cnt = tsk_fs_read_block(fs, xtaffs->rootsect, data_buf, fs->block_size);
    if (cnt != fs->block_size) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("xtaffs_fsstat: root directory: %" PRIuDADDR,
            xtaffs->rootsect);
        free(data_buf);
        return 1;
    }


    /* Find the dentry that is set as the volume label */
    de = (xtaffs_dentry *) data_buf;
    for (i = 0; i < xtaffs->ssize; i += sizeof(*de)) {
        if (de->attrib == XTAFFS_ATTR_VOLUME)
            break;
        de++;
    }
    /* If we didn't find it, then reset de */
    if (de->attrib != XTAFFS_ATTR_VOLUME)
        de = NULL;


    /* Print the general file system information */

    tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "File System Type: XTAF");
    if (fs->ftype == TSK_FS_TYPE_XTAF12)
        tsk_fprintf(hFile, "12\n");
    else if (fs->ftype == TSK_FS_TYPE_XTAF16)
        tsk_fprintf(hFile, "16\n");
    else if (fs->ftype == TSK_FS_TYPE_XTAF32)
        tsk_fprintf(hFile, "32\n");
    else
        tsk_fprintf(hFile, "\n");

    if (xtaffs->fs_info.ftype != TSK_FS_TYPE_XTAF32) {
        tsk_fprintf(hFile, "Serial number: 0x%" PRIx32 "\n",
            tsk_getu32(fs->endian, sb->serial_number));
    }
    else {
        tsk_fprintf(hFile, "Serial number: 0x%" PRIx32 "\n",
            tsk_getu32(fs->endian, sb->serial_number));
    }

    free(data_buf);

    tsk_fprintf(hFile, "\nFile System Layout (in sectors)\n");

    tsk_fprintf(hFile, "Total Range: %" PRIuDADDR " - %" PRIuDADDR "\n",
        fs->first_block, fs->last_block);

    if (fs->last_block != fs->last_block_act)
        tsk_fprintf(hFile,
            "Total Range in Image: %" PRIuDADDR " - %" PRIuDADDR "\n",
            fs->first_block, fs->last_block_act);

    tsk_fprintf(hFile, "* Reserved: 0 - %" PRIuDADDR "\n",
        xtaffs->firstfatsect - 1);

    tsk_fprintf(hFile, "** Boot Sector: 0\n");

    for (i = 0; i < xtaffs->numfat; i++) {
        TSK_DADDR_T base = xtaffs->firstfatsect + i * (xtaffs->sectperfat);

        tsk_fprintf(hFile, "* FAT %d: %" PRIuDADDR " - %" PRIuDADDR "\n",
            i, base, (base + xtaffs->sectperfat - 1));
    }

    tsk_fprintf(hFile, "* Data Area: %" PRIuDADDR " - %" PRIuDADDR "\n",
        xtaffs->firstdatasect, fs->last_block);

    if (xtaffs->fs_info.ftype != TSK_FS_TYPE_XTAF32) {
        TSK_DADDR_T x = xtaffs->csize * xtaffs->clustcnt;

        tsk_fprintf(hFile,
            "** Root Directory: %" PRIuDADDR " - %" PRIuDADDR "\n",
            xtaffs->firstdatasect, xtaffs->firstclustsect - 1);

        tsk_fprintf(hFile,
            "** Cluster Area: %" PRIuDADDR " - %" PRIuDADDR "\n",
            xtaffs->firstclustsect, (xtaffs->firstclustsect + x - 1));

        if ((xtaffs->firstclustsect + x - 1) != fs->last_block) {
            tsk_fprintf(hFile,
                "** Non-clustered: %" PRIuDADDR " - %" PRIuDADDR "\n",
                (xtaffs->firstclustsect + x), fs->last_block);
        }
    }
    else {
        TSK_LIST *list_seen = NULL;
        TSK_DADDR_T x = xtaffs->csize * (xtaffs->lastclust - 1);
        TSK_DADDR_T clust, clust_p;

        tsk_fprintf(hFile,
            "** Cluster Area: %" PRIuDADDR " - %" PRIuDADDR "\n",
            xtaffs->firstclustsect, (xtaffs->firstclustsect + x - 1));


        clust_p = xtaffs->rootsect;
        clust = XTAFFS_SECT_2_CLUST(xtaffs, xtaffs->rootsect);
        while ((clust) && (0 == XTAFFS_ISEOF(clust, XTAFFS_32_MASK))) {
            TSK_DADDR_T nxt;
            clust_p = clust;

            /* Make sure we do not get into an infinite loop */
            if (tsk_list_find(list_seen, clust)) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "Loop found while determining root directory size\n");
                break;
            }
            if (tsk_list_add(&list_seen, clust)) {
                tsk_list_free(list_seen);
                list_seen = NULL;
                return 1;
            }

            if (xtaffs_getFAT(xtaffs, clust, &nxt))
                break;
            clust = nxt;
        }
        tsk_list_free(list_seen);
        list_seen = NULL;

        tsk_fprintf(hFile,
            "*** Root Directory: %" PRIuDADDR " - %" PRIuDADDR "\n",
            xtaffs->rootsect, (XTAFFS_CLUST_2_SECT(xtaffs, clust_p + 1) - 1));

        if ((xtaffs->firstclustsect + x - 1) != fs->last_block) {
            tsk_fprintf(hFile,
                "** Non-clustered: %" PRIuDADDR " - %" PRIuDADDR "\n",
                (xtaffs->firstclustsect + x), fs->last_block);
        }
    }


    tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Range: %" PRIuINUM " - %" PRIuINUM "\n",
        fs->first_inum, fs->last_inum);
    tsk_fprintf(hFile, "Root Directory: %" PRIuINUM "\n", fs->root_inum);


    tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Sector Size: %" PRIu16 "\n", xtaffs->ssize);
    tsk_fprintf(hFile, "Cluster Size: %" PRIu32 "\n",
        (uint32_t) xtaffs->csize << xtaffs->ssize_sh);

    tsk_fprintf(hFile, "Total Cluster Range: 2 - %" PRIuDADDR "\n",
        xtaffs->lastclust);


    /* cycle via cluster and look at each cluster in the FAT 
     * for clusters marked as bad */
    cnt = 0;
    for (i = 2; i <= xtaffs->lastclust; i++) {
        TSK_DADDR_T entry;
        TSK_DADDR_T sect;

        /* Get the FAT table entry */
        if (xtaffs_getFAT(xtaffs, i, &entry))
            break;

        if (XTAFFS_ISBAD(entry, xtaffs->mask) == 0) {
            continue;
        }

        if (cnt == 0)
            tsk_fprintf(hFile, "Bad Sectors: ");

        sect = XTAFFS_CLUST_2_SECT(xtaffs, i);
        for (a = 0; a < xtaffs->csize; a++) {
            tsk_fprintf(hFile, "%" PRIuDADDR " ", sect + a);
            if ((++cnt % 8) == 0)
                tsk_fprintf(hFile, "\n");
        }
    }
    if ((cnt > 0) && ((cnt % 8) != 0))
        tsk_fprintf(hFile, "\n");



    /* Display the FAT Table */
    tsk_fprintf(hFile, "\nFAT CONTENTS (in sectors)\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    /* 'sstart' marks the first sector of the current run to print */
    sstart = xtaffs->firstclustsect;

    /* cycle via cluster and look at each cluster in the FAT  to make runs */
    for (i = 2; i <= xtaffs->lastclust; i++) {

        /* 'send' marks the end sector of the current run, which will extend
         * when the current cluster continues to the next 
         */
        send = XTAFFS_CLUST_2_SECT(xtaffs, i + 1) - 1;

        /* get the next cluster */
        if (xtaffs_getFAT(xtaffs, i, &next))
            break;

        snext = XTAFFS_CLUST_2_SECT(xtaffs, next);

        /* we are also using the next sector (clust) */
        if ((next & xtaffs->mask) == (i + 1)) {
            continue;
        }

        /* The next clust is either further away or the clust is available,
         * print it if is further away 
         */
        else if ((next & xtaffs->mask)) {
            if (XTAFFS_ISEOF(next, xtaffs->mask))
                tsk_fprintf(hFile,
                    "%" PRIuDADDR "-%" PRIuDADDR " (%" PRIuDADDR
                    ") -> EOF\n", sstart, send, send - sstart + 1);
            else if (XTAFFS_ISBAD(next, xtaffs->mask))
                tsk_fprintf(hFile,
                    "%" PRIuDADDR "-%" PRIuDADDR " (%" PRIuDADDR
                    ") -> BAD\n", sstart, send, send - sstart + 1);
            else
                tsk_fprintf(hFile,
                    "%" PRIuDADDR "-%" PRIuDADDR " (%" PRIuDADDR
                    ") -> %" PRIuDADDR "\n", sstart, send,
                    send - sstart + 1, snext);
        }

        /* reset the starting counter */
        sstart = send + 1;
    }

    return 0;
}


/************************* istat *******************************/

/* Callback a_action for file_walk to print the sector addresses
 * of a file
 */

typedef struct {
    FILE *hFile;
    int idx;
    int istat_seen;
} XTAFFS_PRINT_ADDR;

static TSK_WALK_RET_ENUM
print_addr_act(TSK_FS_FILE * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr,
    char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM a_flags, void *a_ptr)
{
    XTAFFS_PRINT_ADDR *print = (XTAFFS_PRINT_ADDR *) a_ptr;

    tsk_fprintf(print->hFile, "%" PRIuDADDR " ", addr);

    if (++(print->idx) == 8) {
        tsk_fprintf(print->hFile, "\n");
        print->idx = 0;
    }
    print->istat_seen = 1;

    return TSK_WALK_CONT;
}



/**
 * Print details on a specific file to a file handle. 
 *
 * @param fs File system file is located in
 * @param hFile File handle to print text to
 * @param inum Address of file in file system
 * @param numblock The number of blocks in file to force print (can go beyond file size)
 * @param sec_skew Clock skew in seconds to also print times in
 * 
 * @returns 1 on error and 0 on success
 */
static uint8_t
xtaffs_istat(TSK_FS_INFO * fs, FILE * hFile, TSK_INUM_T inum,
    TSK_DADDR_T numblock, int32_t sec_skew)
{
    TSK_FS_META *fs_meta;
    TSK_FS_FILE *fs_file;
    TSK_FS_META_NAME_LIST *fs_name_list;
    XTAFFS_PRINT_ADDR print;
    xtaffs_dentry dep;
    char timeBuf[128];

    // clean up any error messages that are lying around
    tsk_error_reset();


    if ((fs_file = tsk_fs_file_open_meta(fs, NULL, inum)) == NULL) {
        return 1;
    }
    fs_meta = fs_file->meta;

    tsk_fprintf(hFile, "Directory Entry: %" PRIuINUM "\n", inum);

    tsk_fprintf(hFile, "%sAllocated\n",
        (fs_meta->flags & TSK_FS_META_FLAG_UNALLOC) ? "Not " : "");

    tsk_fprintf(hFile, "File Attributes: ");

    /* This should only be null if we have the root directory or special file */
    if (xtaffs_dinode_load(fs, &dep, inum)) {
        if (inum == XTAFFS_ROOTINO)
            tsk_fprintf(hFile, "Directory\n");
        else if (fs_file->meta->type == TSK_FS_META_TYPE_VIRT)
            tsk_fprintf(hFile, "Virtual\n");
        else
            tsk_fprintf(hFile, "File\n");
    }
    else if ((dep.attrib & XTAFFS_ATTR_LFN) == XTAFFS_ATTR_LFN) {
        tsk_fprintf(hFile, "Long File Name\n"); /*AJN TODO Scrap, XTAF doesn't have LFN's.*/
    }
    else {
        if (dep.attrib & XTAFFS_ATTR_DIRECTORY)
            tsk_fprintf(hFile, "Directory");
        else if (dep.attrib & XTAFFS_ATTR_VOLUME)
            tsk_fprintf(hFile, "Volume Label");
        else
            tsk_fprintf(hFile, "File");

        /*AJN TODO Confirm these attributes*/
        if (dep.attrib & XTAFFS_ATTR_READONLY)
            tsk_fprintf(hFile, ", Read Only");
        if (dep.attrib & XTAFFS_ATTR_HIDDEN)
            tsk_fprintf(hFile, ", Hidden");
        if (dep.attrib & XTAFFS_ATTR_SYSTEM)
            tsk_fprintf(hFile, ", System");
        if (dep.attrib & XTAFFS_ATTR_ARCHIVE)
            tsk_fprintf(hFile, ", Archive");

        tsk_fprintf(hFile, "\n");
    }

    tsk_fprintf(hFile, "Size: %" PRIuOFF "\n", fs_meta->size);

    if (fs_meta->name2) {
        fs_name_list = fs_meta->name2;
        tsk_fprintf(hFile, "Name: %s\n", fs_name_list->name);
    }

    if (sec_skew != 0) {
        tsk_fprintf(hFile, "\nAdjusted Directory Entry Times:\n");

        if (fs_meta->mtime)
            fs_meta->mtime -= sec_skew;
        if (fs_meta->atime)
            fs_meta->atime -= sec_skew;
        if (fs_meta->crtime)
            fs_meta->crtime -= sec_skew;

        tsk_fprintf(hFile, "Written:\t%s", ctime(&fs_meta->mtime));
        tsk_fprintf(hFile, "Accessed:\t%s", ctime(&fs_meta->atime));
        tsk_fprintf(hFile, "Created:\t%s", ctime(&fs_meta->crtime));

        if (fs_meta->mtime == 0)
            fs_meta->mtime += sec_skew;
        if (fs_meta->atime == 0)
            fs_meta->atime += sec_skew;
        if (fs_meta->crtime == 0)
            fs_meta->crtime += sec_skew;

        tsk_fprintf(hFile, "\nOriginal Directory Entry Times:\n");
    }
    else
        tsk_fprintf(hFile, "\nDirectory Entry Times:\n");

    tsk_fprintf(hFile, "Written:\t%s\n", tsk_fs_time_to_str(fs_meta->mtime,
            timeBuf));
    tsk_fprintf(hFile, "Accessed:\t%s\n",
        tsk_fs_time_to_str(fs_meta->atime, timeBuf));
    tsk_fprintf(hFile, "Created:\t%s\n",
        tsk_fs_time_to_str(fs_meta->crtime, timeBuf));

    tsk_fprintf(hFile, "\nSectors:\n");

    /* A bad hack to force a specified number of blocks */
    if (numblock > 0)
        fs_meta->size = numblock * fs->block_size;

    print.istat_seen = 0;
    print.idx = 0;
    print.hFile = hFile;

    if (tsk_fs_file_walk(fs_file,
            (TSK_FS_FILE_WALK_FLAG_AONLY | TSK_FS_FILE_WALK_FLAG_SLACK),
            print_addr_act, (void *) &print)) {
        tsk_fprintf(hFile, "\nError reading file\n");
        tsk_error_print(hFile);
        tsk_error_reset();
    }
    else if (print.idx != 0) {
        tsk_fprintf(hFile, "\n");
    }

    tsk_fs_file_close(fs_file);
    return 0;
}


/* return 1 on error and 0 on success */
uint8_t
xtaffs_jopen(TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("XTAF does not have a journal\n");
    return 1;
}

/* return 1 on error and 0 on success */
uint8_t
xtaffs_jentry_walk(TSK_FS_INFO * fs, int a_flags,
    TSK_FS_JENTRY_WALK_CB a_action, void *a_ptr)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("XTAF does not have a journal\n");
    return 1;
}


/* return 1 on error and 0 on success */
uint8_t
xtaffs_jblk_walk(TSK_FS_INFO * fs, TSK_DADDR_T start, TSK_DADDR_T end,
    int a_flags, TSK_FS_JBLK_WALK_CB a_action, void *a_ptr)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("XTAF does not have a journal\n");
    return 1;
}

static TSK_FS_ATTR_TYPE_ENUM
xtaffs_get_default_attr_type(const TSK_FS_FILE * a_file)
{
    return TSK_FS_ATTR_TYPE_DEFAULT;
}

/* xtaffs_close - close an xtaffs file system */
static void
xtaffs_close(TSK_FS_INFO * fs)
{
    XTAFFS_INFO *xtaffs = (XTAFFS_INFO *) fs;

    xtaffs_dir_buf_free(xtaffs);

    fs->tag = 0;

    free(xtaffs->sb);
    tsk_deinit_lock(&xtaffs->cache_lock);
    tsk_deinit_lock(&xtaffs->dir_lock);
	
    tsk_fs_free(fs);
}


/**
 * \internal
 * Open part of a disk image as a XTAF file system. 
 *
 * @param img_info Disk image to analyze
 * @param offset Byte offset where FAT file system starts
 * @param ftype Specific type of FAT file system
 * @param test NOT USED
 * @returns NULL on error or if data is not a FAT file system
 */
TSK_FS_INFO *
xtaffs_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
    TSK_FS_TYPE_ENUM ftype, uint8_t test)
{
    char *myname = "xtaffs_open";
    XTAFFS_INFO *xtaffs;
    unsigned int len;
    TSK_FS_INFO *fs;
    xtaffs_sb *fatsb; /*AJN TODO How often does 'fatsb' occur? It shouldn't anymore.*/
    TSK_DADDR_T sectors;
    ssize_t cnt;
    uint32_t fsopen_numfat, fsopen_csize;
    int i;
    uint8_t used_backup_boot = 0;       // set to 1 if we used the backup boot sector
    int is_xtaf = 0;
    TSK_OFF_T partition_size;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (TSK_FS_TYPE_ISXTAF(ftype) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: Invalid FS Type", myname);
        return NULL;
    }

    if ((xtaffs = (XTAFFS_INFO *) tsk_fs_malloc(sizeof(*xtaffs))) == NULL)
        return NULL;

    fs = &(xtaffs->fs_info);
    fs->ftype = ftype;

    fs->img_info = img_info;
    fs->offset = offset;
    fs->tag = TSK_FS_INFO_TAG;

    /*
     * Read the super block.
     */
    len = sizeof(xtaffs_sb);
    fatsb = xtaffs->sb = (xtaffs_sb *) tsk_malloc(len);
    if (fatsb == NULL) {
        fs->tag = 0;
        free(xtaffs);
        return NULL;
    }

    /* Look for the boot sector. We loop because
     * we will try the backup if the first fails.
     * Only FAT32 was known to have a backup though, and XTAF32's backups haven't been seen yet... */
    for (i = 0; i < 2; i++) {
        TSK_OFF_T sb_off;

        if (i == 0)
            sb_off = 0;
        else
            sb_off = 6 * img_info->sector_size; // the backup is located in sector 6


        cnt = tsk_fs_read(fs, sb_off, (char *) fatsb, len);
        if (cnt != len) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("%s: boot sector", myname);
            fs->tag = 0;
            free(xtaffs->sb);
            free(xtaffs);
            return NULL;
        }
        // If the XTAF label is found we're done, break out of loop
        if(strncmp((char *) fatsb->magic, "XTAF", 4) == 0){
          is_xtaf = 1;
          break;
        }
    }
    if(is_xtaf == 0){
        free(fatsb);
        free(xtaffs);
        return NULL;
    }

    fs->dev_bsize = img_info->sector_size;

    /* Calculate block sizes and layout info */
    // sector size AJN NOTE: Hard-coded to 512 for now, see macro variable. Is that right?(TODO)
    xtaffs->ssize = XTAF_SECTOR_SIZE;
    if (xtaffs->ssize == 512) {
        xtaffs->ssize_sh = 9;
    }
    else if (xtaffs->ssize == 1024) {
        xtaffs->ssize_sh = 10;
    }
    else if (xtaffs->ssize == 2048) {
        xtaffs->ssize_sh = 11;
    }
    else if (xtaffs->ssize == 4096) {
        xtaffs->ssize_sh = 12;
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr
            ("Error: sector size (%d) is not a multiple of device size (%d)\nDo you have a disk image instead of a partition image?",
            xtaffs->ssize, fs->dev_bsize);
        if (tsk_verbose)
            fprintf(stderr, "xtaffs_open: Invalid sector size (%d)\n",
                xtaffs->ssize);
        fs->tag = 0;
        free(fatsb);
        free(xtaffs);
        return NULL;
    }

    // cluster size 
    fsopen_csize = tsk_getu32(fs->endian, fatsb->csize);
    if(fsopen_csize > 256) fprintf(stderr, "%s: Warning: Sectors-per-cluster is more than 256!\n", myname);
    xtaffs->csize = (uint8_t) fsopen_csize; 
    if ((xtaffs->csize != 0x01) &&
        (xtaffs->csize != 0x02) &&
        (xtaffs->csize != 0x04) &&
        (xtaffs->csize != 0x08) &&
        (xtaffs->csize != 0x10) &&
        (xtaffs->csize != 0x20) &&
        (xtaffs->csize != 0x40) && (xtaffs->csize != 0x80)) {
        if (tsk_verbose)
            fprintf(stderr, "xtaffs_open: Invalid cluster size (%d)\n",
                xtaffs->csize);
        fs->tag = 0;
        free(fatsb);
        free(xtaffs);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not a XTAFFS file system (cluster size)");
        return NULL;
    }

    // number of FAT tables
    fsopen_numfat = tsk_getu32(fs->endian, fatsb->numfat);
    if(fsopen_numfat > 256) printf("Number of FATs is more than 256!\n");
    xtaffs->numfat = (uint8_t) fsopen_numfat;
    if ((xtaffs->numfat == 0) || (xtaffs->numfat > 8)) {
        if (tsk_verbose)
            fprintf(stderr, "xtaffs_open: Invalid number of FATS (%d)\n",
                xtaffs->numfat);
        fs->tag = 0;
        free(fatsb);
        free(xtaffs);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not a XTAFFS file system (number of FATs)");
        return NULL;
    }

    /* We can't do a sanity check on this b.c. TSK_FS_TYPE_XTAF32 has a value of 0 */ /* AJN TODO Did we write this line? Try a sanity check anyway. */
    /* num of root entries */
    //xtaffs->numroot = tsk_getu16(fs->endian, fatsb->numroot);
    xtaffs->numroot = (uint16_t) 1; /*AJN TODO Why did we hard-code this?*/


    /* EQS NOTE: This can be taken out after issue #21 is verified as fixed */
//    sectors = (TSK_DADDR_T) img_info->size/XTAF_SECTOR_SIZE;

    /* EQS NOTE: sectperfat is hardcoded for the second partition.
                 I found this with hexedit:
                 Offset of 2nd partition FAT  = 0x120eb1000
                 Offset of 2nd partition root = 0x120eba000
                                         - ____________
                                                  0x9000
                 However uxtaf.c shows the FAT size as being 0x8000
                 There is an 8 sector buffer inbetween the FAT and 
                 the root sect?
    */


    /*AJN TODO BUG: img_info->size is an incorrect proxy for the partition size.*/
    if(img_info->size == 146413464 || img_info->size == 4712496640 || img_info->size == 4846714880){
//        printf("Partition 1\n"); //AJN TODO These should be debug prints
        xtaffs->rootsect = 1176; //AJN TODO Can we calculate these instead?
        xtaffs->sectperfat = (uint32_t) 1160;
        xtaffs->firstclustsect = 1240;
        xtaffs->clustcnt = (TSK_DADDR_T) 147910; 
        xtaffs->lastclust = (TSK_DADDR_T) 147891;
//        fs->last_inum = 7673128;
        sectors = (TSK_DADDR_T) (4194304);
    }else if(img_info->size == 2147483648 || offset == 0x80000){
//        printf("Partition 0x80000\n");
        xtaffs->rootsect = 528;
        xtaffs->sectperfat = (uint32_t) 512;
        xtaffs->firstclustsect = (TSK_DADDR_T) 592;
//        xtaffs->clustcnt = (TSK_DADDR_T) 65536;
//        xtaffs->lastclust = (TSK_DADDR_T) 65527;
        xtaffs->clustcnt = (TSK_DADDR_T) 131071;
        xtaffs->lastclust = (TSK_DADDR_T) 131072;
        fs->last_inum = 7673128;
        sectors = (4194304);

    }else if(img_info->size == 2348810240 || offset == 0x80080000){
//        printf("Partition 0x80080000\n");
        xtaffs->rootsect = 2248;
        xtaffs->sectperfat = (uint32_t) 2240;
        xtaffs->firstclustsect = (TSK_DADDR_T) 2264;
        xtaffs->clustcnt = (TSK_DADDR_T) 143359;
        xtaffs->lastclust = (TSK_DADDR_T) 143360;
//        xtaffs->clustcnt = (TSK_DADDR_T) 65536;
//        xtaffs->lastclust = (TSK_DADDR_T) 65527;
//        fs->last_inum = 7673128;
        sectors = (4587520);

    }else if(img_info->size == 216203264 || offset == 0x10C080000){
//        printf("Partition 0x10C080000\n");
        xtaffs->rootsect = 64;
        xtaffs->sectperfat = (uint32_t) 56;
        xtaffs->firstclustsect = (TSK_DADDR_T) 96;
//        xtaffs->clustcnt = (TSK_DADDR_T) 13196;
//        xtaffs->lastclust = (TSK_DADDR_T) 13194;
        xtaffs->clustcnt = (TSK_DADDR_T) 13191;
        xtaffs->lastclust = (TSK_DADDR_T) 13192;
        sectors = (422272);

    }else if(img_info->size == 134217728 || offset == 0x118eb0000){
//        printf("Partition 0x118eb0000\n");
        xtaffs->rootsect = 48;
        xtaffs->sectperfat = (uint32_t) 40;
        xtaffs->firstclustsect = (TSK_DADDR_T) 80;
//        xtaffs->clustcnt = (TSK_DADDR_T) 8192;
//        xtaffs->lastclust = (TSK_DADDR_T) 8190;
        xtaffs->clustcnt = (TSK_DADDR_T) 8191;
        xtaffs->lastclust = (TSK_DADDR_T) 8192;
        sectors = (262144);
   
    }else if(img_info->size == 268435456 || offset == 0x120eb0000){
//        printf("System partition\n");
        xtaffs->rootsect = 80;
        xtaffs->sectperfat = (uint32_t) 64;
        xtaffs->firstclustsect = (TSK_DADDR_T) 112;
//        xtaffs->clustcnt = (TSK_DADDR_T) 16384;
//        xtaffs->lastclust = (TSK_DADDR_T) 16381;
        xtaffs->clustcnt = (TSK_DADDR_T) 7008;
        xtaffs->lastclust = (TSK_DADDR_T) 7009;
        sectors = (224288);
    }else if(img_info->size > 5115150336 || offset == 0x130eb0000){
        /* 5115150336 is the number of bytes of all the first five partitions combined.  An image larger than that would be of a disk, or of the user data partition. */
//        printf("Data Partition\n");

        /*
         * Compute size of partition.
         * Heuristic for determining if we're working with a partition image or disk image:
         *
         *    offset == 0x130eb0000 -> disk image
         *
         * That's it.
         */
        if (offset == 0x130eb0000) {
            partition_size = img_info->size - offset;
        } else {
            partition_size = img_info->size;
        }
        xtaffs->rootsect = 116808; /*AJN TODO This fails on a non-250GB disk*/
        xtaffs->sectperfat = (uint32_t) 116800;
        xtaffs->firstclustsect = (TSK_DADDR_T) 116840;
        xtaffs->firstdatasect = xtaffs->firstclustsect;
        xtaffs->clustcnt = (TSK_DADDR_T) 14950175;
        xtaffs->lastclust = (TSK_DADDR_T) 14946525;
        sectors = (0)/XTAF_SECTOR_SIZE;
    }
    else{
        free(fatsb);
        free(xtaffs);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_UNKTYPE); /*AJN TODO Is this the right error to supply?*/
        tsk_error_set_errstr("Partition was not valid\n");
        return NULL;
    }

    xtaffs->firstfatsect = XTAF_FIRST_FAT_SECT;


    if (xtaffs->sectperfat == 0) {
        if (tsk_verbose)
            fprintf(stderr,
                "xtaffs_open: Invalid number of sectors per FAT (%d)\n",
                xtaffs->sectperfat);
        fs->tag = 0;
        free(fatsb);
        free(xtaffs);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr
            ("Not a XTAFFS file system (invalid sectors per FAT)");
        return NULL;
    }
    if ((xtaffs->firstfatsect == 0) || (xtaffs->firstfatsect > sectors)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr
            ("Not a XTAFFS file system (invalid first FAT sector %"
            PRIuDADDR ")", xtaffs->firstfatsect);
        if (tsk_verbose)
            fprintf(stderr,
                "xtaffs_open: Invalid first FAT (%" PRIuDADDR ")\n",
                xtaffs->firstfatsect);

        fs->tag = 0;
        free(fatsb);
        free(xtaffs);
        return NULL;
    }

    /* Calculate the block info
     * 
     * The sector of the begining of the data area  - which is 
     * after all of the FATs
     *
     * For TSK_FS_TYPE_XTAF12 and TSK_FS_TYPE_XTAF16, the data area starts with the root
     * directory entries and then the first cluster.  For TSK_FS_TYPE_XTAF32,
     * the data area starts with clusters and the root directory
     * is somewhere in the data area
     */
    /* There's a 8 sector void space between the FAT and the first data sector */
//    xtaffs->firstdatasect = HD_VOID_AREA + xtaffs->firstfatsect +
//        xtaffs->sectperfat * xtaffs->numfat;
     xtaffs->firstdatasect = xtaffs->rootsect;
     xtaffs->firstclustsect = xtaffs->firstdatasect + 32 + 0;


    /* The sector where the first cluster is located.  It will be used
     * to translate cluster addresses to sector addresses 
     *
     * For the original FAT32, the first cluster is the start of the data area and
     * it is after the root directory for FAT12 and FAT16.  At this
     * point in the program, numroot is set to 0 in the original FAT32
     */

    /* total number of clusters */
//    xtaffs->clustcnt = (sectors - xtaffs->firstclustsect) / xtaffs->csize;
        

    /* the first cluster is #2, so the final cluster is: */
//    xtaffs->lastclust = 1 + xtaffs->clustcnt;



    /* identify the FAT type by the total number of data clusters
     * this calculation is from the MS FAT Overview Doc
     *
     * A FAT file system made by another OS could use different values
     */
    if (ftype == TSK_FS_TYPE_XTAF_DETECT) {

        if (xtaffs->clustcnt < 0xfff4) {
            ftype = TSK_FS_TYPE_XTAF16;
        }
        else {
            ftype = TSK_FS_TYPE_XTAF32;
        }

        xtaffs->fs_info.ftype = ftype;
    }

    /* Some sanity checks */
    else {
        if ((ftype == TSK_FS_TYPE_XTAF12)
            && (xtaffs->clustcnt >= 4085)) {
            fs->tag = 0;
            free(fatsb);
            free(xtaffs);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_MAGIC);
            tsk_error_set_errstr
                ("Too many sectors for TSK_FS_TYPE_XTAF12: try auto-detect mode");
            if (tsk_verbose)
                fprintf(stderr,
                    "xtaffs_open: Too many sectors for FAT12\n");
            return NULL;
        }
    }
/*
AJN TODO Why did we comment this out? Is the numroot field missing?
    if ((ftype == TSK_FS_TYPE_XTAF32) && (xtaffs->numroot != 0)) {
        fs->tag = 0;
        free(fatsb);
        free(xtaffs);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr
            ("Invalid TSK_FS_TYPE_XTAF32 image (numroot != 0)");
        if (tsk_verbose)
            fprintf(stderr, "xtaffs_open: numroom != 0 for XTAF32\n");
        return NULL;
    }

    if ((ftype != TSK_FS_TYPE_XTAF32) && (xtaffs->numroot == 0)) {
        fs->tag = 0;
        free(fatsb);
        free(xtaffs);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr
            ("Invalid FAT image (numroot == 0, and not TSK_FS_TYPE_XTAF32)");
        if (tsk_verbose)
            fprintf(stderr, "xtaffs_open: numroom == 0 and not XTAF32\n");
        return NULL;
    }
*/
    /* additional sanity checks if we think we are using the backup boot sector.
     * The scenario to prevent here is if fat_open is called 6 sectors before the real start
     * of the file system, then we want to detect that it was not a backup that we saw.  
     */
    if (used_backup_boot) {
        // only FAT32 has backup boot sectors..
        if (ftype != TSK_FS_TYPE_XTAF32) {
            fs->tag = 0;
            free(xtaffs); /*AJN TODO Check for missed 'fatfs' symbols*/
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_MAGIC);
            tsk_error_set_errstr
                ("Invalid XTAF image (Used what we thought was a backup boot sector, but it is not TSK_FS_TYPE_XTAF32)");
            if (tsk_verbose)
                fprintf(stderr,
                    "xtaffs_open: Had to use backup boot sector, but this isn't XTAF32\n");
            return NULL;
        }
        if (xtaffs->numroot > 1) {
            uint8_t buf1[512];
            uint8_t buf2[512];
            int i2;
            int numDiffs;

            cnt =
                tsk_fs_read(fs, xtaffs->firstfatsect * xtaffs->ssize,
                (char *) buf1, 512);
            if (cnt != 512) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2("%s: FAT1", myname);
                fs->tag = 0;
                free(xtaffs->sb);
                free(xtaffs);
                return NULL;
            }

            cnt =
                tsk_fs_read(fs,
                (xtaffs->firstfatsect + xtaffs->sectperfat) * xtaffs->ssize,
                (char *) buf2, 512);
            if (cnt != 512) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2("%s: FAT2", myname);
                fs->tag = 0;
                free(xtaffs->sb);
                free(xtaffs);
                return NULL;
            }

            numDiffs = 0;
            for (i2 = 0; i2 < 512; i2++) {
                if (buf1[i2] != buf2[i2]) {
                    numDiffs++;
                }
            }
            if (numDiffs > 25) {
                fs->tag = 0;
                free(xtaffs);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_MAGIC);
                tsk_error_set_errstr
                    ("Invalid FAT image (Too many differences between FATS from guessing (%d diffs))",
                    numDiffs);
                if (tsk_verbose)
                    fprintf(stderr,
                        "xtaffs_open: Too many differences in FAT from guessing (%d diffs)\n",
                        numDiffs);
                return NULL;
            }
        }
    }


    /* Set the mask to use on the cluster values */
    if (ftype == TSK_FS_TYPE_XTAF12) {
        xtaffs->mask = XTAFFS_12_MASK;
    }
    else if (ftype == TSK_FS_TYPE_XTAF16) {
        xtaffs->mask = XTAFFS_16_MASK;
    }
    else if (ftype == TSK_FS_TYPE_XTAF32) {
        xtaffs->mask = XTAFFS_32_MASK;
    }
    else {
        fs->tag = 0;
        free(fatsb);
        free(xtaffs);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Unknown FAT type in xtaffs_open: %d\n",
            ftype);
        return NULL;
    }
    fs->duname = "Sector";

    for (i = 0; i < FAT_CACHE_N; i++) {
        xtaffs->fatc_addr[i] = 0;
        xtaffs->fatc_ttl[i] = 0;
    }

    /*
     * block calculations : although there are no blocks in fat, we will
     * use these fields for sector calculations
     */
    fs->first_block = 0;
    fs->block_count = sectors;
    fs->last_block = fs->last_block_act = fs->block_count - 1;
    fs->block_size = xtaffs->ssize;

    /* determine the last block we have in this image */
    if ((TSK_DADDR_T) ((img_info->size - offset) / fs->block_size) <
        fs->block_count)
        fs->last_block_act =
            (img_info->size - offset) / fs->block_size - 1;

    /*
     * inode calculations
     */

    /* maximum number of dentries in a sector & cluster */
    xtaffs->dentry_cnt_se = xtaffs->ssize / sizeof(xtaffs_dentry);
    xtaffs->dentry_cnt_cl = xtaffs->dentry_cnt_se * xtaffs->csize;

    fs->root_inum = XTAFFS_ROOTINO;
    fs->first_inum = XTAFFS_FIRSTINO;
    // Add on extras for Orphan and special files
    fs->last_inum =
        (XTAFFS_SECT_2_INODE(xtaffs,
            fs->last_block_act + 1) - 1) + XTAFFS_NUM_SPECFILE;

    fs->last_inum = fs->last_inum;
    fs->inum_count = fs->last_inum - fs->first_inum + 1;


    /*
     * Volume ID
     * AJN NOTE: For XTAF, volume ID is replaced with serial number,
     * which might not be distinct on the drive.
     * (TODO: Refer to Bolt or our drive images.)
     */
    for (fs->fs_id_used = 0; fs->fs_id_used < 4; fs->fs_id_used++) {
        fs->fs_id[fs->fs_id_used] =
            fatsb->serial_number[fs->fs_id_used];
    }

    /*
     * Set the function pointers  
     */

    fs->block_walk = xtaffs_block_walk;
    fs->block_getflags = xtaffs_block_getflags;

    fs->inode_walk = xtaffs_inode_walk;
    fs->istat = xtaffs_istat;
    fs->file_add_meta = xtaffs_inode_lookup;

    fs->get_default_attr_type = xtaffs_get_default_attr_type;
    fs->load_attrs = xtaffs_make_data_run;

    fs->dir_open_meta = xtaffs_dir_open_meta;
    fs->name_cmp = xtaffs_name_cmp;

    fs->fsstat = xtaffs_fsstat;
    fs->fscheck = xtaffs_fscheck;

    fs->close = xtaffs_close;

    fs->jblk_walk = xtaffs_jblk_walk;
    fs->jentry_walk = xtaffs_jentry_walk;
    fs->jopen = xtaffs_jopen;
    fs->journ_inum = 0;


    // initialize the caches
    tsk_init_lock(&xtaffs->cache_lock);
    tsk_init_lock(&xtaffs->dir_lock);
    xtaffs->inum2par = NULL;

    return fs;
}
