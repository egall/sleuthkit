/*
** The Sleuth Kit 
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

/*
 * Contains the structures and function APIs for XTAFFS file system support.
 */


#ifndef _TSK_XTAFFS_H
#define _TSK_XTAFFS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
** Constants
*/
#define XTAFFS_FIRSTINO	2
#define XTAFFS_ROOTINO	2       /* location of root directory inode */
#define XTAFFS_FIRST_NORMINO 3

    // special files go at end of inode list (before $OrphanFiles)
#define XTAFFS_NUM_SPECFILE  3   // includes FAT1, FAT2, and Orphans

#define XTAFFS_FAT1INO(fs_info) \
    (TSK_FS_ORPHANDIR_INUM(fs_info) - 2)        // inode for FAT1 "special file"
#define XTAFFS_FAT1NAME  "$FAT1"

#define XTAFFS_FAT2INO(fs_info) \
    (TSK_FS_ORPHANDIR_INUM(fs_info) - 1)        // inode for FAT2 "special file"
#define XTAFFS_FAT2NAME  "$FAT2"


#define XTAFFS_SBOFF		0
#define XTAFFS_MAXNAMLEN	256
#define XTAFFS_MAXNAMLEN_UTF8	1024
#define XTAFFS_FILE_CONTENT_LEN sizeof(TSK_DADDR_T)      // we will store the starting cluster


/* Partition info */

#define PART_ONE_SIZE_BYTES 	  2147483648
#define PART_ONE_OFFSET_BYTES	  0x80000
#define PART_ONE_ROOTSECT	  528
#define PART_ONE_SECTPERFAT	  512
#define PART_ONE_FIRSTCLUSTSECT	  592
#define PART_ONE_CLUSTCNT	  131072 
#define PART_ONE_LASTCLUST	  131072
#define PART_ONE_SECTORS	  4194304

#define PART_TWO_SIZE_BYTES	  2348810240
#define PART_TWO_OFFSET_BYTES	  0x80080000
#define PART_TWO_ROOTSECT	  2248
#define PART_TWO_SECTPERFAT       2240
#define PART_TWO_FIRSTCLUSTSECT	  2264
#define PART_TWO_CLUSTCNT	  143360
#define PART_TWO_LASTCLUST	  143360
#define PART_TWO_SECTORS	  4587520

#define PART_THREE__SIZE_BYTES	  216203264
#define PART_THREE__OFFSET_BYTES  0x10C080000
#define PART_THREE_ROOTSECT 	  64
#define PART_THREE_SECTPERFAT 	  56
#define PART_THREE_FIRSTCLUSTSECT 96
#define PART_THREE_CLUSTCNT       13192
#define PART_THREE_LASTCLUST	  13192
#define PART_THREE_SECTORS	  422272

#define PART_FOUR_SIZE_BYTES	  134217728
#define PART_FOUR_OFFSET_BYTES	  0x118eb0000
#define PART_FOUR_ROOTSECT 	  48
#define PART_FOUR_SECTPERFAT 	  40
#define PART_FOUR_FIRSTCLUSTSECT  80
#define PART_FOUR_CLUSTCNT	  8192
#define PART_FOUR_LASTCLUST       8192
#define PART_FOUR_SECTORS	  262144

#define PART_FIVE_SIZE_BYTES 	  268435456
#define PART_FIVE_OFFSET_BYTES	  0x120eb0000
#define PART_FIVE_ROOTSECT 	  80
#define PART_FIVE_SECTPERFAT	  64
#define PART_FIVE_FIRSTCLUSTSECT  112
#define PART_FIVE_CLUSTCNT	  7009
#define PART_FIVE_LASTCLUST 	  7009
#define PART_FIVE_SECTORS 	  224288

#define PART_SIX_SIZE_BYTES_MIN	  5115150336
#define PART_SIX_OFFSET_BYTES     0x130eb0000
#define PART_SIX_ROOTSECT 	  116808
#define PART_SIX_SECTPERFAT 	  116800
#define PART_SIX_FIRSTCLUSTSECT   116840
#define PART_SIX_CLUSTCNT	  14946553
#define PART_SIX_LASTCLUST	  14946553





/* size of FAT to read into XTAFFS_INFO each time */
/* This must be at least 1024 bytes or else fat12 will get messed up */
#define FAT_CACHE_N		4       // number of caches
#define FAT_CACHE_B		4096
#define FAT_CACHE_S		8       // number of sectors in cache

/* MASK values for FAT entries */
#define XTAFFS_12_MASK	0x00000fff
#define XTAFFS_16_MASK	0x0000ffff
#define XTAFFS_32_MASK	0x0fffffff

/* Constants for the FAT entry */
#define XTAFFS_UNALLOC	0
#define XTAFFS_BAD		0x0ffffff7
#define XTAFFS_EOFS		0x0ffffff8
#define XTAFFS_EOFE		0x0fffffff



/* macro to identify if the FAT value is End of File
 * returns 1 if it is and 0 if it is not 
 */
#define XTAFFS_ISEOF(val, mask)	\
	((val >= (XTAFFS_EOFS & mask)) && (val <= (XTAFFS_EOFE)))


#define XTAFFS_ISBAD(val, mask) \
	((val) == (XTAFFS_BAD & mask))

#define XTAFFS_CLUST_2_SECT(xtaffs, c)	\
	(TSK_DADDR_T)(xtaffs->firstclustsect + ((((c) & xtaffs->mask) - 2) * xtaffs->csize))

#define XTAFFS_SECT_2_CLUST(xtaffs, s)	\
	(TSK_DADDR_T)(2 + ((s)  - xtaffs->firstclustsect) / xtaffs->csize)



/* given an inode address, determine in which sector it is located
 * i must be larger than 3 (2 is the root and it doesn't have a sector)
 */
#define XTAFFS_INODE_2_SECT(xtaffs, i)    \
    (TSK_DADDR_T)((i - XTAFFS_FIRST_NORMINO)/(xtaffs->dentry_cnt_se) + xtaffs->firstdatasect)

#define XTAFFS_INODE_2_OFF(xtaffs, i)     \
    (size_t)(((i - XTAFFS_FIRST_NORMINO) % xtaffs->dentry_cnt_se) * sizeof(xtaffs_dentry))


/* (Reference: Carrier FSF 231-232 Desc of sect to "inode addr") */
/* given a sector IN THE DATA AREA, return the base inode for it */
#define XTAFFS_SECT_2_INODE(xtaffs, s)    \
    (TSK_INUM_T)((s - xtaffs->firstdatasect) * xtaffs->dentry_cnt_se + XTAFFS_FIRST_NORMINO)



/*
 * Boot Sector Structure for TSK_FS_INFO_TYPE_XTAF
 * (512 bytes)
 */
    typedef struct {
        uint8_t magic[4]; /* "XTAF" in ASCII */
        uint8_t serial_number[4];
        uint8_t csize[4];
        uint8_t numfat[4];
        uint8_t f5[2]; /* NULL expected */
        uint8_t f6[0xFEE];
    } xtaffs_sb;
        




/* directory entry short name structure */
    typedef struct {
        uint8_t name[8];
        uint8_t ext[3];
        uint8_t attrib;
        uint8_t lowercase;
        uint8_t ctimeten;       /* create times (ctimeten is 0-199) */
        uint8_t ctime[2];
        uint8_t cdate[2];
        uint8_t adate[2];       /* access time */
        uint8_t highclust[2];
        uint8_t wtime[2];       /* last write time */
        uint8_t wdate[2];
        uint8_t startclust[2];
        uint8_t size[4];
    } old_fatfs_dentry;

    typedef struct {
        uint8_t fnl;
        uint8_t attrib;
        char name[42];
        uint8_t startclust[4];
        uint8_t size[4];
        uint8_t cdate[2];
        uint8_t ctime[2];
        uint8_t adate[2];
        uint8_t atime[2];
	uint8_t wdate[2];
        uint8_t wtime[2];
//        uint8_t highclust[2];
    } xtaffs_dentry;



/* Macro to combine the upper and lower 2-byte parts of the starting
 * cluster 
 */
#define XTAFFS_DENTRY_CLUST(fsi, de)	\
	(TSK_DADDR_T)((tsk_getu32(fsi->endian, de->startclust))-0)

/* constants for first byte of name[] */
#define XTAFFS_SLOT_EMPTY	0x00
#define XTAFFS_SLOT_E5		0x05    /* actual value is 0xe5 */
#define XTAFFS_SLOT_DELETED	0xe5

/* 
 *Return 1 if c is an valid charactor for a short file name 
 *
 * NOTE: 0x05 is allowed in name[0], and 0x2e (".") is allowed for name[0]
 * and name[1] and 0xe5 is allowed for name[0]
 */

#define XTAFFS_IS_83_NAME(c)		\
	((((c) < 0x20) || \
	  ((c) == 0x22) || \
	  (((c) >= 0x2a) && ((c) <= 0x2c)) || \
	  ((c) == 0x2e) || \
	  ((c) == 0x2f) || \
	  (((c) >= 0x3a) && ((c) <= 0x3f)) || \
	  (((c) >= 0x5b) && ((c) <= 0x5d)) || \
	  ((c) == 0x7c)) == 0)

// extensions are to be ascii / latin
#define XTAFFS_IS_83_EXT(c)		\
    (XTAFFS_IS_83_NAME((c)) && ((c) < 0x7f))



/* flags for attributes field */
#define XTAFFS_ATTR_NORMAL	0x00    /* normal file */
#define XTAFFS_ATTR_READONLY	0x01    /* file is readonly */
#define XTAFFS_ATTR_HIDDEN	0x02    /* file is hidden */
#define XTAFFS_ATTR_SYSTEM	0x04    /* file is a system file */
#define XTAFFS_ATTR_VOLUME	0x08    /* entry is a volume label */
#define XTAFFS_ATTR_DIRECTORY	0x10    /* entry is a directory name */
#define XTAFFS_ATTR_ARCHIVE	0x20    /* file is new or modified */
#define XTAFFS_ATTR_LFN		0x0f    /* A long file name entry */
#define XTAFFS_ATTR_ALL		0x3f    /* all flags set */

/* flags for lowercase field */
#define XTAFFS_CASE_LOWER_BASE	0x08    /* base is lower case */
#define XTAFFS_CASE_LOWER_EXT	0x10    /* extension is lower case */
#define XTAFFS_CASE_LOWER_ALL	0x18    /* both are lower */

#define XTAFFS_SEC_MASK		0x001f    /* number of seconds div by 2 */
#define XTAFFS_SEC_SHIFT	1       /* Symbol provided for code symmetry */
#define XTAFFS_SEC_MIN		0
#define XTAFFS_SEC_MAX		30
#define XTAFFS_MIN_MASK		0x07e0   /* number of minutes 0-59 */
#define XTAFFS_MIN_SHIFT	5
#define XTAFFS_MIN_MIN		0
#define XTAFFS_MIN_MAX		59
#define XTAFFS_HOUR_MASK	0xf800  /* number of hours 0-23 */
#define XTAFFS_HOUR_SHIFT	11
#define XTAFFS_HOUR_MIN		0
#define XTAFFS_HOUR_MAX		23

/* return 1 if x is a valid XTAF time */

#define XTAFFS_ISTIME(x)        \
        (((((x & XTAFFS_SEC_MASK) << XTAFFS_SEC_SHIFT) < XTAFFS_SEC_MIN) || \
          (((x & XTAFFS_SEC_MASK) << XTAFFS_SEC_SHIFT) > XTAFFS_SEC_MAX) || \
          (((x & XTAFFS_MIN_MASK) >> XTAFFS_MIN_SHIFT) < XTAFFS_MIN_MIN) || \
          (((x & XTAFFS_MIN_MASK) >> XTAFFS_MIN_SHIFT) > XTAFFS_MIN_MAX) || \
          (((x & XTAFFS_HOUR_MASK) >> XTAFFS_HOUR_SHIFT) > XTAFFS_MIN_MAX) || \
          (((x & XTAFFS_HOUR_MASK) >> XTAFFS_HOUR_SHIFT) > XTAFFS_HOUR_MAX) ) == 0)


#define XTAFFS_DAY_MASK		0x001f    /* day of month 1-31 */
#define XTAFFS_DAY_SHIFT	0
#define XTAFFS_DAY_MIN		1
#define XTAFFS_DAY_MAX		31
#define XTAFFS_MON_MASK		0x01e0   /* month 1-12 */
#define XTAFFS_MON_SHIFT	5
#define XTAFFS_MON_MIN		1
#define XTAFFS_MON_MAX		12
#define XTAFFS_YEAR_MASK	0xfe00  /* year, from 1980 0-127 */
#define XTAFFS_YEAR_SHIFT	9
#define XTAFFS_YEAR_MIN		0
#define XTAFFS_YEAR_MAX		127
#define XTAFFS_YEAR_OFFSET      80

/* return 1 if x is a valid XTAF date */
#define XTAFFS_ISDATE(x)        \
         ((((x & XTAFFS_DAY_MASK) > XTAFFS_DAY_MAX) || \
           ((x & XTAFFS_DAY_MASK) < XTAFFS_DAY_MIN) || \
           (((x & XTAFFS_MON_MASK) >> XTAFFS_MON_SHIFT) > XTAFFS_MON_MAX) || \
           (((x & XTAFFS_MON_MASK) >> XTAFFS_MON_SHIFT) < XTAFFS_MON_MIN) || \
           (((x & XTAFFS_YEAR_MASK) >> XTAFFS_YEAR_SHIFT) > XTAFFS_YEAR_MAX) ) == 0)



/* 
 * Long file name support for windows 
 *
 * Contents of this are in UNICODE, not ASCII 
 */
    typedef struct {
        uint8_t seq;
        uint8_t part1[10];
        uint8_t attributes;
        uint8_t reserved1;
        uint8_t chksum;
        uint8_t part2[12];
        uint8_t reserved2[2];
        uint8_t part3[4];
    } xtaffs_dentry_lfn;

/* flags for seq field */
#define XTAFFS_LFN_SEQ_FIRST	0x40    /* This bit is set for the first lfn entry */
#define XTAFFS_LFN_SEQ_MASK	0x3f    /* These bits are a mask for the decreasing
                                         * sequence number for the entries */

/* internal XTAFFS_INFO structure */
    typedef struct {
        TSK_FS_INFO fs_info;    /* super class */
        //TSK_DATA_BUF *table;      /* cached section of file allocation table */

        /* FAT cache */
        /* cache_lock protects fatc_buf, fatc_addr, fatc_ttl */
        tsk_lock_t cache_lock;
        char fatc_buf[FAT_CACHE_N][FAT_CACHE_B];        //r/w shared - lock
        TSK_DADDR_T fatc_addr[FAT_CACHE_N];     // r/w shared - lock
        uint8_t fatc_ttl[FAT_CACHE_N];  //r/w shared - lock

        xtaffs_sb *sb;

        /* FIrst sector of FAT */
        TSK_DADDR_T firstfatsect;

        /* First sector after FAT  - For the original FAT12 and FAT16, this is where the
         * root directory entries are.  For FAT32, this is the the first 
         * cluster */
        /* AJN TODO Clarify this for XTAF */
        TSK_DADDR_T firstdatasect;

        /* The sector number were cluster 2 (the first one) is
         * for the original FAT32, it will be the same as firstdatasect, but for FAT12 & FAT16
         * it will be the first sector after the Root directory  */
        /* AJN TODO Clarify this for XTAF */
        TSK_DADDR_T firstclustsect;

        /* size of data area in clusters, starting at firstdatasect */
        TSK_DADDR_T clustcnt;

        TSK_DADDR_T lastclust;

        /* sector where the root directory is located */
        TSK_DADDR_T rootsect;

        uint32_t dentry_cnt_se; /* max number of dentries per sector */
        uint32_t dentry_cnt_cl; /* max number of dentries per cluster */

        uint16_t ssize;         /* size of sectors in bytes */
        uint16_t ssize_sh;      /* power of 2 for size of sectors */
        uint8_t csize;          /* size of clusters in sectors */ /*NOTE: XTAF uses 32 bits for this value, so we may lose bits here. TODO: Check while parsing.*/
        //uint16_t      reserved;       /* number of reserved sectors */
        uint8_t numfat;         /* number of fat tables */
        uint32_t sectperfat;    /* sectors per fat table */
        uint16_t numroot;       /* number of 32-byte dentries in root dir */
        uint32_t mask;          /* the mask to use for the sectors */

        tsk_lock_t dir_lock;    //< Lock that protects inum2par.
        void *inum2par;         //< Maps subfolder metadata address to parent folder metadata addresses.
    } XTAFFS_INFO;


    extern int8_t xtaffs_is_sectalloc(XTAFFS_INFO *, TSK_DADDR_T);
    extern int8_t xtaffs_is_clustalloc(XTAFFS_INFO * xtaffs,
        TSK_DADDR_T clust);

    extern uint8_t xtaffs_isdentry(XTAFFS_INFO *, xtaffs_dentry *, uint8_t);
    extern uint8_t xtaffs_make_root(XTAFFS_INFO *, TSK_FS_META *);
    extern uint8_t xtaffs_dinode_load(TSK_FS_INFO *, xtaffs_dentry *,
        TSK_INUM_T);

    extern uint8_t xtaffs_inode_lookup(TSK_FS_INFO * fs,
        TSK_FS_FILE * a_fs_file, TSK_INUM_T inum);
    extern uint8_t xtaffs_inode_walk(TSK_FS_INFO * fs,
        TSK_INUM_T start_inum, TSK_INUM_T end_inum,
        TSK_FS_META_FLAG_ENUM a_flags, TSK_FS_META_WALK_CB a_action,
        void *a_ptr);
    extern uint8_t xtaffs_make_data_run(TSK_FS_FILE * a_fs_file);

    extern uint8_t xtaffs_getFAT(XTAFFS_INFO * xtaffs, TSK_DADDR_T clust,
        TSK_DADDR_T * value);

    extern TSK_RETVAL_ENUM
        xtaffs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir,
        TSK_INUM_T a_addr);

    extern int xtaffs_name_cmp(TSK_FS_INFO *, const char *, const char *);
    extern uint8_t xtaffs_dir_buf_add(XTAFFS_INFO * xtaffs,
        TSK_INUM_T par_inum, TSK_INUM_T dir_inum);
    extern void xtaffs_cleanup_ascii(char *);
    extern void xtaffs_dir_buf_free(XTAFFS_INFO *xtaffs);


#ifdef __cplusplus
}
#endif
#endif
