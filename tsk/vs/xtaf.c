#include "tsk_vs_i.h"
#include "../fs/tsk_fs_i.h"
#include "../fs/tsk_xtaffs.h"

#define XTAF_PART_LABEL_MAX_LENGTH 25

static void
xtaf_close(TSK_VS_INFO * vs)
{
    vs->tag = 0;
    tsk_vs_part_free(vs);
    free(vs);
}

/*
 * Inspects a byte address for an XTAF superblock structure.
 *
 * @param offset Offset in sectors.
 *
 * Returns 0 on finding a sane-looking XTAF superblock.
 * Returns 1 on finding non-XTAF-superblock data.
 * Returns <0 on more basic errors (memory, I/O).
 */
int
tsk_vs_xtaf_verifysb(TSK_IMG_INFO * img_info, TSK_DADDR_T offset, unsigned int sector_size){
    ssize_t cnt;
    xtaffs_sb* xtafsb;
    unsigned int xtafsb_len;

    xtafsb_len = sizeof(xtaffs_sb);

    /* Allocate superblock struct. */
    xtafsb = (xtaffs_sb*) tsk_malloc(xtafsb_len);
    if (NULL == xtafsb) {
        tsk_fprintf(stderr, "tsk_vs_xtaf_verifysb: Failed to allocate superblock for partition %d.\n");
        return -ENOMEM;
    }

    /* Read in superblock. */
    /* NOTE: This is read as a char* instead of a xtaffs_sb to keep img_read() happy. */
    cnt = tsk_img_read(img_info, offset * sector_size, (char *) xtafsb, xtafsb_len);
    /* Check for a failed read. */
    if (cnt != xtafsb_len) {
        tsk_fprintf(stderr, "tsk_vs_xtaf_verifysb: Failed to read at disk offset %" PRIuDADDR " bytes.\n", offset * sector_size);
        free(xtafsb);
        return -EIO;
    }

    /* Sanity test: Check the magic. */
    if(strncmp((char*) xtafsb->magic, "XTAF", 4)){
        if (tsk_verbose)
            tsk_fprintf(stderr, "tsk_vs_xtaf_verifysb: Partition at %" PRIuDADDR " bytes is not an XTAF file system.\n", offset * sector_size);
        free(xtafsb);
        return 1;
    }

    /* The partition at this point is sane. No further need to check the superblock. */
    free(xtafsb);

    return 0;
}

/* 
 * Given the path to the file, open it and load the internal
 * partition table structure
 *
 * offset is the byte offset to the start of the volume system
 *
 * If test is 1 then additional tests are performed to make sure 
 * it isn't a FAT or NTFS file system. This is used when autodetection
 * is being used to detect the volume system type. 
 */
TSK_VS_INFO *
tsk_vs_xtaf_open(TSK_IMG_INFO * img_info, TSK_DADDR_T offset, uint8_t test)
{
    TSK_VS_INFO *vs;
    ssize_t cnt = 0;
    char* xtaf_buffer[4];
    
    unsigned int sector_size;
    /* Offsets and lengths (in sectors) are hard-coded, except for the user data partition length. */
//    TSK_DADDR_T known_xtaf_offsets[] = {1024   , 4195328, 8782848, 9205120, 9467264, 9991552};
    TSK_DADDR_T known_xtaf_offsets[] = {0x80000, 0x80080000, 0x10C080000, 0x118EB0000, 0x120eb0000, 0x130eb0000};
    TSK_DADDR_T known_xtaf_lengths[] = {4194304, 4587520, 422272 , 262144 , 524288 , 0};
    /* Partition labels c/o the Free60 Wiki: http://free60.org/FATX */
    char* known_xtaf_labels[] = {
      "XTAF (System Cache)",
      "XTAF (Game Cache)",
      "XTAF (System Extended)",
      "XTAF (System Extended 2)",
      "XTAF (Compatibility)",
      "XTAF (System)"
    }; //AJN: Recall that the label passed to tsk_vs_part_add must be malloc'ed.
    TSK_VS_PART_INFO* part;
    TSK_DADDR_T partition_offset;
    TSK_DADDR_T partition_length;
    int itor;
    char *part_label;
    int rc_verifysb;
    int partition_tally = 0;

    /* Clean up any errors that are lying around. */
    tsk_error_reset();

    /* Zero out buffer before reading */
    memset(xtaf_buffer, 0, sizeof(xtaf_buffer));

    sector_size = img_info->sector_size;
    if (0 == sector_size) {
        tsk_fprintf(stderr, "tsk_vs_xtaf_open: img_info has the sector size of this image as 0 bytes.  Guessing 512 instead, but this should be fixed.\n");
        sector_size = 512;
    }

    vs = (TSK_VS_INFO *) tsk_malloc(sizeof(*vs));
    if (vs == NULL)
        return NULL;

    vs->vstype = TSK_VS_TYPE_XTAF;
    vs->tag = TSK_VS_INFO_TAG;
    vs->img_info = img_info;
    vs->offset = offset;

    /* inititialize settings */
    vs->part_list = NULL;
    vs->endian = 0x02; /*AJN TODO Setting this to TSK_BIG_ENDIAN, which is the same value, causes XTAF recognition to immediately fail...why?*/
    vs->block_size = 512;

    /* Assign functions */
    vs->close = xtaf_close;
    vs->part_count = 0;

    /* Inspect beginning of image for XTAF superblock.  If one is present there, assume we're looking at a partition image, and quit early. */
    rc_verifysb = tsk_vs_xtaf_verifysb(img_info, 0, sector_size);
    if (rc_verifysb == 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "tsk_vs_xtaf_open: Encountered XTAF superblock at beginning of image.  Assuming this is a partition image, not a disk image.\n");
        xtaf_close(vs);
        return NULL;
    }

    /* check to see if image is a single partition, in which case XTAF would start at the beginning */
    memset(xtaf_buffer, 0, sizeof(xtaf_buffer));
    cnt = tsk_img_read(img_info, 0x0, (char *) xtaf_buffer, 4);
    if(strncmp(xtaf_buffer, "XTAF", 4) == 0){
        partition_offset = 0;
        partition_length = img_info->size;
        rc_verifysb = tsk_vs_xtaf_verifysb(img_info, partition_offset, sector_size);
        /* Check for XTAF superblock. */
        if (rc_verifysb != 0) {
            if (tsk_verbose)
                tsk_fprintf(stderr, "Superblock incorrect\n");
            xtaf_close(vs);
            return NULL;
        }
        /* Allocate partition label. */
        part_label = (char *) tsk_malloc(XTAF_PART_LABEL_MAX_LENGTH * sizeof(char));
        snprintf(part_label, XTAF_PART_LABEL_MAX_LENGTH, "unknown");

        /* Populate partition struct and append to partition list. */
        part = tsk_vs_part_add(vs, partition_offset, partition_length, TSK_VS_PART_FLAG_ALLOC, part_label, 0, 0);
        if (NULL == part) {
            tsk_fprintf(stderr, "tsk_vs_xtaf_open: Failed to add partition %d to partition list.\n", itor);
            xtaf_close(vs);
            return NULL;
        }
        partition_tally = 1;
    }else{


        /* Loop through the known partition offsets, looking for XTAF file systems only by a sane XTAF superblock being present. */
        for (itor = 0; itor < 6; itor++) {
            /* Reset. */
            part = NULL;
            part_label = NULL;
    
            partition_offset = known_xtaf_offsets[itor];
    
            /* Check to see if XTAF is at the location it should be */
            memset(xtaf_buffer, 0, sizeof(xtaf_buffer));
            cnt = tsk_img_read(img_info, partition_offset, (char *) xtaf_buffer, 4);
            if(strncmp(xtaf_buffer, "XTAF", 4) != 0){
                continue;
            }
    
            partition_length = known_xtaf_lengths[itor];
            /* Last partition will have variable size depending on the size of drive, this partition will run to the end of the drive */       
            if( partition_offset == 0x130eb0000){
                partition_length = img_info->size - 0x130eb0000;
                printf("Size of 6th partition = %"PRIu64"\n", partition_length);
            }
    
            if (0 == partition_length) {
                if (tsk_verbose) {
                    tsk_fprintf(stderr, "tsk_vs_xtaf_open: Computing partition length.\n");
                    tsk_fprintf(stderr, "tsk_vs_xtaf_open: Image size: %" PRIuOFF " bytes.\n", img_info->size);
                    tsk_fprintf(stderr, "tsk_vs_xtaf_open: Sector size: %u bytes.\n", img_info->sector_size);
                    tsk_fprintf(stderr, "tsk_vs_xtaf_open: Partition offset: %" PRIuDADDR " bytes.\n", partition_offset * img_info->sector_size);
                }
    
                /* Compute partition length of the user data partition differently - based on input image's length. */
                if ((img_info->size / sector_size) < partition_offset) {
                    if (tsk_verbose)
                        tsk_fprintf(stderr, "tsk_vs_xtaf_open: This image is smaller than the offset of the target partition.  Aborting.\n");
                    xtaf_close(vs);
                    return NULL;
                }
                partition_length = (img_info->size / sector_size) - partition_offset;
            }
    
            if (tsk_verbose) {
                tsk_fprintf(stderr, "tsk_vs_xtaf_open: Testing for partition.\n");
                tsk_fprintf(stderr, "tsk_vs_xtaf_open:   itor: %d.\n", itor);
                tsk_fprintf(stderr, "tsk_vs_xtaf_open:   offset: %" PRIuDADDR " sectors.\n", partition_offset);
                tsk_fprintf(stderr, "tsk_vs_xtaf_open:   length: %" PRIuDADDR " sectors.\n", partition_length);
            }
    
            /* Check for XTAF superblock. */
            rc_verifysb = tsk_vs_xtaf_verifysb(img_info, partition_offset, sector_size);
            if (rc_verifysb != 0) {
                continue;
            }
    
            /* Allocate partition label. */
            part_label = (char *) tsk_malloc(XTAF_PART_LABEL_MAX_LENGTH * sizeof(char));
            snprintf(part_label, XTAF_PART_LABEL_MAX_LENGTH, known_xtaf_labels[itor]);
    
            /* Populate partition struct and append to partition list. */
            part = tsk_vs_part_add(vs, partition_offset, partition_length, TSK_VS_PART_FLAG_ALLOC, part_label, 0, 0);
            if (NULL == part) {
                tsk_fprintf(stderr, "tsk_vs_xtaf_open: Failed to add partition %d to partition list.\n", itor);
                break;
            }
    
            partition_tally++;
        }
    }

    /* Don't call this an XTAF volume system if none of the hard-coded partitions were found. */
    if (partition_tally == 0) {
        xtaf_close(vs);
        return NULL;
    }

    /* Denote unallocated space as "Unused" disk area. */
    if (tsk_vs_part_unused(vs)) {
        xtaf_close(vs);
        return NULL;
    }

    return vs;
}
