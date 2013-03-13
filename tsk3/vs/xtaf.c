#include "tsk_vs_i.h"
#include "../fs/tsk_fs_i.h"
#include "../fs/tsk_xtaffs.h"

static void
xtaf_close(TSK_VS_INFO * vs)
{
    vs->tag = 0;
    tsk_vs_part_free(vs);
    free(vs);
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
//    TSK_VS_PART_INFO* part_0x80000;
//    TSK_VS_PART_INFO* part_0x80080000;
//    TSK_VS_PART_INFO* part_0x10C080000;
//    TSK_VS_PART_INFO* part_0x118eb0000;
    TSK_VS_PART_INFO* part_sys;
//    TSK_VS_PART_INFO* part_data;
//    TSK_VS_PART_INFO* all_parts[5] = {part_0x80000, part_0x80080000, part_0x10C080000, part_0x118eb0000, part_sys, part_data};
    
    
    ssize_t cnt;
    unsigned int len;
    xtaffs_sb* xtafsb;
    //EQS TODO: This may need to be malloc'ed.  AJN:  The label passed to tsk_vs_part_add must be malloc'ed.
    char zeroth_part[] = "Partition0x80000";
    char first_part[] = "Partition0x80080000";
    char second_part[] = "Partition0x10C080000";
    char third_part[] = "Partition0x118eb0000";
    char sys_part[] = "System Partition";
    char data_part[] = "Data Partition ";
//    char part_names[5][] = {
    TSK_DADDR_T offsets[] = {0x80000, 0x80080000, 0x10C080000, 0x118eb0000, 0x120eb0000, 0x130eb0000};
//    TSK_DADDR_T part_offset[] = {1024, 4195328, 8782848, 9205120, 9467264, 9991552};
//    TSK_DADDR_T part_size[] = {4194304, 4587520, 422272, 262144, 524288, 478405616};
    int itor;
    char *part_label;

    // clean up any errors that are lying around
    tsk_error_reset();


    len = sizeof(xtaffs_sb);
    xtafsb = (xtaffs_sb *) tsk_malloc(len);
    if (xtafsb == NULL) {
        return NULL;
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

    //look for XTAF sig, if it isn't there return NULL
    for(itor = 0; itor <= 5; itor++){
        /*  NOTE: This is read as a char* instead of a xtaffs_sb to keep img_read() happy */
        cnt = tsk_img_read(img_info, offsets[itor], (char *) xtafsb, len);
        if(strncmp((char*) xtafsb->magic, "XTAF", 4)){
            tsk_fprintf(stderr, "Part %d not XTAF file system\n", itor);
//            return NULL;
            continue;
        }    
        if (itor == 0) {
            continue; //EQS NOTE: This partition has a different structure so it is skipped over
            if (tsk_verbose)
                tsk_fprintf(stderr, "tsk_vs_xtaf_open: Adding part %d to list\n", itor);
            part_label = (char *) tsk_malloc(5 * sizeof(char));
            snprintf(part_label, 5, "XTAF");

            TSK_VS_PART_INFO* part_0x80000;
            part_0x80000 = (TSK_VS_PART_INFO*) tsk_malloc(sizeof(*part_0x80000));
            part_0x80000 = tsk_vs_part_add(vs, 1024, 4194304, TSK_VS_PART_FLAG_ALLOC, part_label, 0, 0);
            if (NULL == part_0x80000) {
                if (tsk_verbose)
                    tsk_fprintf(stderr, "tsk_vs_xtaf_open: Failed to add part %d\n", itor);
                return NULL;
            }
        } else if (itor == 1) {
            continue; //EQS NOTE: This partition has a different structure so it is skipped over
            if (tsk_verbose)
                tsk_fprintf(stderr, "tsk_vs_xtaf_open: Adding part %d to list\n", itor);
            part_label = (char *) tsk_malloc(5 * sizeof(char));
            snprintf(part_label, 5, "XTAF");

            TSK_VS_PART_INFO* part_0x80080000;
            part_0x80080000 = (TSK_VS_PART_INFO*) tsk_malloc(sizeof(*part_0x80080000));
            part_0x80080000 = tsk_vs_part_add(vs, 4195328, 4587520, TSK_VS_PART_FLAG_ALLOC, part_label, 0, 0);
            if (NULL == part_0x80080000) {
                if (tsk_verbose)
                    tsk_fprintf(stderr, "tsk_vs_xtaf_open: Failed to add part %d\n", itor);
                return NULL;
            }
        } else if (itor == 2) {
            if (tsk_verbose)
                tsk_fprintf(stderr, "tsk_vs_xtaf_open: Adding part %d to list\n", itor);
            part_label = (char *) tsk_malloc(5 * sizeof(char));
            snprintf(part_label, 5, "XTAF");

            TSK_VS_PART_INFO* part_0x10C080000;
            part_0x10C080000 = (TSK_VS_PART_INFO*) tsk_malloc(sizeof(*part_0x10C080000));
            part_0x10C080000 = tsk_vs_part_add(vs, 8782848, 422272, TSK_VS_PART_FLAG_ALLOC, part_label, 0, 0);
            if (NULL == part_0x10C080000) {
                if (tsk_verbose)
                    tsk_fprintf(stderr, "tsk_vs_xtaf_open: Failed to add part %d\n", itor);
                return NULL;
            }
        } else if (itor == 3) {
            if (tsk_verbose)
                tsk_fprintf(stderr, "tsk_vs_xtaf_open: Adding part %d to list\n", itor);
            part_label = (char *) tsk_malloc(5 * sizeof(char));
            snprintf(part_label, 5, "XTAF");

            TSK_VS_PART_INFO* part_0x118eb0000;
            part_0x118eb0000 = (TSK_VS_PART_INFO*) tsk_malloc(sizeof(*part_0x118eb0000));
            part_0x118eb0000 = tsk_vs_part_add(vs, 9205120, 262144, TSK_VS_PART_FLAG_ALLOC, part_label, 0, 0);
            if (NULL == part_0x118eb0000) {
                if (tsk_verbose)
                    tsk_fprintf(stderr, "tsk_vs_xtaf_open: Failed to add part %d\n", itor);
                return NULL;
            }
        } else if (itor == 4) {
            if (tsk_verbose)
                tsk_fprintf(stderr, "tsk_vs_xtaf_open: Adding part %d to list\n", itor);
            part_label = (char *) tsk_malloc(5 * sizeof(char));
            snprintf(part_label, 5, "XTAF");

            TSK_VS_PART_INFO* part_sys;
            part_sys = (TSK_VS_PART_INFO*) tsk_malloc(sizeof(*part_sys));
            part_sys = tsk_vs_part_add(vs, 9467264, 524288, TSK_VS_PART_FLAG_ALLOC, part_label, 0, 0);
            if (NULL == part_sys) {
                if (tsk_verbose)
                    tsk_fprintf(stderr, "tsk_vs_xtaf_open: Failed to add part %d\n", itor);
                return NULL;
            }
        } else if(itor == 5) {
            if (tsk_verbose)
                tsk_fprintf(stderr, "tsk_vs_xtaf_open: Adding part %d to list\n", itor);
            part_label = (char *) tsk_malloc(5 * sizeof(char));
            snprintf(part_label, 5, "XTAF");

            TSK_VS_PART_INFO* part_data;
            part_data = (TSK_VS_PART_INFO*) tsk_malloc(sizeof(*part_data));
            part_data = tsk_vs_part_add(vs, 9991552, 478405616, TSK_VS_PART_FLAG_ALLOC, part_label, 0, 0);
            if (NULL == part_data) {
                if (tsk_verbose)
                    tsk_fprintf(stderr, "tsk_vs_xtaf_open: Failed to add part %d\n", itor);
                return NULL;
            }
        }

/*
        all_parts[itor] = (TSK_VS_PART_INFO*) tsk_malloc(sizeof(TSK_VS_PART_INFO*));
        printf("size = %"PRIu64" offset = %"PRIu64"\n", part_size[itor], part_offset[itor]);
        all_parts[itor] = tsk_vs_part_add(vs, part_offset[itor], part_size[itor], 0x1, "part", 0, 0);
*/
    }
    
/*
    part_0x80000 = (TSK_VS_PART_INFO*) tsk_malloc(sizeof(*part_0x80000));
    part_0x80080000 = (TSK_VS_PART_INFO*) tsk_malloc(sizeof(*part_0x80080000));
    part_0x10C080000 = (TSK_VS_PART_INFO*) tsk_malloc(sizeof(*part_0x10C080000));
    part_0x118eb0000 = (TSK_VS_PART_INFO*) tsk_malloc(sizeof(*part_0x118eb0000));
*/
//    part_sys = (TSK_VS_PART_INFO*) tsk_malloc(sizeof(*part_sys));
//    part_data = (TSK_VS_PART_INFO*) tsk_malloc(sizeof(*part_data));


/*
    part_0x80000  = tsk_vs_part_add(vs, 1024, 4194304, 0x1, zeroth_part, 0, 0);
    part_0x80080000  = tsk_vs_part_add(vs, 4195328, 4587520, 0x1, first_part, 0, 0);
*/
    
//    part_0x10C080000  = tsk_vs_part_add(vs, 8782848, 422272, 0x1, second_part, 0, 0);
//    part_0x118eb0000  = tsk_vs_part_add(vs, 9205120, 262144, 0x1, third_part, 0, 0);

//    part_sys  = tsk_vs_part_add(vs, 9467264, 524288, 0x1, sys_part, 0, 0);
//    part_data  = tsk_vs_part_add(vs, 9991552, 478405616, 0x1, data_part, 0, 0);

    /* fill in the sorted list with the 'unknown' values */
    if (tsk_vs_part_unused(vs)) {
        xtaf_close(vs);
        return NULL;
    }

    return vs;
}
