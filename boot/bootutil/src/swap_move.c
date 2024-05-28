/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2019 JUUL Labs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "bootutil/bootutil.h"
#include "bootutil_priv.h"
#include "swap_priv.h"
#include "bootutil/bootutil_log.h"

#include "mcuboot_config/mcuboot_config.h"


#ifdef MCUBOOT_DELTA_UPGRADE
#include "../../zephyr/delta_dfu_lib/include/delta.h"
#define FLASH_NODEID 	DT_CHOSEN(zephyr_flash_controller)
extern uint32_t patch_size; 
extern const struct device *flash_device;
extern  uint8_t opFlag ;
extern off_t status_address;
extern struct detools_apply_patch_t apply_patch;
/** variable used to indicate source image should be moved up how many pages before aplly */
extern uint8_t move_up_pages;	
extern fih_int get_source_hash(const struct flash_area *fap,uint8_t *hash_buf);
#endif

BOOT_LOG_MODULE_DECLARE(mcuboot);

#ifdef MCUBOOT_SWAP_USING_MOVE

#if defined(MCUBOOT_VALIDATE_PRIMARY_SLOT)
/*
 * FIXME: this might have to be updated for threaded sim
 */
int boot_status_fails = 0;
#define BOOT_STATUS_ASSERT(x)                \
    do {                                     \
        if (!(x)) {                          \
            boot_status_fails++;             \
        }                                    \
    } while (0)
#else
#define BOOT_STATUS_ASSERT(x) ASSERT(x)
#endif

uint32_t
find_last_idx(struct boot_loader_state *state, uint32_t swap_size)
{
    uint32_t sector_sz;
    uint32_t sz;
    uint32_t last_idx;

    sector_sz = boot_img_sector_size(state, BOOT_PRIMARY_SLOT, 0);
    sz = 0;
    last_idx = 0;
    while (1) {
        sz += sector_sz;
        last_idx++;
        if (sz >= swap_size) {
            break;
        }
    }

    return last_idx;
}

int
boot_read_image_header(struct boot_loader_state *state, int slot,
                       struct image_header *out_hdr, struct boot_status *bs)
{
    const struct flash_area *fap;
    uint32_t off;
    uint32_t sz;
    uint32_t last_idx;
    uint32_t swap_size;
    int area_id;
    int rc;

#if (BOOT_IMAGE_NUMBER == 1)
    (void)state;
#endif

    off = 0;
    if (bs && !boot_status_is_reset(bs)) {
	boot_find_status(BOOT_CURR_IMG(state), &fap);
        if (fap == NULL || boot_read_swap_size(fap, &swap_size)) {
            rc = BOOT_EFLASH;
            goto done;
        }
        flash_area_close(fap);

        last_idx = find_last_idx(state, swap_size);
        sz = boot_img_sector_size(state, BOOT_PRIMARY_SLOT, 0);

        /*
         * Find the correct offset or slot where the image header is expected to
         * be found for the steps where it is moved or swapped.
         */
        if (bs->op == BOOT_STATUS_OP_MOVE && slot == 0 && bs->idx > last_idx) {
            off = sz;
        } else if (bs->op == BOOT_STATUS_OP_SWAP) {
            if (bs->idx > 1 && bs->idx <= last_idx) {
                slot = (slot == 0) ? 1 : 0;
            } else if (bs->idx == 1) {
                if (slot == 0) {
                    off = sz;
                } else if (slot == 1 && bs->state == 2) {
                    slot = 0;
                }
            }
        }
    }

    area_id = flash_area_id_from_multi_image_slot(BOOT_CURR_IMG(state), slot);
    rc = flash_area_open(area_id, &fap);
    if (rc != 0) {
        rc = BOOT_EFLASH;
        goto done;
    }

    rc = flash_area_read(fap, off, out_hdr, sizeof *out_hdr);
    if (rc != 0) {
        rc = BOOT_EFLASH;
        goto done;
    }

    /* We only know where the headers are located when bs is valid */
    if (bs != NULL && out_hdr->ih_magic != IMAGE_MAGIC) {
        rc = -1;
        goto done;
    }

    rc = 0;

done:
    flash_area_close(fap);
    return rc;
}

int
swap_read_status_bytes(const struct flash_area *fap,
        struct boot_loader_state *state, struct boot_status *bs)
{
    uint32_t off;
    uint8_t status;
    int max_entries;
    int found_idx;
    uint8_t write_sz;
    int move_entries;
    int rc;
    int last_rc;
    int erased_sections;
    int i;

    max_entries = boot_status_entries(BOOT_CURR_IMG(state), fap);
    if (max_entries < 0) {
        return BOOT_EBADARGS;
    }

    erased_sections = 0;
    found_idx = -1;
    /* skip erased sectors at the end */
    last_rc = 1;
    write_sz = BOOT_WRITE_SZ(state);
    off = boot_status_off(fap);
    for (i = max_entries; i > 0; i--) {
        rc = flash_area_read(fap, off + (i - 1) * write_sz, &status, 1);
        if (rc < 0) {
            return BOOT_EFLASH;
        }

        if (bootutil_buffer_is_erased(fap, &status, 1)) {
            if (rc != last_rc) {
                erased_sections++;
            }
        } else {
            if (found_idx == -1) {
                found_idx = i;
            }
        }
        last_rc = rc;
    }

    if (erased_sections > 1) {
        /* This means there was an error writing status on the last
         * swap. Tell user and move on to validation!
         */
#if !defined(__BOOTSIM__)
        BOOT_LOG_ERR("Detected inconsistent status!");
#endif

#if !defined(MCUBOOT_VALIDATE_PRIMARY_SLOT)
        /* With validation of the primary slot disabled, there is no way
         * to be sure the swapped primary slot is OK, so abort!
         */
        assert(0);
#endif
    }

    move_entries = BOOT_MAX_IMG_SECTORS * BOOT_STATUS_MOVE_STATE_COUNT;
    if (found_idx == -1) {
        /* no swap status found; nothing to do */
    } else if (found_idx < move_entries) {
        bs->op = BOOT_STATUS_OP_MOVE;
        bs->idx = (found_idx  / BOOT_STATUS_MOVE_STATE_COUNT) + BOOT_STATUS_IDX_0;
        bs->state = (found_idx % BOOT_STATUS_MOVE_STATE_COUNT) + BOOT_STATUS_STATE_0;;
    } else {
        bs->op = BOOT_STATUS_OP_SWAP;
        bs->idx = ((found_idx - move_entries) / BOOT_STATUS_SWAP_STATE_COUNT) + BOOT_STATUS_IDX_0;
        bs->state = ((found_idx - move_entries) % BOOT_STATUS_SWAP_STATE_COUNT) + BOOT_STATUS_STATE_0;
    }

    return 0;
}

uint32_t
boot_status_internal_off(const struct boot_status *bs, int elem_sz)
{
    uint32_t off;
    int idx_sz;

    idx_sz = elem_sz * ((bs->op == BOOT_STATUS_OP_MOVE) ?
            BOOT_STATUS_MOVE_STATE_COUNT : BOOT_STATUS_SWAP_STATE_COUNT);

    off = ((bs->op == BOOT_STATUS_OP_MOVE) ?
               0 : (BOOT_MAX_IMG_SECTORS * BOOT_STATUS_MOVE_STATE_COUNT * elem_sz)) +
           (bs->idx - BOOT_STATUS_IDX_0) * idx_sz +
           (bs->state - BOOT_STATUS_STATE_0) * elem_sz;

    return off;
}

int
boot_slots_compatible(struct boot_loader_state *state)
{
#if defined (PM_S1_ADDRESS) || defined (MCUBOOT_DELTA_UPGRADE)
    /* Patch needed for NCS. In this case, image 1 primary points to the other
     * B1 slot (ie S0 or S1), and image 0 primary points to the app.
     * With this configuration, image 0 and image 1 share the secondary slot.
     * Hence, the primary slot of image 1 will be *smaller* than image 1's
     * secondary slot. This is not allowed in upstream mcuboot, so we need
     * this patch to allow it. Also, all of these checks are redundant when
     * partition manager is in use, and since we have the same sector size
     * in all of our flash.
     */
        return 1;
#else
    size_t num_sectors_pri;
    size_t num_sectors_sec;
    size_t sector_sz_pri = 0;
    size_t sector_sz_sec = 0;
    size_t i;

    num_sectors_pri = boot_img_num_sectors(state, BOOT_PRIMARY_SLOT);
    num_sectors_sec = boot_img_num_sectors(state, BOOT_SECONDARY_SLOT);
    if ((num_sectors_pri != num_sectors_sec) &&
            (num_sectors_pri != (num_sectors_sec + 1))) {
        BOOT_LOG_WRN("Cannot upgrade: not a compatible amount of sectors[%d:%d]",num_sectors_pri,num_sectors_sec);
        return 0;
    }

    if (num_sectors_pri > BOOT_MAX_IMG_SECTORS) {
        BOOT_LOG_WRN("Cannot upgrade: more sectors than allowed");
        return 0;
    }

    for (i = 0; i < num_sectors_sec; i++) {
        sector_sz_pri = boot_img_sector_size(state, BOOT_PRIMARY_SLOT, i);
        sector_sz_sec = boot_img_sector_size(state, BOOT_SECONDARY_SLOT, i);
        if (sector_sz_pri != sector_sz_sec) {
            BOOT_LOG_WRN("Cannot upgrade: not same sector layout");
            return 0;
        }
    }

    if (num_sectors_pri > num_sectors_sec) {
        if (sector_sz_pri != boot_img_sector_size(state, BOOT_PRIMARY_SLOT, i)) {
            BOOT_LOG_WRN("Cannot upgrade: not same sector layout");
            return 0;
        }
    }

    return 1;
#endif /* PM_S1_ADDRESS */
}

#define BOOT_LOG_SWAP_STATE(area, state)                            \
    BOOT_LOG_INF("%s: magic=%s, swap_type=0x%x, copy_done=0x%x, "   \
                 "image_ok=0x%x",                                   \
                 (area),                                            \
                 ((state)->magic == BOOT_MAGIC_GOOD ? "good" :      \
                  (state)->magic == BOOT_MAGIC_UNSET ? "unset" :    \
                  "bad"),                                           \
                 (state)->swap_type,                                \
                 (state)->copy_done,                                \
                 (state)->image_ok)

int
swap_status_source(struct boot_loader_state *state)
{
    struct boot_swap_state state_primary_slot;
    struct boot_swap_state state_secondary_slot;
    int rc;
    uint8_t source;
    uint8_t image_index;

#if (BOOT_IMAGE_NUMBER == 1)
    (void)state;
#endif

    image_index = BOOT_CURR_IMG(state);

    rc = boot_read_swap_state_by_id(FLASH_AREA_IMAGE_PRIMARY(image_index),
            &state_primary_slot);
    assert(rc == 0);

    BOOT_LOG_SWAP_STATE("Primary image", &state_primary_slot);

    rc = boot_read_swap_state_by_id(FLASH_AREA_IMAGE_SECONDARY(image_index),
            &state_secondary_slot);
    assert(rc == 0);

    BOOT_LOG_SWAP_STATE("Secondary image", &state_secondary_slot);

    if (state_primary_slot.magic == BOOT_MAGIC_GOOD &&
            state_primary_slot.copy_done == BOOT_FLAG_UNSET &&
            state_secondary_slot.magic != BOOT_MAGIC_GOOD) {

        source = BOOT_STATUS_SOURCE_PRIMARY_SLOT;

        BOOT_LOG_INF("Boot source: primary slot");
        return source;
    }

    BOOT_LOG_INF("Boot source: none");
    return BOOT_STATUS_SOURCE_NONE;
}


#ifdef MCUBOOT_DELTA_UPGRADE
static void
boot_move_sector_up_pages(int idx, uint32_t sz, uint8_t pages, struct boot_loader_state *state,
        struct boot_status *bs, const struct flash_area *fap_pri,
        const struct flash_area *fap_sec)
{
    uint32_t new_off;
    uint32_t old_off;
    int rc;

    /*
     * FIXME: assuming sectors of size == sz, a single off variable
     * would be enough
     */

    /* Calculate offset from start of image area. */
    new_off = boot_img_sector_off(state, BOOT_PRIMARY_SLOT, idx + pages -1);
    old_off = boot_img_sector_off(state, BOOT_PRIMARY_SLOT, idx - 1);

    if (bs->idx == BOOT_STATUS_IDX_0) {
        if (bs->source != BOOT_STATUS_SOURCE_PRIMARY_SLOT) {
            rc = swap_erase_trailer_sectors(state, fap_pri);
            assert(rc == 0);

            rc = swap_status_init(state, fap_pri, bs);
            assert(rc == 0);
        }

        rc = swap_erase_trailer_sectors(state, fap_sec);
        assert(rc == 0);
    }

    rc = boot_erase_region(fap_pri, new_off, sz);
    assert(rc == 0);
    // BOOT_LOG_INF("============Start sector move up at %" PRIu32 "\n", k_uptime_get_32());
    rc = boot_copy_region(state, fap_pri, fap_pri, old_off, new_off, sz);
    assert(rc == 0);
    // BOOT_LOG_INF("============Start sector move up at %" PRIu32 "\n", k_uptime_get_32());
    rc = boot_write_status(state, bs);

    bs->idx++;
    BOOT_STATUS_ASSERT(rc == 0);
}


static void
boot_move_sector_down_pages(int idx, uint32_t sz, uint8_t pages, struct boot_loader_state *state,
        struct boot_status *bs, const struct flash_area *fap_pri,
        const struct flash_area *fap_sec)
{
    uint32_t new_off;
    uint32_t old_off;
    int rc;

    /*
     * FIXME: assuming sectors of size == sz, a single off variable
     * would be enough
     */

    /* Calculate offset from start of image area. */
    old_off = boot_img_sector_off(state, BOOT_PRIMARY_SLOT, idx + pages -1);
    new_off = boot_img_sector_off(state, BOOT_PRIMARY_SLOT, idx - 1);

    if (bs->idx == BOOT_STATUS_IDX_0) {
        if (bs->source != BOOT_STATUS_SOURCE_PRIMARY_SLOT) {
            rc = swap_erase_trailer_sectors(state, fap_pri);
            assert(rc == 0);

            rc = swap_status_init(state, fap_pri, bs);
            assert(rc == 0);
        }

        rc = swap_erase_trailer_sectors(state, fap_sec);
        assert(rc == 0);
    }

    rc = boot_erase_region(fap_pri, new_off, sz);
    assert(rc == 0);

    rc = boot_copy_region(state, fap_pri, fap_pri, old_off, new_off, sz);
    assert(rc == 0);

    rc = boot_write_status(state, bs);

    bs->idx++;
    BOOT_STATUS_ASSERT(rc == 0);
}

#else

static void
boot_swap_sectors(int idx, uint32_t sz, struct boot_loader_state *state,
        struct boot_status *bs, const struct flash_area *fap_pri,
        const struct flash_area *fap_sec)
{
    uint32_t pri_off;
    uint32_t pri_up_off;
    uint32_t sec_off;
    int rc;

    pri_up_off = boot_img_sector_off(state, BOOT_PRIMARY_SLOT, idx);
    pri_off = boot_img_sector_off(state, BOOT_PRIMARY_SLOT, idx - 1);
    sec_off = boot_img_sector_off(state, BOOT_SECONDARY_SLOT, idx - 1);

    if (bs->state == BOOT_STATUS_STATE_0) {
        rc = boot_erase_region(fap_pri, pri_off, sz);
        assert(rc == 0);

        rc = boot_copy_region(state, fap_sec, fap_pri, sec_off, pri_off, sz);
        assert(rc == 0);

        rc = boot_write_status(state, bs);
        bs->state = BOOT_STATUS_STATE_1;
        BOOT_STATUS_ASSERT(rc == 0);
    }

    if (bs->state == BOOT_STATUS_STATE_1) {
        rc = boot_erase_region(fap_sec, sec_off, sz);
        assert(rc == 0);

        rc = boot_copy_region(state, fap_pri, fap_sec, pri_up_off, sec_off, sz);
        assert(rc == 0);

        rc = boot_write_status(state, bs);
        bs->idx++;
        bs->state = BOOT_STATUS_STATE_0;
        BOOT_STATUS_ASSERT(rc == 0);
    }
}

/*
 * "Moves" the sector located at idx - 1 to idx.
 */
static void
boot_move_sector_up(int idx, uint32_t sz, struct boot_loader_state *state,
        struct boot_status *bs, const struct flash_area *fap_pri,
        const struct flash_area *fap_sec)
{
    uint32_t new_off;
    uint32_t old_off;
    int rc;

    /*
     * FIXME: assuming sectors of size == sz, a single off variable
     * would be enough
     */

    /* Calculate offset from start of image area. */
    new_off = boot_img_sector_off(state, BOOT_PRIMARY_SLOT, idx);
    old_off = boot_img_sector_off(state, BOOT_PRIMARY_SLOT, idx - 1);

    if (bs->idx == BOOT_STATUS_IDX_0) {
        if (bs->source != BOOT_STATUS_SOURCE_PRIMARY_SLOT) {
            rc = swap_erase_trailer_sectors(state, fap_pri);
            assert(rc == 0);

            rc = swap_status_init(state, fap_pri, bs);
            assert(rc == 0);
        }

        rc = swap_erase_trailer_sectors(state, fap_sec);
        assert(rc == 0);
    }

    rc = boot_erase_region(fap_pri, new_off, sz);
    assert(rc == 0);

    rc = boot_copy_region(state, fap_pri, fap_pri, old_off, new_off, sz);
    assert(rc == 0);

    rc = boot_write_status(state, bs);

    bs->idx++;
    BOOT_STATUS_ASSERT(rc == 0);
}

#endif
/*
 * When starting a revert the swap status exists in the primary slot, and
 * the status in the secondary slot is erased. To start the swap, the status
 * area in the primary slot must be re-initialized; if during the small
 * window of time between re-initializing it and writing the first metadata
 * a reset happens, the swap process is broken and cannot be resumed.
 *
 * This function handles the issue by making the revert look like a permanent
 * upgrade (by initializing the secondary slot).
 */
void
fixup_revert(const struct boot_loader_state *state, struct boot_status *bs,
        const struct flash_area *fap_sec)
{
    struct boot_swap_state swap_state;
    int rc;

#if (BOOT_IMAGE_NUMBER == 1)
    (void)state;
#endif

    /* No fixup required */
    if (bs->swap_type != BOOT_SWAP_TYPE_REVERT ||
        bs->op != BOOT_STATUS_OP_MOVE ||
        bs->idx != BOOT_STATUS_IDX_0) {
        return;
    }

    rc = boot_read_swap_state(fap_sec, &swap_state);
    assert(rc == 0);

    BOOT_LOG_SWAP_STATE("Secondary image", &swap_state);

    if (swap_state.magic == BOOT_MAGIC_UNSET) {
        rc = swap_erase_trailer_sectors(state, fap_sec);
        assert(rc == 0);

        rc = boot_write_image_ok(fap_sec);
        assert(rc == 0);

        rc = boot_write_swap_size(fap_sec, bs->swap_size);
        assert(rc == 0);

        rc = boot_write_magic(fap_sec);
        assert(rc == 0);
    }
}

void
swap_run(struct boot_loader_state *state, struct boot_status *bs,
         uint32_t copy_size)
{
    uint32_t sz;
    uint32_t sector_sz;
    uint32_t idx;
    uint32_t trailer_sz;
    uint32_t first_trailer_idx;
    uint32_t last_idx;
    uint8_t image_index;
    const struct flash_area *fap_pri;
    const struct flash_area *fap_sec;
    int rc;

    BOOT_LOG_INF("Starting swap using move algorithm.");

    last_idx = find_last_idx(state, copy_size);
    sector_sz = boot_img_sector_size(state, BOOT_PRIMARY_SLOT, 0);
#ifdef MCUBOOT_DELTA_UPGRADE
    BOOT_LOG_INF("last_idx=%d\t sector_sz=%d\t Start Delta DFU at %" PRIu32 "\n", last_idx,sector_sz,k_uptime_get_32());
#endif
    /*
     * When starting a new swap upgrade, check that there is enough space.
     */
    if (boot_status_is_reset(bs)) {
        sz = 0;
        trailer_sz = boot_trailer_sz(BOOT_WRITE_SZ(state));
        first_trailer_idx = boot_img_num_sectors(state, BOOT_PRIMARY_SLOT) - 1;

        while (1) {
            sz += sector_sz;
            if  (sz >= trailer_sz) {
                break;
            }
            first_trailer_idx--;
        }

        if (last_idx >= first_trailer_idx) {
            BOOT_LOG_WRN("Not enough free space to run swap upgrade");
            BOOT_LOG_WRN("required %d bytes but only %d are available",
                         (last_idx + 1) * sector_sz,
                         first_trailer_idx * sector_sz);
            bs->swap_type = BOOT_SWAP_TYPE_NONE;
            return;
        }
    }

    image_index = BOOT_CURR_IMG(state);

    rc = flash_area_open(FLASH_AREA_IMAGE_PRIMARY(image_index), &fap_pri);
    assert (rc == 0);

    rc = flash_area_open(FLASH_AREA_IMAGE_SECONDARY(image_index), &fap_sec);
    assert (rc == 0);

#ifdef MCUBOOT_DELTA_UPGRADE
    uint8_t source_hash[32] = {0};
    fih_int fih_rc = FIH_FAILURE;
  
    flash_device = DEVICE_DT_GET(FLASH_NODEID);
	if(!flash_device) {
        BOOT_LOG_INF("Load flash driver failed!!!\r\n");
		return;
	}

    fih_rc = get_source_hash(fap_pri, source_hash);
#ifdef DELTA_ENABLE_LOG
    if (fih_rc == FIH_SUCCESS)
    {
        printf("\nsource_hash read from slot 1:\r\n");
        for(int i = 0; i < sizeof(source_hash); i++)
        {
            printf("%02X ",source_hash[i]);
        }
    }
#endif
	rc = delta_read_patch_header(source_hash, &patch_size, &opFlag);
	if (rc < 0) {
		printf("ret=%d	read patch file error, exit delta update process!!!\n", rc);
        flash_area_erase(fap_sec, 0, flash_area_get_size(fap_sec));       //just for test
		return;
	}
    else
    {
    #ifdef MCUBOOT_WRITE_STATUS_DYNAMIC
        move_up_pages = 10 + ((patch_size/2)/PAGE_SIZE);
    #else
        move_up_pages = (((patch_size/2)/PAGE_SIZE > 0) ? ((patch_size/2)/PAGE_SIZE) : 1) ;
    #endif
        printf("##patch_size = %d\t opFlag = %02X\t move_up_pages=%d\t status_address=0X%lX\r\n", patch_size, opFlag, move_up_pages,status_address);
    }
#endif

    fixup_revert(state, bs, fap_sec);

#ifndef MCUBOOT_DELTA_UPGRADE
    if (bs->op == BOOT_STATUS_OP_MOVE) {
        idx = last_idx;
        while (idx > 0) {
            if (idx <= (last_idx - bs->idx + 1)) {
                boot_move_sector_up(idx, sector_sz, state, bs, fap_pri, fap_sec);
            }
            idx--;
        }
        bs->idx = BOOT_STATUS_IDX_0;
    }

    bs->op = BOOT_STATUS_OP_SWAP;

    idx = 1;
    while (idx <= last_idx) {
        if (idx >= bs->idx) {
            boot_swap_sectors(idx, sector_sz, state, bs, fap_pri, fap_sec);
        }
        idx++;
    }

#else

    // BOOT_LOG_INF("============Start sector move up at %" PRIu32 "\n", k_uptime_get_32());
/** move up source image move_up_pages pages */
    if (bs->op == BOOT_STATUS_OP_MOVE) {
        idx = last_idx;
        while (idx > 0) {
            if (idx <= (last_idx - bs->idx + 1)) {
                boot_move_sector_up_pages(idx, sector_sz, move_up_pages, state, bs, fap_pri, fap_sec);
            }
            idx--;
        }
        bs->idx = BOOT_STATUS_IDX_0;
        bs->op = BOOT_STATUS_OP_APPLY;
    }
    // BOOT_LOG_INF("============End sector move up at %" PRIu32 "\n", k_uptime_get_32());

    struct flash_mem flash_pt = {0};
    /** This step try to find the old image pages which will be used after be erased*/
    if(opFlag == DELTA_OP_TRAVERSE)
    { 
        if(traverse_delta_file(&flash_pt, &apply_patch) > 0)
        {
            opFlag = DELTA_OP_APPLY;
        }  
        else
        {
            bs->op = BOOT_STATUS_OP_RESTORE;
            goto restore;
        }     
    }
    // BOOT_LOG_INF("============Traverse end at %" PRIu32 "\n", k_uptime_get_32());
    /** Now we start to apply patch file to create new image*/
    if(opFlag == DELTA_OP_APPLY)
    { 
    #ifdef MCUBOOT_WRITE_STATUS_DYNAMIC
        status_address = get_status_address();
    #endif

        rc = apply_read_status(&flash_pt); 
        if (rc < 0) {
            bs->op = BOOT_STATUS_OP_RESTORE;
            goto restore;
        }  

        // printf("##Now start applying patch file!!!\r\n");

        rc = delta_apply_init(&flash_pt,patch_size,&apply_patch);
        if (rc < 0) {
            bs->op = BOOT_STATUS_OP_RESTORE;
            goto restore;
        }      
                 
        delta_check_and_apply(&flash_pt, &apply_patch);
    }
    BOOT_LOG_INF("============Applying end at %" PRIu32 "\n", k_uptime_get_32());
restore:
    if(bs->op == BOOT_STATUS_OP_RESTORE)
    {
        printf("!!!There is something wrong during apply, let's restore the old image. move_down_pages=%d!!!\r\n", move_up_pages);
        idx = 1;
        while (idx <= last_idx) {
            if (idx >= (bs->idx)) {
                boot_move_sector_down_pages(idx, sector_sz, move_up_pages, state, bs, fap_pri, fap_sec);
            }
            idx++;
        }
        bs->idx = BOOT_STATUS_IDX_0;
        bs->op = BOOT_STATUS_OP_MOVE;
    }
#endif

    flash_area_close(fap_pri);
    flash_area_close(fap_sec);
}



int app_max_size(struct boot_loader_state *state)
{
    uint32_t sz = 0;
    uint32_t sector_sz;
    uint32_t trailer_sz;
    uint32_t first_trailer_idx;

    sector_sz = boot_img_sector_size(state, BOOT_PRIMARY_SLOT, 0);
    trailer_sz = boot_trailer_sz(BOOT_WRITE_SZ(state));
    first_trailer_idx = boot_img_num_sectors(state, BOOT_PRIMARY_SLOT) - 1;

    while (1) {
        sz += sector_sz;
        if  (sz >= trailer_sz) {
            break;
        }
        first_trailer_idx--;
    }

    return (first_trailer_idx * sector_sz);
}

#endif
