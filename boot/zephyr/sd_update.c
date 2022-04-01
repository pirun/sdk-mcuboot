#include <ctype.h>
#include <disk/disk_access.h>
#include <drivers/flash.h>
#include <errno.h>
#include <ff.h>
#include <stddef.h>

#include "bootutil/bootutil_log.h"
#include "bootutil/image.h"
#include "bootutil/crypto/sha256.h"
#include "flash_map_backend/flash_map_backend.h"
#include <drivers/gpio.h>
#include "nrfx_gpiote.h"
#include "nrfx_clock.h"

#include "sd_update.h"

MCUBOOT_LOG_MODULE_REGISTER(sd_update);

#define PATH_SEPARATOR "/"
#define UPDATE_DIRECTORY CONFIG_SD_UPDATE_MOUNT_POINT PATH_SEPARATOR CONFIG_SD_UPDATE_DIRECTORY_NAME
#define APP_UPDATE_FILE UPDATE_DIRECTORY PATH_SEPARATOR CONFIG_SD_UPDATE_APP_CORE_IMAGE_FILE_NAME
#define APP_BACKUP_FILE UPDATE_DIRECTORY PATH_SEPARATOR CONFIG_SD_UPDATE_APP_CORE_BACKUP_FILE_NAME
#define NET_UPDATE_FILE UPDATE_DIRECTORY PATH_SEPARATOR CONFIG_SD_UPDATE_NET_CORE_IMAGE_FILE_NAME
#define NET_BACKUP_FILE UPDATE_DIRECTORY PATH_SEPARATOR CONFIG_SD_UPDATE_NET_CORE_BACKUP_FILE_NAME
#define BOOT_SECONDARY_SLOT             1

#define SHARED_SPI DT_NODELABEL(spi4) /* SD card and HW codec share the SPI4 */
#define RET_IF_ERR(err_code)                                                                       \
	do {                                                                                       \
		if (err_code) {                                                                    \
			return err_code;                                                           \
		}                                                                                  \
	} while (0)

static FATFS fat_fs;
/* mounting info */
static struct fs_mount_t mp = {
    .type = FS_FATFS,
    .fs_data = &fat_fs,
    .mnt_point = CONFIG_SD_UPDATE_MOUNT_POINT,
    .flags = FS_MOUNT_FLAG_NO_FORMAT,
};

static struct sd_update update[CORE_NUMS];

#define RET_IF_ERR_MSG(err_code, msg)                                                              \
	do {                                                                                       \
		if (err_code) {                                                                    \
			LOG_ERR("%s", msg);                                                        \
			return err_code;                                                           \
		}                                                                                  \
	} while (0)
static int lsdir(const char *path);
static int core_app_config(void)
{
	int ret;

	nrf_gpiote_latency_t latency = nrfx_gpiote_latency_get();

	if (latency != NRF_GPIOTE_LATENCY_LOWPOWER) {
		LOG_DBG("Setting gpiote latency to low power");
		nrfx_gpiote_latency_set(NRF_GPIOTE_LATENCY_LOWPOWER);
	}

	/* Use this to turn on 128 MHz clock for cpu_app */
	ret = nrfx_clock_divider_set(NRF_CLOCK_DOMAIN_HFCLK, NRF_CLOCK_HFCLK_DIV_1);
	RET_IF_ERR(ret - NRFX_ERROR_BASE_NUM);

	nrfx_clock_hfclk_start();
	while (!nrfx_clock_hfclk_is_running()) {
	}

	/* Workaround for issue with PCA10121 v0.7.0 related to SD-card */
	static const struct device *gpio_dev;

	gpio_dev = device_get_binding(DT_SPI_DEV_CS_GPIOS_LABEL(DT_NODELABEL(sdhc0)));
	if (!gpio_dev) {
		return -ENODEV;
	}

	ret = gpio_pin_configure(gpio_dev, DT_PROP(SHARED_SPI, mosi_pin),
				 GPIO_DS_ALT_HIGH | GPIO_DS_ALT_LOW);
	RET_IF_ERR(ret);
	ret = gpio_pin_configure(gpio_dev, DT_PROP(SHARED_SPI, sck_pin),
				 GPIO_DS_ALT_HIGH | GPIO_DS_ALT_LOW);
	RET_IF_ERR(ret);

	return 0;
}
int sdu_init()
{
    static const char *disk_pdrv = "SD";
    int err;
	uint64_t sd_card_size_bytes;
	uint32_t sector_count;
	size_t sector_size;

    err = core_app_config();
    if(err) {
        BOOT_LOG_ERR("Failed to initial core app gpio");
    }

    err = disk_access_init(disk_pdrv);

    if (err) {
        BOOT_LOG_ERR("Failed to initialize SD card (%d)", err);
        return err;
    }
	err = disk_access_ioctl(disk_pdrv, DISK_IOCTL_GET_SECTOR_COUNT, &sector_count);
	RET_IF_ERR_MSG(err, "Unable to get sector count");
	LOG_DBG("Sector count: %d", sector_count);

	err = disk_access_ioctl(disk_pdrv, DISK_IOCTL_GET_SECTOR_SIZE, &sector_size);
	RET_IF_ERR_MSG(err, "Unable to get sector size");
	LOG_DBG("Sector size: %d bytes", sector_size);

	sd_card_size_bytes = (uint64_t)sector_count * sector_size;
	LOG_INF("SD card volume size: %d MB", (uint32_t)(sd_card_size_bytes >> 20));

    err = fs_mount(&mp);
    if (err == FR_OK) {
        BOOT_LOG_INF("SD Card mounted");
    } else {
        BOOT_LOG_ERR("Failed to mount SD card (%d)", err);
    }
    return err;
}

int strcasecmp(const char *s1, const char *s2)
{
	const unsigned char *us1 = (const unsigned char *)s1;
	const unsigned char *us2 = (const unsigned char *)s2;

	while (tolower(*us1) == tolower(*us2++)) {
        if (*us1++ == '\0') {
			return 0;
        }
    }
    return tolower(*us1) - tolower(*--us2);
}

int sdu_check_update()
{
    int res;
    struct fs_dir_t dirp;
    static struct fs_dirent entry;
    bool has_update = false;

	fs_dir_t_init(&dirp);
    res = fs_opendir(&dirp, UPDATE_DIRECTORY);
    if (res) {
        update->update_file.filep = NULL;
        BOOT_LOG_ERR("Error opening dir %s [%d]\n", UPDATE_DIRECTORY, res);
        return res;
    }

    for (;;) {
        res = fs_readdir(&dirp, &entry);

        if (res || entry.name[0] == 0) {
            break;
        }
#if IS_ENABLED(CONFIG_SD_UPDATE_APP_CORE)
            if (entry.type == FS_DIR_ENTRY_FILE && strcasecmp(entry.name, CONFIG_SD_UPDATE_APP_CORE_IMAGE_FILE_NAME) == 0) {
            update[APP_CORE].has_update = true;
            has_update = true;
            LOG_INF("found APP update");
            break;
        }
#endif
#if IS_ENABLED(CONFIG_SD_UPDATE_NET_CORE)          
        if (entry.type == FS_DIR_ENTRY_FILE && strcasecmp(entry.name, CONFIG_SD_UPDATE_NET_CORE_IMAGE_FILE_NAME) == 0) {
            update[NET_CORE].has_update = true;
            has_update = true;
            LOG_INF("found NET update");
            break;
        }
#endif
    }

    fs_closedir(&dirp);

    if (!has_update) {
        BOOT_LOG_INF("No update file found on the SD card");
        update[APP_CORE].update_file.filep = NULL;
        update[NET_CORE].update_file.filep = NULL;
        return -ENOENT;
    }
#if IS_ENABLED(CONFIG_SD_UPDATE_APP_CORE)
    res = sdu_check_update_file(APP_CORE);
    if (!res) {
        return res;
    }
#endif    
#if IS_ENABLED(CONFIG_SD_UPDATE_NET_CORE)
    res = sdu_check_update_file(NET_CORE);
    if (!res) {
        return res;
    }
#endif
    return 0;
}
int sdu_check_update_file(uint8_t core)
{
    int res;
    const char *file_name;
    if(core == APP_CORE) {
        file_name = APP_UPDATE_FILE;
    } else {
        file_name = NET_UPDATE_FILE;
    }
    BOOT_LOG_DBG("core %d looking for %s", core, log_strdup(file_name));
	fs_file_t_init(&update[core].update_file);
    res = fs_open(&update[core].update_file, file_name, FS_O_RDWR);
    if (res) {
        BOOT_LOG_ERR("Failed to open the core %d update image file name %s (%d)", core, res, log_strdup(file_name));
        return res;
    }

    res = fs_read(&update[core].update_file, &update[core].header, sizeof(update[core].header));
    if (res < sizeof(&update[core].header)) {
        BOOT_LOG_ERR("Failed to read update header (%d)", res);
        //fs_close(&update[core].update_file);
        return res;
    }

    if (update[core].header.ih_magic != IMAGE_MAGIC) {
        BOOT_LOG_ERR("The update does not contain a valid image");
        //fs_close(&update[core].update_file);
        return res;
    }

    fs_seek(&update[core].update_file, 0, FS_SEEK_SET);
    return 0;
}

static int get_update_hash(struct sd_update *update, uint8_t *hash_result) {
    bootutil_sha256_context sha256_ctx;

    bootutil_sha256_init(&sha256_ctx);

    const size_t tmp_buf_sz = 256;
    uint8_t tmpbuf[tmp_buf_sz];

    int res;
    size_t remains = update->header.ih_hdr_size;
    remains += update->header.ih_img_size;
    remains += update->header.ih_protect_tlv_size;

    while (remains > 0) {
        res = fs_read(&update->update_file, tmpbuf, tmp_buf_sz < remains ? tmp_buf_sz : remains);
        if (res < 0) {
            return res;
        }
        bootutil_sha256_update(&sha256_ctx, tmpbuf, res);
        remains -= res;
    }

    bootutil_sha256_finish(&sha256_ctx, hash_result);

    return 0;
}

struct tlv_iterator {
    struct fs_file_t *update_file;
    off_t end;
    off_t offset;
};

static int tlv_iter_begin(struct sd_update *update, struct tlv_iterator *it) {
    off_t offset = update->header.ih_hdr_size + update->header.ih_img_size;
    struct image_tlv_info info;
    int res = fs_seek(&update->update_file, offset, FS_SEEK_SET);
    if (res) {
        return res;
    }
    res = fs_read(&update->update_file, &info, sizeof(info));
    if (res < sizeof(info)) {
        return -EIO;
    }

    if (info.it_magic == IMAGE_TLV_PROT_INFO_MAGIC) {
        if (update->header.ih_protect_tlv_size != info.it_tlv_tot) {
            return -1;
        }

        offset += info.it_tlv_tot;
        res = fs_seek(&update->update_file, offset, FS_SEEK_SET);
        if (res) {
            return res;
        }
        res = fs_read(&update->update_file, &info, sizeof(info));
        if (res < sizeof(info)) {
            return -EIO;
        }
    } else if (update->header.ih_protect_tlv_size != 0) {
        return -1;
    }

    if (info.it_magic != IMAGE_TLV_INFO_MAGIC) {
        return -1;
    }

    it->update_file = &update->update_file;
    it->offset = offset + sizeof(info);
    it->end = offset + info.it_tlv_tot;

    return 0;
}

static int tlv_iter_next(struct tlv_iterator *it, off_t *offset, uint16_t *type, uint16_t *len) {
    struct image_tlv tlv;

    if (it == NULL || it->update_file == NULL) {
        return -1;
    }

    while (it->offset < it->end) {
        int res = fs_seek(it->update_file, it->offset, FS_SEEK_SET);
        if (res) {
            return res;
        }
        res = fs_read(it->update_file, &tlv, sizeof(tlv));
        if (res < sizeof(tlv)) {
            return -EIO;
        }

        *type = tlv.it_type;
        *len = tlv.it_len;
        *offset = it->offset + sizeof(tlv);
        it->offset += sizeof(tlv) + tlv.it_len;
        return 0;
    }

    return 1;
}

int sdu_validate_update_image(struct sd_update *update)
{
    uint8_t hash[32];
    uint8_t buf[32];
    int res;

    BOOT_LOG_INF("Found update image, validating...");

    res = get_update_hash(update, hash);
    if (res) {
        BOOT_LOG_ERR("Failed to compute image hash (%d)", res);
        return res;
    }

    struct tlv_iterator it;
    res = tlv_iter_begin(update, &it);
    if (res) {
        BOOT_LOG_ERR("Failed to read update image TLVs (%d)", res);
        return res;
    }

    while (true) {
        off_t offset;
        uint16_t type;
        uint16_t len;
        res = tlv_iter_next(&it, &offset, &type, &len);
        if (res < 0) {
            BOOT_LOG_ERR("Failed to read update image TLV (%d)", res);
            return res;
        } else if (res > 0) {
            break;
        }
        if (type == IMAGE_TLV_SHA256) {
            if (len != sizeof(hash)) {
                BOOT_LOG_ERR("Incorrect update hash size");
                return -1;
            }
            res = fs_read(&update->update_file, buf, sizeof(hash));
            if (res < sizeof(hash)) {
                BOOT_LOG_ERR("Failed to read update hash (%d)", res);
                return res;
            }
            if (memcmp(hash, buf, sizeof(hash))) {
                BOOT_LOG_ERR("Incorrect update hash");
                return -1;
            }
            BOOT_LOG_INF("Update image is valid");
            return 0;
        }
    }

    BOOT_LOG_ERR("Failed to find update hash");
    return -1;
}

int sdu_backup_firmware(uint8_t core)
{
    const struct flash_area *fap;
    size_t buf_size = 256;
    uint8_t buf[buf_size];
    struct fs_file_t backup;
    int area_id;
    int res;
    const char *file_name;

    /* FIXME: Pirun Wuo Bu Ji Dow how to read net core from PCD now */
    if(core == NET_CORE)
    {
        BOOT_LOG_INF("FIXME: Pirun Wuo Bu Ji Dao how to read net core from PCD now");
        BOOT_LOG_INF("FIXME: So just skip backup net core");
        return 0;
    }
    if(core == APP_CORE) {
        file_name = APP_BACKUP_FILE;
    } else {
        file_name = NET_BACKUP_FILE;
    }

    BOOT_LOG_INF("Backing up current core %d firmware...", core);
    fs_unlink(file_name);
    /* FIXME: Read net core data from PCD*/
    area_id = flash_area_id_from_image_slot(0);
    res = flash_area_open(area_id, &fap);
    if (res) {
        BOOT_LOG_ERR("Failed to open the primary slot (%d)", res);
        goto done2;
    }

	fs_file_t_init(&backup);
    res = fs_open(&backup, file_name, FS_O_RDWR | FS_O_CREATE);
    if (res) {
        BOOT_LOG_ERR("Failed to create backup file on SD (%d)", res);
        goto done2;
    }

    size_t remains = fap->fa_size;
    off_t offset = 0;
    while (remains > 0) {
        size_t num_bytes = buf_size > remains ? remains : buf_size;
        res = flash_area_read(fap, offset, buf, num_bytes);
        if (res) {
            BOOT_LOG_ERR("Failed to read flash data (%d)", res);
            goto done;
        }
        res = fs_write(&backup, buf, num_bytes);
        if (res != num_bytes) {
            BOOT_LOG_ERR("Failed to write backup data (%d)", res);
            goto done;
        }

        remains -= num_bytes;
        offset += num_bytes;
    }
    res = 0;
    BOOT_LOG_INF("Backup complete");

done:
    fs_close(&backup);
done2:
    flash_area_close(fap);
    return res;
}

static int write_app_image(struct fs_file_t *file) {
    const struct flash_area *fap;
    size_t buf_size = 256;
    uint8_t buf[buf_size];
    int area_id;
    int res;

    BOOT_LOG_INF("Writing image to flash...");

    area_id = flash_area_id_from_image_slot(0);
    res = flash_area_open(area_id, &fap);
    if (res) {
        BOOT_LOG_ERR("Failed to open the primary slot (%d)", res);
        return res;
    }

    res = flash_area_erase(fap, 0, fap->fa_size);
    if (res) {
        BOOT_LOG_ERR("Failed to erase flash memory (%d)", res);
        goto done;
    }

    off_t offset = 0;
    size_t read = 0;
    do {
        read = fs_read(file, buf, buf_size);
        if (read < 0) {
            BOOT_LOG_ERR("Failed to read file data (%d)", res);
            goto done;
        }
        if (read < buf_size) {
            memset(buf + read, 0xFF, buf_size - read);
        }
        res = flash_area_write(fap, offset, buf, buf_size);
        if (res) {
            BOOT_LOG_ERR("Failed to write flash data (%d)", res);
            goto done;
        }

        offset += read;
    } while (read == buf_size);
    res = 0;
    BOOT_LOG_INF("Image written successfully");

done:
    flash_area_close(fap);
    return res;
}

int sdu_write_app_update(struct sd_update *update) {
    int res = fs_seek(&update->update_file, 0, FS_SEEK_SET);
    if (res) {
        BOOT_LOG_ERR("Failed to seek at the beggining of the update file (%d)", res);
        return res;
    }

    return write_app_image(&update->update_file);
}

int sdu_revert_app_update()
{
    struct fs_file_t backup;
    fs_file_t_init(&backup);
    int res = fs_open(&backup, APP_BACKUP_FILE, FS_O_RDWR);
    if (res) {
        BOOT_LOG_ERR("Failed to open the backup file (%d)", res);
        return res;
    }

    res = write_app_image(&backup);
    fs_close(&backup);

    return res;
}

int sdu_cleanup(uint8_t core, bool removeUpdate)
{
    BOOT_LOG_INF("core %d removeUpdate %d", core, removeUpdate);
    BOOT_LOG_INF("1");
    if (update[core].update_file.filep != NULL) {
    BOOT_LOG_INF("2");
        fs_close(&update[core].update_file);
    }
    BOOT_LOG_INF("3");
    if (removeUpdate) {
        BOOT_LOG_INF("4");
        fs_unlink( ((core == APP_CORE) ? APP_UPDATE_FILE : NET_UPDATE_FILE));
        BOOT_LOG_INF("5");
    }
    BOOT_LOG_INF("6");
    return 0;
}

bool sdu_do_update() {
    BOOT_LOG_INF("Starting SD update...");
    #if IS_ENABLED(CONFIG_SD_UPDATE_APP_CORE)
        BOOT_LOG_INF("APP CORE ENABLED");
    #endif
    #if IS_ENABLED(CONFIG_SD_UPDATE_NET_CORE)
        BOOT_LOG_INF("NET CORE ENABLED");
    #endif
    int res;
    bool updated = false;

    res = sdu_init();
    if (res) {
        return updated;
    }
    lsdir(UPDATE_DIRECTORY);
    res = sdu_check_update();
    if (res) {
        goto cleanup;
    }
#if IS_ENABLED(CONFIG_SD_UPDATE_APP_CORE)
    res = sdu_validate_update_image(&update[APP_CORE]);
    if (res) {
        BOOT_LOG_ERR("Failed update app core image validation (%d)", res);
        goto cleanup;
    }
    res = sdu_backup_firmware(APP_CORE);
    if (res) {
        BOOT_LOG_ERR("Could not backup app core current firmware, update won't continue. (%d)", res);
        goto cleanup;
    }
    res = sdu_write_app_update(&update[APP_CORE]);
    if (res) {
        BOOT_LOG_WRN("Failed to write app update, attempting revert...");
        res = sdu_revert_app_update();
        if (res) {
            BOOT_LOG_ERR("Revert app core failed");
        } else {
            BOOT_LOG_INF("Revert app core successful, update has not been done");
        }
    } else {
        updated = true;
    }
#endif
#if IS_ENABLED(CONFIG_SD_UPDATE_NET_CORE)
    res = sdu_validate_update_image(&update[NET_CORE]);
    if (res) {
        BOOT_LOG_ERR("Failed update net core image validation (%d)", res);
        goto cleanup;
    }
    res = sdu_backup_firmware(NET_CORE);
    if (res) {
        BOOT_LOG_ERR("Could not backup net core current firmware, update won't continue. (%d)", res);
        goto cleanup;
    }
    res = sdu_write_net_update(&update[NET_CORE]);
    if (res) {
        BOOT_LOG_WRN("Failed to write net update, attempting revert... (%d)", res);
        res = sdu_revert_net_update();
        if (res) {
            BOOT_LOG_ERR("Revert failed");
        } else {
            BOOT_LOG_INF("Revert successful, update has not been done");
        }
    } else {
        updated = true;
    }
#endif


cleanup:
    BOOT_LOG_INF("sdu_cleanup");
#if IS_ENABLED(CONFIG_SD_UPDATE_APP_CORE)
    if(update[APP_CORE].has_update) {
        sdu_cleanup(APP_CORE, updated);
    }
#endif
#if IS_ENABLED(CONFIG_SD_UPDATE_NET_CORE)
    if(update[NET_CORE].has_update) {
        sdu_cleanup(NET_CORE, updated);
    }
#endif
    BOOT_LOG_INF("SD update finished");
    fs_unmount(&mp);
    return updated;
}
static int lsdir(const char *path)
{
	int res;
	struct fs_dir_t dirp;
	static struct fs_dirent entry;

	fs_dir_t_init(&dirp);

	/* Verify fs_opendir() */
	res = fs_opendir(&dirp, path);
	if (res) {
		printk("Error opening dir %s [%d]\n", path, res);
		return res;
	}

	printk("\nListing dir %s ...\n", path);
	for (;;) {
		/* Verify fs_readdir() */
		res = fs_readdir(&dirp, &entry);

		/* entry.name[0] == 0 means end-of-dir */
		if (res || entry.name[0] == 0) {
			break;
		}

		if (entry.type == FS_DIR_ENTRY_DIR) {
			printk("[DIR ] %s\n", entry.name);
		} else {
			printk("[FILE] %s (size = %zu)\n",
				entry.name, entry.size);
		}
	}

	/* Verify fs_closedir() */
	fs_closedir(&dirp);

	return res;
}

static int write_net_image(struct fs_file_t *file) {
    const struct flash_area *fap;
    size_t buf_size = 256;
    uint8_t buf[buf_size];
    int area_id;
    int res;
    size_t read = 0;
    struct image_header *hdr;
    off_t offset = 0;
    bool dump = true;
    BOOT_LOG_INF("Writing net core image to MCUBOOT_SECONDARY...");
    area_id = flash_area_id_from_image_slot(BOOT_SECONDARY_SLOT);
    res = flash_area_open(area_id, &fap);
    BOOT_LOG_INF("writing data to 0x%08x", fap->fa_off);
    if (res) {
        BOOT_LOG_ERR("Failed to open the secondary slot (%d)", res);
        return res;
    }
    res = flash_area_erase(fap, 0, fap->fa_size);
    if (res) {
        BOOT_LOG_ERR("Failed to erase flash memory (%d)", res);
        goto done;
    }

    do {
        read = fs_read(file, buf, buf_size);
        if (read < 0) {
            BOOT_LOG_ERR("Failed to read file data (%d)", res);
            goto done;
        }
        if (read < buf_size) {
            memset(buf + read, 0xFF, buf_size - read);
        }
        if(dump){
            LOG_HEXDUMP_INF(buf, read, "write_net_image");
            LOG_HEXDUMP_INF(fap->fa_off, read, "read_flash");
            dump = false;
        }

        res = flash_area_write(fap, offset, buf, buf_size);
        if (res) {
            BOOT_LOG_ERR("Failed to write flash data (%d)", res);
            goto done;
        }
        offset += read;
    } while (read == buf_size);
    res = 0;
    dump = true;
    BOOT_LOG_INF("Net core image written successfully");
    BOOT_LOG_INF("Call pcd_network_core_update from MCUBOOT_SECONDARY");
    const struct flash_area *secondary_fa;
    flash_area_open(area_id, &secondary_fa);
    hdr = (struct image_header *)secondary_fa->fa_off;
    if(dump){
            LOG_HEXDUMP_INF(secondary_fa->fa_off, buf_size, "dump from secondary");
            dump = false;
    }
    LOG_INF("hdr address 0%08x", secondary_fa->fa_off);
    if (hdr->ih_magic == IMAGE_MAGIC) {
        LOG_INF("flash area has valid IMAGE_MAGIC");
        uint32_t fw_size = hdr->ih_img_size;
        uint32_t vtable_addr = (uint32_t)hdr + hdr->ih_hdr_size;
        uint32_t *vtable = (uint32_t *)(vtable_addr);
        uint32_t reset_addr = vtable[1];

        LOG_INF("fw_size %d", fw_size);
        LOG_INF("vtable_addr 0x%08x", vtable_addr);
        LOG_INF("vtable 0x%08x", vtable);
        LOG_INF("reset_addr 0x%08x", vtable[1]);
        if (reset_addr > PM_CPUNET_B0N_ADDRESS) {
            if(true) {//if (wait) {
                res =  pcd_network_core_update(vtable, fw_size);
            } else {
                res = pcd_network_core_update_initiate(vtable, fw_size);
            }
        } else {
            LOG_ERR("reset_addr not b0n");
        }
    } else {
        /* No IMAGE_MAGIC no valid image */
        LOG_ERR("No IMAGE_MAGIC no valid image");
        return -ENODATA;
    }

done:
    return res;
}
int sdu_write_net_update(struct sd_update *update)
{
    int res = fs_seek(&update->update_file, 0, FS_SEEK_SET);
    if (res) {
        BOOT_LOG_ERR("Failed to seek at the beggining of the net core update file (%d)", res);
        return res;
    }
    return write_net_image(&update->update_file);
}

int sdu_revert_net_update()
{
    LOG_INF("%s skip", __func__);
    return 0;
}
