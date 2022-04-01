#ifndef H_SD_UPDATE_SD
#define H_SD_UPDATE_SD

#include <fs/fs.h>

#include "bootutil/image.h"

struct sd_update {
    struct image_header header;
    struct fs_file_t update_file;
};

int sdu_init();

int sdu_check_update(struct sd_update *update);

int sdu_validate_update_image(struct sd_update *update);

int sdu_backup_firmware();

int sdu_write_update(struct sd_update *update);

int sdu_revert_update();

int sdu_cleanup(struct sd_update *update, bool removeUpdate);

bool sdu_do_update();

#endif