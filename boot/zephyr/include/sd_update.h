#ifndef H_SD_UPDATE_SD
#define H_SD_UPDATE_SD

#include <fs/fs.h>

#include "bootutil/image.h"
static struct sd_update {
    struct image_header header;
    struct fs_file_t update_file;
    bool has_update;
    bool updated;
};

#define APP_CORE 0
#define NET_CORE 1
#define CORE_NUMS 2

int sdu_init();

int sdu_check_update();

int sdu_check_update_file(uint8_t core);

int sdu_validate_update_image(struct sd_update *update);

int sdu_backup_firmware(uint8_t core);

int sdu_write_app_update(struct sd_update *update);

int sdu_revert_app_update();

int sdu_write_net_update(struct sd_update *update);

int sdu_revert_net_update();

int sdu_cleanup(uint8_t core, bool removeUpdate);

bool sdu_do_update();
int sdu_update_net();
#endif