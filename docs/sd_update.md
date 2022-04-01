# Updating firmware from an SD card

## General

The boot loader is able to update the firmware image from another flash partition or an SD card. The first option is available by default. The later one is currently only available for Zephyr and only supports the FAT file system. To enable this feature you need to add the following lines into the *prj.conf* in *boot/zephyr*:

 - `CONFIG_MCUBOOT_SD_UPDATE=y` which automatically selects `CONFIG_DISK_ACCESS`, `CONFIG_DISK_ACCESS_SDHC`, `CONFIG_FILE_SYSTEM` and `CONFIG_FAT_FILESYSTEM_ELM`
 - enable SD card and related drivers, this depends on your board, example is given below
 - depending on the drivers you may very probably need to enable multithreading by adding `CONFIG_MULTITHREADING=y`

Besides that there are four optional config lines:

 - `CONFIG_SD_UPDATE_MOUNT_POINT`: SD card mount point; default `"/SD:"`
 - `CONFIG_SD_UPDATE_DIRECTORY_NAME`: Directory with update file on the SD card, `""` for root; default `""`
 - `CONFIG_SD_UPDATE_IMAGE_FILE_NAME`: Name of the update file; default `"UPDATE.BIN"`
 - `CONFIG_SD_UPDATE_BACKUP_FILE_NAME`: Name of the firmware backup file; default: `"BACKUP.BIN"`

### Example of the lines added to prj.conf
+Below is a sample of the lines that needed to be added to the prj.conf on Nordic's NRF52 DK (nrf52dk_pca10040) to enable the SD card update. The loader will use Disk Access SDHC drivers and the SD card is connected to SPI2 which will be accessed using legacy SPI drivers because of [PAN58](https://infocenter.nordicsemi.com/index.jsp?topic=%2Ferrata_nRF52832_Rev2%2FERR%2FnRF52832%2FRev2%2Flatest%2Ferr_832.html).

```KConfig
### SPI SDHC drivers rely on multithreading
CONFIG_MULTITHREADING=y

CONFIG_MCUBOOT_SD_UPDATE=y

CONFIG_SPI=y
CONFIG_SPI_4=y
CONFIG_NRFX_SPI4=y
CONFIG_SPI_4_NRF_SPI=y
CONFIG_DISK_ACCESS_SPI_SDHC=y
```

## Preparing the update file
Preparing the update file is simple, just build your application as usual, sign it using the [imgtool](./imgtool.md) name it according to `CONFIG_SD_UPDATE_IMAGE_FILE_NAME` (*update.bin* by default) and place it to the `CONFIG_SD_UPDATE_DIRECTORY_NAME` (root by default) on the SD card.

**NOTE:** Only .bin files are currently supported, using the HEX format will result in a corrupted firmware.

## Update process description
Updating the firmware is done in the following steps:

 1. SD card is mounted under `CONFIG_SD_UPDATE_MOUNT_POINT`
 2. The `CONFIG_SD_UPDATE_DIRECTORY_NAME` directory is scanned for a file named `CONFIG_SD_UPDATE_IMAGE_FILE_NAME` if it is not found the process ends
 3. The file is open and its headers are loaded into memory
 4. Image SHA256 is validated against the hash stored in image TLVs
 5. Current firmware is backed up to `CONFIG_SD_UPDATE_BACKUP_FILE_NAME` file in the `CONFIG_SD_UPDATE_DIRECTORY_NAME` directory
 6. Slot 0 in flash is erased and rewritten with the new image; if a failure occurs the backup is flashed back
 7. After a successful update, the update file is deleted from the SD card
 8. Bootloader validates the written image, if the check fails, backup is flashed back
