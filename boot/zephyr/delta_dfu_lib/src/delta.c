/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "../include/delta.h"
#include "../../include/mcuboot_config/mcuboot_config.h"

const struct device *flash_device;
uint32_t patch_size; 
static uint8_t to_flash_buf[ERASE_PAGE_SIZE + MAX_WRITE_UNIT];
#ifdef MCUBOOT_WRITE_STATUS_DYNAMIC
off_t status_address = PRIMARY_OFFSET + PAGE_SIZE*4;
#else
off_t status_address = 0;
#endif
uint8_t opFlag = 0;	
/** variable used to indicate source image should be moved up how many pages before aplly */
uint8_t move_up_pages = 8;			
struct detools_apply_patch_t apply_patch;


struct
{
	int addr[IMAGE_ARRAY_SIZE];
	uint16_t size[IMAGE_ARRAY_SIZE];
	uint16_t count;
} image_position_adjust;

static void flush_patch_status(struct detools_apply_patch_t *self_p,struct flash_mem *flash);
/*
 *  INIT
 */

static int delta_init_flash_mem(struct flash_mem *flash)
{
	if (!flash) {
		return -DELTA_NO_FLASH_FOUND;
	}

	flash->from_current = PRIMARY_OFFSET + PAGE_SIZE * move_up_pages;
	flash->from_end = flash->from_current + PRIMARY_SIZE - PAGE_SIZE;

	flash->to_current = PRIMARY_OFFSET;
	flash->to_end = flash->to_current + PRIMARY_SIZE - PAGE_SIZE;

	flash->erased_addr = PRIMARY_OFFSET;

	flash->patch_current = SECONDARY_OFFSET + MCUBOOT_PAD_SIZE + HEADER_SIZE;
	flash->patch_end = flash->patch_current + SECONDARY_SIZE - HEADER_SIZE - MCUBOOT_PAD_SIZE - PAGE_SIZE;

	flash->write_size = 0;

	flash->backup_addr = 0;

	image_position_adjust.count = 0;

	// printf("\nInit: mcuboot_pad=0X%X from_current=0X%lX to_current=0X%lX patch_current=0X%lX STATUS_ADDRESS=0X%lX backup_addr=0x%lX\t write_size=%d\n",
	// 		MCUBOOT_PAD_SIZE,flash->from_current, flash->to_current, flash->patch_current,status_address,flash->backup_addr, flash->write_size);

	return DELTA_OK;
}

#ifdef DELTA_ENABLE_LOG
static void print_apply_patch_info(struct detools_apply_patch_t *apply_patch)
{
	printk("chunk.size=%d chunk.offset=%d patch_offset=%d to_offset=%d from_offset=%d chunk_size=%d reader:state=%d value=%d offset=%d issigned=%d\r"
			"heatshrink: window_sz2=%d lookahead_sz2=%d decoder:head_index=%d state=%d output_count=%d output_index=%d current_byte=%d bit_index=%d\r\n",
			apply_patch->chunk.size,apply_patch->chunk.offset,apply_patch->patch_offset,apply_patch->to_offset,apply_patch->from_offset,apply_patch->chunk_size,
			apply_patch->patch_reader.size.state,apply_patch->patch_reader.size.value,apply_patch->patch_reader.size.offset,apply_patch->patch_reader.size.is_signed,
			apply_patch->patch_reader.compression.heatshrink.window_sz2,apply_patch->patch_reader.compression.heatshrink.lookahead_sz2,
			apply_patch->patch_reader.compression.heatshrink.decoder.head_index,apply_patch->patch_reader.compression.heatshrink.decoder.state,
			apply_patch->patch_reader.compression.heatshrink.decoder.output_count,apply_patch->patch_reader.compression.heatshrink.decoder.output_index,
			apply_patch->patch_reader.compression.heatshrink.decoder.current_byte,apply_patch->patch_reader.compression.heatshrink.decoder.bit_index);
}
#endif


static int save_backup_image(void *arg_p)
{
	uint16_t i;
	uint32_t total_size = 0;
	uint8_t data[MAX_WRITE_UNIT + DATA_HEADER + 2];
	uint32_t addr;
	uint32_t magic = 0;
	uint32_t opFlag = DELTA_OP_TRAVERSE;

	struct flash_mem *flash = (struct flash_mem *)arg_p;	

	// printk("==== Write adjustment to Flash\r");
	//write image_position_adjust to Flash
	for (i = 0; i < image_position_adjust.count; i++)
	{
		total_size += (DATA_HEADER +image_position_adjust.size[i]);  //addr->4bytes len->2bytes				
	}
	printk("==== total_count=%d\t totat_size=%d\r\n", image_position_adjust.count,total_size);

#ifdef MCUBOOT_WRITE_STATUS_DYNAMIC
	uint32_t patch_len= patch_size + MCUBOOT_PAD_SIZE + HEADER_SIZE + PAGE_SIZE - (patch_size + MCUBOOT_PAD_SIZE + HEADER_SIZE)%PAGE_SIZE;
	if ((patch_len + total_size) > SECONDARY_SIZE - PAGE_SIZE) 
#else
	if((status_address + 4*PAGE_SIZE + total_size) > (SECONDARY_OFFSET + SECONDARY_SIZE - PAGE_SIZE))		//4 pages to save status pages + the last 1 page reserve
#endif
	{
		printk("## The delta file has a big variation!\r\n");
		return -DELTA_WRITING_ERROR;
	}

	for (i = 1; i <= (total_size/PAGE_SIZE + 1); i++)
	{
		flash_erase(flash_device, flash->patch_end - i * PAGE_SIZE, PAGE_SIZE);
	}			
	magic = addr = flash->patch_end - PAGE_SIZE * (i-1);

	for (i = 0; i < image_position_adjust.count; i++)
	{				
		total_size = (DATA_HEADER +image_position_adjust.size[i]);
		*(uint16_t *)&data[0] = image_position_adjust.size[i];
		*(uint32_t *)&data[DATA_LEN] = image_position_adjust.addr[i];

		if (flash_read(flash_device, image_position_adjust.addr[i], &data[DATA_HEADER], 
			image_position_adjust.size[i]))
		{
			printk("flash read err\r");
			return -DELTA_READING_SOURCE_ERROR;
		}

		if (flash_write(flash_device, addr, data, total_size)) {
			printk("flash write err\r");
			return -DELTA_WRITING_ERROR;
		}

		addr += total_size;
	}

	delta_init_flash_mem(flash);
	flash->backup_addr = magic;
	// printk("backup_addr = %p\r\n", flash->backup_addr);
	//apply_write_status(flash,STATUS_ADDRESS);
	apply_write_status(flash,status_address + PAGE_SIZE*3);

	flash_erase(flash_device, status_address, PAGE_SIZE*3);			//clean backup information

	if (flash_write(flash_device, SECONDARY_OFFSET + MCUBOOT_PAD_SIZE, &opFlag, sizeof(opFlag))) {
		return -DELTA_PATCH_HEADER_ERROR;
	}

	return DELTA_OK;		
}



static int traverse_flash_write(void *arg_p,
					const uint8_t *buf_p,
					size_t size)
{
	struct flash_mem *flash = (struct flash_mem *)arg_p;	
	if (!flash) {
		return -DELTA_CASTING_ERROR;
	}
#ifdef DELTA_ENABLE_LOG
	printk("to_flash write size 0x%x\r", size);
#endif
	flash->write_size += size;
	if (flash->write_size >= ERASE_PAGE_SIZE) {
	#ifdef MCUBOOT_WRITE_STATUS_DYNAMIC
		off_t save_address = PRIMARY_OFFSET + ((flash->to_current - PRIMARY_OFFSET)/(PAGE_SIZE*4) + 2) * (PAGE_SIZE*4);
		flash->erased_addr =  save_address +(PAGE_SIZE*4);
	#else
		flash->erased_addr =  flash->to_current + ERASE_PAGE_SIZE;
	#endif
#ifdef DELTA_ENABLE_LOG
		printk("==== erased_addr 0x%x\r", flash->erased_addr);
#endif
		flash->to_current += (off_t) ERASE_PAGE_SIZE;
		flash->write_size = flash->write_size - ERASE_PAGE_SIZE;
	}

	return DELTA_OK;		
}


static int apply_last_buffer(void *arg_p)
{
	struct flash_mem *flash = (struct flash_mem *)arg_p;
	uint32_t opFlag = DELTA_OP_APPLY;	
	int rc;

	// printk("===== Apply last Flash buffer\r\n");
	if (flash_erase(flash_device, flash->to_current, ERASE_PAGE_SIZE)) {
		return -DELTA_CLEARING_ERROR;
	}
	// printk("last Flash buffer:addr=0X%lx\t write_size=%d\r\n",flash->to_current,flash->write_size);
	rc = flash_write(flash_device, flash->to_current, to_flash_buf, flash->write_size);
	if (rc) 
	{
		printk("flash write err = %d\r\n", rc);
		return -DELTA_WRITING_ERROR;
	}

	flash->to_current += flash->write_size;
	flash->write_size = 0;	

	if (flash_write(flash_device, SECONDARY_OFFSET + MCUBOOT_PAD_SIZE, &opFlag, sizeof(opFlag))) {
		return -DELTA_PATCH_HEADER_ERROR;
	}			

	return DELTA_OK;		
}


static int write_new_image_to_flash(struct flash_mem *flash)
{
	if (flash_erase(flash_device, flash->to_current, ERASE_PAGE_SIZE)) {
		return -DELTA_CLEARING_ERROR;
	}
#ifdef MCUBOOT_WRITE_STATUS_DYNAMIC
	off_t save_address = PRIMARY_OFFSET + ((flash->to_current - PRIMARY_OFFSET)/(PAGE_SIZE*4) + 2) * (PAGE_SIZE*4);
	flash->erased_addr =  save_address +(PAGE_SIZE*4);
#else
	flash->erased_addr =  flash->to_current + ERASE_PAGE_SIZE;
#endif

	if (flash_write(flash_device, flash->to_current, to_flash_buf, ERASE_PAGE_SIZE)) {
		printk("flash write2 err\r");
		return -DELTA_WRITING_ERROR;
	}
	flash->to_current += (off_t) ERASE_PAGE_SIZE;
	if (flash->to_current >= flash->to_end) {
		return -DELTA_SLOT1_OUT_OF_MEMORY;
	}

	flash->write_size = flash->write_size - ERASE_PAGE_SIZE;			
	memcpy(to_flash_buf, &to_flash_buf[ERASE_PAGE_SIZE], flash->write_size);

	memcpy(flash->rest_buf,&to_flash_buf[ERASE_PAGE_SIZE], flash->write_size);
	//apply_write_status(flash,STATUS_ADDRESS);	
	apply_write_status(flash,status_address + PAGE_SIZE*3);
#ifdef DELTA_ENABLE_LOG
	printf("\nErase: from_current=%p to_current=%p patch_current=%p backup_addr=0x%X\t write_size=%d\n",
			flash->from_current, flash->to_current, flash->patch_current, flash->backup_addr, flash->write_size);
	//print_apply_patch_info(&apply_patch);
#endif	
	return DELTA_OK;
}

static int apply_flash_write(void *arg_p,
					const uint8_t *buf_p,
					size_t size)
{
	struct flash_mem *flash = (struct flash_mem *)arg_p;	
	if (!flash) {
		return -DELTA_CASTING_ERROR;
	}

	if (size > PAGE_SIZE)
	{
		printf("error size\r");
		return -DELTA_WRITING_ERROR;
	}


	memcpy(to_flash_buf + flash->write_size, buf_p, size);  //put the TO content to a temp buffer first
	flash->write_size += size;

	if (flash->write_size >= ERASE_PAGE_SIZE) {
	#ifdef DELTA_ENABLE_LOG
		printk("Start to_flash write size 0x%x to %p at %" PRIu32 "\r\n\n",flash->write_size,flash->to_current + flash->write_size,k_uptime_get_32());
	#endif
		apply_backup_write_status(flash);
		flush_patch_status(&apply_patch,flash);	
		write_new_image_to_flash(flash);
	#ifdef DELTA_ENABLE_LOG
		printk("End to_flash write to %p at %" PRIu32 "\r\n\n",flash->to_current + flash->write_size,k_uptime_get_32());
	#endif
	}

	return DELTA_OK;
}


int write_last_buffer(void *arg_p)
{
	struct flash_mem *flash = (struct flash_mem *)arg_p;	
	if (!flash) {
		return -DELTA_CASTING_ERROR;
	}

	if(0 == flash->backup_addr)
	{
		return save_backup_image(arg_p);
	}
	else
	{
		return apply_last_buffer(arg_p);
	}
}


static int traverse_flash_from_read(void *arg_p,
					uint8_t *buf_p,
					size_t size)
{
	struct flash_mem *flash;
	static int fatal_err = 0;

	flash = (struct flash_mem *)arg_p;
#ifdef DELTA_ENABLE_LOG
	printk("from_flash read size: 0x%x off: 0x%x\r", size, flash->from_current);
#endif
	if (!flash) {
		return -DELTA_CASTING_ERROR;
	}
	if (size <= 0) {
		return -DELTA_INVALID_BUF_SIZE;
	}

	if (fatal_err)
	{
		return -DELTA_CASTING_ERROR;
	}

	if (flash->from_current < flash->erased_addr)
	{
	#ifdef DELTA_ENABLE_LOG
		printk("=== adjust pos %d\r", image_position_adjust.count);
	#endif
		image_position_adjust.addr[image_position_adjust.count] = flash->from_current;
		image_position_adjust.size[image_position_adjust.count] = size;
		image_position_adjust.count++;
		if (image_position_adjust.count > IMAGE_ARRAY_SIZE)
		{
			fatal_err = -DELTA_WRITING_ERROR;
			return -DELTA_WRITING_ERROR;				
		}	
	}

	flash->from_current += (off_t) size;
	if (flash->from_current >= flash->from_end) {
		return -DELTA_READING_SOURCE_ERROR;
	}

	return DELTA_OK;
}

static int apply_flash_from_read(void *arg_p,
					uint8_t *buf_p,
					size_t size)
{
	struct flash_mem *flash;
	static int fatal_err = 0;

	flash = (struct flash_mem *)arg_p;

	if (!flash) {
		return -DELTA_CASTING_ERROR;
	}
	if (size <= 0) {
		return -DELTA_INVALID_BUF_SIZE;
	}

	if (fatal_err)
	{
		return -DELTA_CASTING_ERROR;
	}

	if (flash->from_current < flash->erased_addr)
	{		
		//uint32_t magic[2];
		uint8_t data[DATA_HEADER];

		/** read the saved size and address which saved in the backup flash*/
		if (flash_read(flash_device, flash->backup_addr, data, sizeof(data))) {
			fatal_err = -DELTA_READING_SOURCE_ERROR;
			return -DELTA_READING_SOURCE_ERROR;
		}
		flash->backup_addr += DATA_HEADER;

		if ((*(uint16_t*)&data[0]) != size || (*(uint32_t*)&data[DATA_LEN]) != flash->from_current)
		{
			printf("address or size mismatch!\r");
			fatal_err = -DELTA_READING_SOURCE_ERROR;
			return -DELTA_READING_SOURCE_ERROR;
		}
	#ifdef DELTA_ENABLE_LOG	
		printk("from_backup read size: 0x%x offset: 0x%x\r", size, flash->backup_addr);
	#endif
		if (flash_read(flash_device, flash->backup_addr, buf_p, size)) {
			fatal_err = -DELTA_READING_SOURCE_ERROR;
			return -DELTA_READING_SOURCE_ERROR;
		}
		flash->backup_addr += size;	
	}
	else
	{
	#ifdef DELTA_ENABLE_LOG
		printk("from_flash read size: 0x%x offset: 0x%x\r", size, flash->from_current);
	#endif
		if (flash_read(flash_device, flash->from_current, buf_p, size)) {
			return -DELTA_READING_SOURCE_ERROR;
		}
	}

	flash->from_current += (off_t) size;
	if (flash->from_current >= flash->from_end) {
		return -DELTA_READING_SOURCE_ERROR;
	}

	return DELTA_OK;
}


static int delta_flash_patch_read(void *arg_p,
					uint8_t *buf_p,
					size_t size)
{
	struct flash_mem *flash;

	flash = (struct flash_mem *)arg_p;
#ifdef DELTA_ENABLE_LOG
	printk("patch_flash read size 0x%x from %p\r\n\n", size,flash->patch_current);
#endif
	if (!flash) {
		return -DELTA_CASTING_ERROR;
	}
	if (size <= 0) {
		return -DELTA_INVALID_BUF_SIZE;
	}

	if (flash_read(flash_device, flash->patch_current, buf_p, size)) {
		return -DELTA_READING_PATCH_ERROR;
	}
	
	return DELTA_OK;
}

int increase_patch_offset(void *arg_p,off_t size)
{
	struct flash_mem *flash = (struct flash_mem *)arg_p;
	flash->patch_current += (off_t) size;
	if (flash->patch_current >= flash->patch_end) {
		return -DELTA_READING_PATCH_ERROR;
	}
	return DELTA_OK;
}

static int delta_flash_seek(void *arg_p, int offset)
{
	struct flash_mem *flash;

	flash = (struct flash_mem *)arg_p;
#ifdef DELTA_ENABLE_LOG
	printk("from_flash seek offset %d\r", offset);
#endif
	if (!flash) {
		return -DELTA_CASTING_ERROR;
	}

	flash->from_current += offset;
	if (flash->from_current >= flash->from_end) {
		return -DELTA_SEEKING_ERROR;
	}

	return DELTA_OK;
}




static int delta_traverse_init(struct flash_mem *flash,uint32_t patch_size,struct detools_apply_patch_t *apply_patch)
{
	int ret;
	ret = delta_init_flash_mem(flash);
	ret += detools_apply_patch_init(apply_patch,
                                   traverse_flash_from_read,
                                   delta_flash_seek,
                                   patch_size,
                                   traverse_flash_write,
                                   flash);

	
	if (ret) {
		return ret;
	}

	return DELTA_OK;
}

static void flush_patch_status(struct detools_apply_patch_t *self_p,struct flash_mem *flash)
{
	flash->state = self_p->state;
	flash->patch_offset = self_p->patch_offset;
	flash->to_offset = self_p->to_offset;
	flash->from_offset = self_p->from_offset;
	flash->chunk_size = self_p->chunk_size;
	flash->chunk_offset = self_p->chunk.offset;
	flash->last_chunk_size =  self_p->chunk.size;
	flash->size.is_signed = self_p->patch_reader.size.is_signed;
	flash->size.offset = self_p->patch_reader.size.offset;
	flash->size.state = self_p->patch_reader.size.state;
	flash->size.value = self_p->patch_reader.size.value;
	flash->compression.heatshrink = self_p->patch_reader.compression.heatshrink;
}

static int init_patch_header(struct detools_apply_patch_t *self_p,
                    const uint8_t *patch_p)
{
    int res;
	struct flash_mem *flash = (struct flash_mem *)(self_p->arg_p);
    //self_p->patch_offset += 0x200;
    self_p->chunk.buf_p = patch_p;
    self_p->chunk.size = 0x200;
    self_p->chunk.offset = 0;
	res = restore_apply_patch_header(self_p);

    self_p->state = flash->state;
	self_p->patch_offset =  flash->patch_offset;
	self_p->to_offset = flash->to_offset;
	self_p->from_offset = flash->from_offset;
	self_p->chunk_size = flash->chunk_size;
	self_p->patch_reader.size.state = flash->size.state;
	self_p->patch_reader.size.offset = flash->size.offset;
	self_p->patch_reader.size.value = flash->size.value;
	self_p->patch_reader.size.is_signed = flash->size.is_signed;
	self_p->patch_reader.compression.heatshrink = flash->compression.heatshrink;
	self_p->chunk.size = flash->last_chunk_size;
	self_p->chunk.offset = flash->chunk_offset;
	if (flash->write_size >= ERASE_PAGE_SIZE)
	{
		res = write_new_image_to_flash(flash);
	}

#ifdef DELTA_ENABLE_LOG
	printk("Init patch header: reader:state=%d value=%d offset=%d issigned=%d heatshrink: window_sz2=%d lookahead_sz2=%d\r"
			 "decoder:head_index=%d state=%d output_count=%d output_index=%d current_byte=%d bit_index=%d\r\n",
			self_p->patch_reader.size.state,self_p->patch_reader.size.value,self_p->patch_reader.size.offset,self_p->patch_reader.size.is_signed,	
			self_p->patch_reader.compression.heatshrink.window_sz2,self_p->patch_reader.compression.heatshrink.lookahead_sz2,
			self_p->patch_reader.compression.heatshrink.decoder.head_index,self_p->patch_reader.compression.heatshrink.decoder.state,
			self_p->patch_reader.compression.heatshrink.decoder.output_count,self_p->patch_reader.compression.heatshrink.decoder.output_index,
			self_p->patch_reader.compression.heatshrink.decoder.current_byte,self_p->patch_reader.compression.heatshrink.decoder.bit_index);
#endif
    if (res < 0) {
        self_p->state = detools_apply_patch_state_failed_t;
    }
    return (res);
}

int delta_apply_init(struct flash_mem *flash,uint32_t patch_size,struct detools_apply_patch_t *apply_patch)
{
	int ret = -1;
	uint8_t chunk[512];
	off_t start_addr = SECONDARY_OFFSET + MCUBOOT_PAD_SIZE + HEADER_SIZE;

	ret = detools_apply_patch_init(apply_patch,
                                   apply_flash_from_read,
                                   delta_flash_seek,
                                   patch_size,
                                   apply_flash_write,
                                   flash);
	if(flash->patch_current >= start_addr)
	{
		//printk("Init apply reader!!!!!!!!!!!!!!!!!!!!!!!!!!!!\r\n\r\n");
		if (flash_read(flash_device, start_addr, chunk, sizeof(chunk))) {
			return -DELTA_READING_PATCH_ERROR;
		}
		ret = init_patch_header(apply_patch,chunk);
	}
	
	return ret;
}


int traverse_delta_file(struct flash_mem *flash, struct detools_apply_patch_t *apply_patch)
{
	int ret;
	
	ret = delta_traverse_init(flash,patch_size,apply_patch);
	if (ret) {
		return ret;
	}
#ifndef DELTA_ENABLE_LOG
	printf("\nTraverse: mcuboot_pad=0X%X\t from_current=0X%lX\t size=0x%X\t to_current=0X%lX\t size=0x%X\t patch_current=0X%lX\t patch_end=0X%lX\t backup_addr=0X%lX\n",
		MCUBOOT_PAD_SIZE,flash->from_current,PRIMARY_SIZE,flash->to_current,SECONDARY_SIZE,flash->patch_current,flash->patch_end, flash->backup_addr);
#endif
	ret = apply_patch_process(apply_patch, delta_flash_patch_read, patch_size, 0, flash);
	
	return ret;
}


int delta_check_and_apply(struct flash_mem *flash, struct detools_apply_patch_t *apply_patch)
{
	int ret;

	size_t patch_offset = flash->patch_current - (SECONDARY_OFFSET + MCUBOOT_PAD_SIZE + HEADER_SIZE);
	ret = apply_patch_process(apply_patch, delta_flash_patch_read, patch_size, patch_offset, flash);

	return ret;
}

int delta_read_patch_header(uint8_t *hash_buf, uint32_t *size, uint8_t *op)
{
	uint32_t new_patch = 0x5057454E;  	// ASCII for "NEWP" signaling new patch
	struct patch_header
	{
		uint32_t flag;
		uint32_t length;
		uint8_t hash_buf[32];
	} header_st;


	if (flash_read(flash_device, SECONDARY_OFFSET + MCUBOOT_PAD_SIZE, &header_st, sizeof(header_st))) {
		return -DELTA_PATCH_HEADER_ERROR;
	}
#ifdef DELTA_ENABLE_LOG
	printf("flag=%0X\t length=%0X\r\n", header_st.flag, header_st.length);
	for(int i = 0; i < sizeof(header_st.hash_buf); i++)
	{
		printf("%02X ",header_st.hash_buf[i]);
	}
#endif

	if(new_patch == header_st.flag)
	{
		if(0 == memcmp(header_st.hash_buf, hash_buf, sizeof(header_st.hash_buf)))
		{
			*op = DELTA_OP_TRAVERSE;

			uint32_t opFlag = DELTA_OP_START;
			if (flash_write(flash_device, SECONDARY_OFFSET + MCUBOOT_PAD_SIZE, &opFlag, sizeof(opFlag))) {
				return -DELTA_PATCH_HEADER_ERROR;
			}

			printf("source hash is matched, now start delta upgrade!!!\r\n");
		}
		else
		{
			printk("\r\nsource file hash didn't match, exit upgrade!!!\r\n");
			return -DELTA_SOURCE_HASH_ERROR;
		}
	}
	else if(header_st.flag == DELTA_OP_START)
	{
		*op = DELTA_OP_TRAVERSE;
	}
	else if(header_st.flag == DELTA_OP_TRAVERSE)
	{
		*op = DELTA_OP_APPLY;
	}
	else if(header_st.flag == DELTA_OP_APPLY)
	{
		*op = DELTA_OP_NONE;
	}

	*size = header_st.length;
#ifndef MCUBOOT_WRITE_STATUS_DYNAMIC
	status_address = SECONDARY_OFFSET + MCUBOOT_PAD_SIZE + HEADER_SIZE + *size + PAGE_SIZE - (SECONDARY_OFFSET + MCUBOOT_PAD_SIZE + HEADER_SIZE + *size)%PAGE_SIZE;
#endif
	return DELTA_OK;
}

#ifdef MCUBOOT_WRITE_STATUS_DYNAMIC
off_t get_status_address(void)
{
	uint32_t flag = 0;
	off_t save_addr = PRIMARY_OFFSET + PRIMARY_SIZE - PAGE_SIZE;

	while(save_addr >= PRIMARY_OFFSET +  PAGE_SIZE*4)
	{
		flash_read(flash_device, save_addr, &flag, sizeof(flag));
		if(flag == SAVE_FLAG)
		{
			flag = 0;
			save_addr -= PAGE_SIZE;
			flash_read(flash_device, save_addr, &flag, sizeof(flag));
			if(flag == SAVE_FLAG)
			{
				save_addr -= PAGE_SIZE*2;
			}
			else
			{
				save_addr -= PAGE_SIZE;
			}
			break;
		}
		save_addr -= PAGE_SIZE;
	}
	
	if((save_addr < PRIMARY_OFFSET +  PAGE_SIZE*4) || (save_addr == PRIMARY_OFFSET +  PAGE_SIZE*5))
	{
		save_addr = PRIMARY_OFFSET +  PAGE_SIZE*4;
	}
	// printf("Get save_addr: %p\r\n",save_addr);
	return save_addr;
}
#endif

int apply_backup_write_status(struct flash_mem *flash_mem)
{
	struct bak_flash_mem bak_flash;
	uint8_t rest_count = flash_mem->write_size - ERASE_PAGE_SIZE;

	flash_mem->save_flag = SAVE_FLAG;			//This flag is used to indicate which page has been used by the power off protection
	bak_flash.flash = *flash_mem;
	memcpy(bak_flash.buffer, to_flash_buf, ERASE_PAGE_SIZE);		
	memcpy(bak_flash.flash.rest_buf, &to_flash_buf[ERASE_PAGE_SIZE], rest_count);
	flush_patch_status(&apply_patch,&(bak_flash.flash));
#ifdef MCUBOOT_WRITE_STATUS_DYNAMIC
	status_address = PRIMARY_OFFSET + ((flash_mem->to_current - PRIMARY_OFFSET)/(PAGE_SIZE*4) + 1) * (PAGE_SIZE*4);
#endif
	flash_erase(flash_device, status_address, PAGE_SIZE*3);
	if (flash_write(flash_device, status_address, &bak_flash, sizeof(struct bak_flash_mem))) {
		printk("magic2 write err\r");
		return -DELTA_WRITING_ERROR;
	}
	      
#ifdef DELTA_ENABLE_LOG
	printf("Save backup: from_current=%p to_current=%p patch_current=%p status_address=%p\r\n",
			flash_mem->from_current,flash_mem->to_current,flash_mem->patch_current,status_address);
#endif
	return DELTA_OK;
}


int apply_write_status(struct flash_mem *flash,off_t addr)
{
	flash->save_flag = SAVE_FLAG;
	flash_erase(flash_device, addr, PAGE_SIZE);
	if (flash_write(flash_device, addr, flash, sizeof(struct flash_mem))) {
		printk("magic1 write err\r");
		return -DELTA_WRITING_ERROR;
	}
	return DELTA_OK;
}


int apply_read_status(struct flash_mem *flash)
{	
	struct bak_flash_mem bak_flash;
	// printf("READ: STATUS_ADDRESS = 0X%lX\r\n",status_address);
	
	if (flash_read(flash_device, status_address, &bak_flash, sizeof(struct bak_flash_mem))) 
	{
			printk("magic1 read err\r");
			return -DELTA_WRITING_ERROR;
	}
#ifdef MCUBOOT_WRITE_STATUS_DYNAMIC
	// /** backup has been erased and only write a SAVE_FLAG, so we have to read the last status saved after new image been written */
	if((bak_flash.flash.save_flag == SAVE_FLAG) && (bak_flash.flash.backup_addr == 0xffffffff))
	{
		status_address -= PAGE_SIZE*4;
		// printf("FIXED STATUS_ADDRESS = %p\r\n",status_address);
	}
#endif
	if (flash_read(flash_device, status_address+PAGE_SIZE*3, flash, sizeof(struct flash_mem))) {
		printk("magic1 read err\r");
		return -DELTA_WRITING_ERROR;
	}

	/** last save failed, we should read backup data to restore the apply status */
	if((flash->patch_current == 0xffffffff)	||
	#ifdef MCUBOOT_WRITE_STATUS_DYNAMIC
		(flash->save_flag != SAVE_FLAG) ||
	#endif
		((bak_flash.flash.from_current!=flash->from_current || bak_flash.flash.backup_addr!=flash->backup_addr) && (bak_flash.flash.to_current == flash->to_current)))
	{
		// printf("Last save failed, we should read backup data to restore the apply status!!!!!!\r\n");
		
		*flash = bak_flash.flash;	
	#ifdef MCUBOOT_WRITE_STATUS_DYNAMIC
		if(flash->write_size >= ERASE_PAGE_SIZE)
		{
			memcpy(to_flash_buf,bak_flash.buffer,ERASE_PAGE_SIZE);
			memcpy(&to_flash_buf[ERASE_PAGE_SIZE],bak_flash.flash.rest_buf, MAX_WRITE_UNIT);
		}	
		else if(flash->write_size <= MAX_WRITE_UNIT)	/** backup has been erased, so we have to read the last status saved after new image been written */
		{
			memcpy(to_flash_buf, flash->rest_buf, flash->write_size);
		}
	#else
		memcpy(to_flash_buf,bak_flash.buffer,ERASE_PAGE_SIZE);
		memcpy(&to_flash_buf[ERASE_PAGE_SIZE],bak_flash.flash.rest_buf, MAX_WRITE_UNIT);
	#endif	
	}
	else
	{
		if(flash->write_size <= MAX_WRITE_UNIT)
		{
			memcpy(to_flash_buf, flash->rest_buf, flash->write_size);
		}
	}
	
#ifdef DELTA_ENABLE_LOG
	printf("\nRead status: from_current=0X%lX to_current=0X%lX patch_current=0X%lX backup_addr=0X%lX write_size=%d\r" 
		"patch_offset=%d to_offset=%d from_offset=%d chunk_size=%d last_chunk_size=%d chunk.offset=%d apply_state=%d\r"
		"reader:state=%d value=%d offset=%d issigned=%d\r"
		"decoder:head_index=%d state=%d output_count=%d output_index=%d current_byte=%d bit_index=%d\r\n\n",
	flash->from_current,flash->to_current,flash->patch_current,flash->backup_addr,flash->write_size,
	flash->patch_offset,flash->to_offset,flash->from_offset,flash->chunk_size,flash->last_chunk_size,flash->chunk_offset,flash->state,
	flash->size.state,flash->size.value,flash->size.offset,flash->size.is_signed,
	flash->compression.heatshrink.decoder.head_index,flash->compression.heatshrink.decoder.state,
	flash->compression.heatshrink.decoder.output_count,flash->compression.heatshrink.decoder.output_index,
	flash->compression.heatshrink.decoder.current_byte,flash->compression.heatshrink.decoder.bit_index);
#endif

	if((flash->last_chunk_size > 0) && (flash->chunk_offset >= flash->last_chunk_size))
	{
		flash->patch_current += 0x200;
		flash->last_chunk_size = 0;
		flash->chunk_offset = 0;
	}

	return DELTA_OK;
}

const char *delta_error_as_string(int error)
{
	if (error < 28) {
		return detools_error_as_string(error);
	}

	if (error < 0) {
		error *= -1;
	}

	switch (error) {
	case DELTA_SLOT1_OUT_OF_MEMORY:
		return "Slot 1 out of memory.";
	case DELTA_READING_PATCH_ERROR:
		return "Error reading patch.";
	case DELTA_READING_SOURCE_ERROR:
		return "Error reading source image.";
	case DELTA_WRITING_ERROR:
		return "Error writing to slot 1.";
	case DELTA_SEEKING_ERROR:
		return "Seek error.";
	case DELTA_CASTING_ERROR:
		return "Error casting to flash_mem.";
	case DELTA_INVALID_BUF_SIZE:
		return "Read/write buffer less or equal to 0.";
	case DELTA_CLEARING_ERROR:
		return "Could not clear slot 1.";
	case DELTA_NO_FLASH_FOUND:
		return "No flash found.";
	case DELTA_PATCH_HEADER_ERROR:
		return "Error reading patch header.";
	default:
		return "Unknown error.";
	}
}
