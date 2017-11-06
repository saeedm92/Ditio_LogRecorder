/*
 * Log recorder 
 * File: log_recorder.c
 *
 * Copyright (c) 2017 University of California, Irvine, CA, USA
 * All rights reserved.
 *
 * Authors: Saeed Mirzamohammadi <saeed@uci.edu>
 * Ardalan Amiri Sani   <arrdalan@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>. 
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <asm/uaccess.h>
#include <linux/delay.h>
#include <asm/io.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <asm/cacheflush.h> /* clflush_cache_range() */
#include <asm/tlbflush.h> /* flush_tlb_all() */
#include <asm/io.h>
#include <asm/pgtable.h> /* flush_tlb_all() */
#include <linux/time.h>
#include "entry_fast.h"
#include <linux/unistd.h>
#include <linux/vmalloc.h>
//#include <linux/prints.h>

/* ioctl */
#define LOGME_ON		5
#define LOGME_OFF		1
#define LOGME_GET_KEY		124
#define LOGME_SYNC_TIME		125

#define LOG_TYPE_W		0
#define LOG_TYPE_RW		1

#define PER_CPU_LOG_NAME	0
#define SELECTIVE_LOGGING	1
#define SERVER_PORT		1234

struct logme_log_ioctl {
	unsigned long pfn;
	int log_type;
	int num_pages;
};

#define OPENED		1
#define CLOSED		0
#define DEVICE_NAME "logMe"

static struct class *logMe_class = NULL;
static struct cdev logMe_cdev;
DEFINE_SPINLOCK(log_lock);
static int device_is_open;
static unsigned int major;

/* Shared memory */
extern uint8_t shared_buf[10000];

static time_t server_time;

typedef struct {
        struct work_struct my_work;
        void *buf;
	int bufn; //which buffer number this work is on
} my_work_t;

static struct workqueue_struct *my_wq;

/* Max entries in xen local buffer */
#define MAX_LOG_SIZE                    8144

/* Size of local xen buffer */
#define ENTRY_POS(log_ptr, offset)      log_ptr + offset

#define START_LOG_OPCODE                1
#define STOP_LOG_OPCODE                 2
#define PHONE_ON_OPCODE                 3
#define PHONE_OFF_OPCODE                4
#define COUNTER_OPCODE                  5
#define TIME_DIFF_OPCODE                6
#define TIME_CHANGE_OPCODE              7
#define REG_WRITE_OPCODE                8
#define REG_READ_OPCODE                 9

#define START_LOG_SIZE                  4114
#define STOP_LOG_SIZE                   17
#define PHONE_ON_SIZE                   9
#define PHONE_OFF_SIZE                  9
#define COUNTER_SIZE                    5
#define TIME_DIFF_SIZE                  9
#define TIME_CHANGE_SIZE                9
#define REG_WRITE_SIZE                  18
#define REG_READ_SIZE                   18

/* Local memory buffer */
static DEFINE_PER_CPU(void *, local_buf); /* per-cpu buffer */
static DEFINE_PER_CPU(void **, local_buf_all); /* per-cpu buffer array */
static DEFINE_PER_CPU(void *, lbmap); /* per-cpu buffer array */
static DEFINE_PER_CPU(void *, next_bufn); /* Next buffer number */

#define LBUF_ALL_SIZE 512

#if PER_CPU_LOG_NAME
	static DEFINE_PER_CPU(int, log_file_num); /* we have a per-cpu buffer and hence a per-cpu log_size */
#endif /* PER_CPU_LOG_NAME */

/* Counter for number of log entries */
static DEFINE_PER_CPU(int, log_size); /* we have a per-cpu buffer and hence a per-cpu log_size */
static DEFINE_MUTEX(log_mutex);
#define ENCRYPT 0
#define Big_SOS 1
static uint64_t ktime_get_real_ns(void)
{
	return ktime_to_ns(ktime_get_real());
}

static uint64_t get_time(void)
{
	uint64_t time;
	time = ktime_get_real_ns();
	
	return time;
}
#if PER_CPU_LOG_NAME
static uint64_t get_file_ext(void)
{
	uint64_t ret;
	ret = *this_cpu_ptr(&log_file_num);
	*this_cpu_ptr(&log_file_num) = ret + 1;
	return ret;
}

#else
uint64_t file_ext_counter = 0;

static uint64_t get_file_ext(void)
{
	uint64_t ret;

	ret = file_ext_counter;
	file_ext_counter++;
	return ret;
}
#endif

int log_flag = 0;
static void __write_logs_to_file(void *buf, int bufn)
{
	mm_segment_t old_fs;
	struct file* filp = NULL;
	char filename[256];
	int* temp;

	mutex_lock(&log_mutex);
#if PER_CPU_LOG_NAME
	snprintf(filename, 256, "/data/local/log_%d_%lu", smp_processor_id(), (unsigned long) get_file_ext());
#else
	snprintf(filename, 256, "/data/local/log%lu", (unsigned long) get_file_ext());
#endif
	filp = filp_open(filename, O_RDWR | O_CREAT, 0644);
	old_fs = get_fs();
	set_fs(get_ds());

#if ENCRYPT
        memcpy_toio(shared_buf, buf, 8192);
	sign_buf();
	filp->f_op->write(filp, shared_buf, 8192, &filp->f_pos);
#else
	filp->f_op->write(filp, buf, 8192, &filp->f_pos);
#endif
	set_fs(old_fs);
	filp_close(filp, NULL);
	temp = ( (int*) *this_cpu_ptr(&lbmap) + bufn );
	*((int*)temp) = 0;

	mutex_unlock(&log_mutex);
}

static void write_logs_to_file(struct work_struct *work)
{
	my_work_t *my_work = (my_work_t*) work; 
	__write_logs_to_file(my_work->buf, my_work->bufn);
	kfree(my_work);
}

void *get_log_ptr(int entry_size)
{
	int cpu_log_size = *this_cpu_ptr(&log_size);
	void *ptr;
	my_work_t *work;
	int i;
	void** temp;
	int t;

        if (cpu_log_size + entry_size >= MAX_LOG_SIZE) {

		/* Queue some work (item 1) */
                work = (my_work_t *) kmalloc(sizeof(my_work_t), GFP_KERNEL);
                if (!work) {
			BUG();
		}
		INIT_WORK((struct work_struct *) work, write_logs_to_file);

	        work->buf = *this_cpu_ptr(&local_buf);
		work->bufn = *((int*) *this_cpu_ptr(&next_bufn));
        	queue_work(my_wq, (struct work_struct *) work);
		i = 0;
		while(1) {
			if (i==LBUF_ALL_SIZE) {
				i = 0;
			}
			t = *((int*) *this_cpu_ptr(&lbmap) + i);
			if (t != 1) {
				temp = *this_cpu_ptr(&local_buf_all);
				ptr = temp[i];
				*((int*) *this_cpu_ptr(&lbmap) + i) = 1;
				*((int*) *this_cpu_ptr(&next_bufn)) = i; //the next buffer we will use
				break;
			}
			else {
				i++;
			}
		}
		if (!ptr) {
			BUG();
		}
		*this_cpu_ptr(&local_buf) = ptr;
		*this_cpu_ptr(&log_size) = entry_size;
        } else {
		ptr = *this_cpu_ptr(&local_buf) + cpu_log_size;
		cpu_log_size += entry_size;
		*this_cpu_ptr(&log_size) = cpu_log_size;
	}
		
	return ptr;
}

int log_start_log(uint64_t pfn, uint8_t log_type, void *addr)
{
        uint64_t time;
	int offset = 0;
	void *log_ptr = NULL;

	spin_lock(&log_lock);
	log_ptr = get_log_ptr(START_LOG_SIZE);

        /* Dump data into local buffer */
        memset(ENTRY_POS(log_ptr, offset), START_LOG_OPCODE, sizeof(uint8_t));
        offset++;
        memcpy(ENTRY_POS(log_ptr, offset), &pfn, sizeof(uint64_t));
        offset += 8;
        time = get_time();
        memcpy(ENTRY_POS(log_ptr, offset), &time, sizeof(uint64_t));
        offset += 8;
        memcpy(ENTRY_POS(log_ptr, offset), &log_type, sizeof(uint8_t));
        offset++;
	memcpy(ENTRY_POS(log_ptr, offset), addr, 4096); /* PAGE_SIZE */
        memcpy_fromio(ENTRY_POS(log_ptr, offset), addr, 4096); /* PAGE_SIZE */
        offset += 4096;

	spin_unlock(&log_lock);

        return 0;
}

int log_stop_log(uint64_t pfn)
{
        uint64_t time;
	int offset = 0;
	void *log_ptr = NULL;

	spin_lock(&log_lock);
	log_ptr = get_log_ptr(STOP_LOG_SIZE);

        /* Dump data into local buffer */
        memset(ENTRY_POS(log_ptr, offset), STOP_LOG_OPCODE, sizeof(uint8_t));
        offset++;
        memcpy(ENTRY_POS(log_ptr, offset), &pfn, sizeof(uint64_t));
        offset += 8;
        time = get_time();
        memcpy(ENTRY_POS(log_ptr, offset), &time, sizeof(uint64_t));
        offset += 8;

	spin_unlock(&log_lock);

        return 0;
}
int log_phone_on(void)
{
        uint64_t time;
	int offset = 0;
	void *log_ptr = NULL;

	spin_lock(&log_lock);
        
	log_ptr = get_log_ptr(PHONE_ON_SIZE);

        /* Dump data into local buffer */
        memset(ENTRY_POS(log_ptr, offset), PHONE_ON_OPCODE, sizeof(uint8_t));
        offset++;
        time = get_time();
        memcpy(ENTRY_POS(log_ptr, offset), &time, sizeof(uint64_t));
        offset += 8;

	spin_unlock(&log_lock);

        return 0;
}
int log_phone_off(void)
{
        uint64_t time;
	int offset = 0;
	void *log_ptr = NULL;

	spin_lock(&log_lock);
        
	log_ptr = get_log_ptr(PHONE_OFF_SIZE);

        /* Dump data into local buffer */
        memset(ENTRY_POS(log_ptr, offset), PHONE_OFF_OPCODE, sizeof(uint8_t));
        offset++;
        time = get_time();
        memcpy(ENTRY_POS(log_ptr, offset), &time, sizeof(uint64_t));
        offset += 8;

	spin_unlock(&log_lock);

        return 0;
}
int log_counter(uint32_t counter)
{
	int offset = 0;
	void *log_ptr = NULL;

	spin_lock(&log_lock);
	log_ptr = get_log_ptr(COUNTER_SIZE);

        /* Dump data into local buffer */
        memset(ENTRY_POS(log_ptr, offset), COUNTER_OPCODE, sizeof(uint8_t));
        offset++;
        memcpy(ENTRY_POS(log_ptr, offset), &counter, sizeof(uint32_t));
        offset += 4;

	spin_unlock(&log_lock);

        return 0;
}
int log_time_diff(uint64_t time)
{
	int offset = 0;
	void *log_ptr = NULL;

	spin_lock(&log_lock);
	log_ptr = get_log_ptr(TIME_DIFF_SIZE);

        /* Dump data into local buffer */
        memset(ENTRY_POS(log_ptr, offset), TIME_DIFF_OPCODE, sizeof(uint8_t));
        offset++;
        memcpy(ENTRY_POS(log_ptr, offset), &time, sizeof(uint64_t));
        offset += 8;

	spin_unlock(&log_lock);

        return 0;
}

int log_time_change(uint64_t time)
{
        //int ret = 0;
	int offset = 0;
	void *log_ptr = NULL;

	spin_lock(&log_lock); 
	log_ptr = get_log_ptr(TIME_CHANGE_SIZE);

        /* Dump data into local buffer */
        memset(ENTRY_POS(log_ptr, offset), TIME_CHANGE_OPCODE, sizeof(uint8_t));
        offset++;
        memcpy(ENTRY_POS(log_ptr, offset), &time, sizeof(uint64_t));
        offset += 8;

	spin_unlock(&log_lock);

        return 0;
}
int log_reg_write(uint64_t addr, uint8_t val)
{
        uint64_t time;
	int offset = 0;
	void *log_ptr = NULL;

	spin_lock(&log_lock);
	log_ptr = get_log_ptr(REG_WRITE_SIZE);

        /* Dump data into local buffer */
        memset(ENTRY_POS(log_ptr, offset), REG_WRITE_OPCODE, sizeof(uint8_t));
        offset++;
        memcpy(ENTRY_POS(log_ptr, offset), &addr, sizeof(uint64_t));
        offset += 8;
        memcpy(ENTRY_POS(log_ptr, offset), &val, sizeof(uint8_t));
        offset++;
        time = get_time();
        memcpy(ENTRY_POS(log_ptr, offset), &time, sizeof(uint64_t));
        offset += 8;

	spin_unlock(&log_lock);
        return 0;
}
int log_reg_read(uint64_t addr, uint8_t val)
{
        uint64_t time;
	int offset = 0;
	void *log_ptr = NULL;
	
	spin_lock(&log_lock);
	log_ptr = get_log_ptr(REG_READ_SIZE);

        /* Dump data into local buffer */
        memset(ENTRY_POS(log_ptr, offset), REG_READ_OPCODE, sizeof(uint8_t));
        offset++;
        memcpy(ENTRY_POS(log_ptr, offset), &addr, sizeof(uint64_t));
        offset += 8;
        memcpy(ENTRY_POS(log_ptr, offset), &val, sizeof(uint8_t));
        offset++;
        time = get_time();
        memcpy(ENTRY_POS(log_ptr, offset), &time, sizeof(uint64_t));
        offset += 8;

	spin_unlock(&log_lock);

        return 0;
}

static int logMe_open(struct inode *inode, struct file *file)
{
	void **temp;
	void *temp2;
	void *ptr;
	int i, j;
	if (device_is_open)
		return -EBUSY;
	printk("After device busy\n");
	/* Allocate two pages */
	for (i = 0; i < NR_CPUS; i++) {
		if (cpu_possible(i)) {
			per_cpu(lbmap, i) = vzalloc(LBUF_ALL_SIZE * sizeof(int));
			per_cpu(next_bufn, i) = vzalloc(1 * sizeof(int));

			temp = vmalloc(sizeof(void *) * LBUF_ALL_SIZE);
			for (j = 0; j < LBUF_ALL_SIZE; j++) {
				temp[j] = vzalloc(8192);
			}
			per_cpu(local_buf_all, i) = temp;
			ptr = temp[0];
			temp2 = per_cpu(lbmap, i);
			*((int*)temp2) = 1;	
			
			if (!ptr) {
				printk("ptr null\n");
				return -ENOMEM;
			}
			per_cpu(local_buf, i) = ptr;

			per_cpu(log_size, i) = 0;
			#if PER_CPU_LOG_NAME
				per_cpu(log_file_num, i) = 0;
			#endif
		}
	} 
	printk("Device opened\n");
	device_is_open = OPENED;
	return 0;
}

static int logMe_release(struct inode *inode, struct file *file)
{
	void *ptr, *bufn;
	int size, i;

	for (i = 0; i < NR_CPUS; i++) {
		if (cpu_possible(i)) {
			size = per_cpu(log_size, i);
			ptr = per_cpu(local_buf, i);
			bufn = per_cpu(next_bufn, i);
			if (size) {
				 __write_logs_to_file(ptr, *((int*)bufn));
			} else {
				if (ptr)
					vfree(ptr);
			}
		}
	}
	
	device_is_open = CLOSED;
	return 0;
}

static ssize_t logMe_read(struct file *fname, char *buf,
			  size_t size, loff_t *off)
{
	return 0;
}

static ssize_t logMe_write(struct file *fname, const char *buf, 
			   size_t size, loff_t *off)
{
	return 0;
}

#ifdef CONFIG_ARM
PTE_BIT_FUNC(exprotect, |= L_PTE_XN);
PTE_BIT_FUNC(mkpresent, |= L_PTE_PRESENT);
PTE_BIT_FUNC(mknotpresent, &= ~L_PTE_PRESENT); // use for invalidation (to signal NO permissions)
#define dfv_pte_present pte_present

enum LOGME_PAGE_STATE {
	LOGME_MODIFIED = 0,
	LOGME_SHARED = 1,
	LOGME_INVALID = 2
};

pte_t *logme_get_pte(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;

	if (!mm)
		mm = &init_mm;

	pgd = pgd_offset(mm, addr);

	do {
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;

		if (pgd_none(*pgd))
			break;

		pud = pud_offset(pgd, addr);

		if (pud_none(*pud))
			break;

		pmd = pmd_offset(pud, addr);

		if (pmd_none(*pmd))
			break;

		/* We must not map this if we have highmem enabled */
		if (PageHighMem(pfn_to_page(pmd_val(*pmd) >> PAGE_SHIFT)))
			break;

		pte = pte_offset_map(pmd, addr);
		return pte;
	} while(0);

	return NULL;
}
#endif /* CONFIG_ARM */

int logme_change_page_state(unsigned long local_addr, int state)
{
	pte_t *ptep;
	ptep = logme_get_pte(NULL, local_addr);
	if (!ptep)
		goto error_no_pte;

	switch (state) {
		
	case LOGME_SHARED:
		/* grant read-only permissions to the PTE, aka SHARED state */
		set_pte_ext(ptep, pte_mkpresent(*ptep), 0);
		set_pte_ext(ptep, pte_wrprotect(*ptep), 0);
		break;
		
	case LOGME_MODIFIED:
		set_pte_ext(ptep, pte_mkpresent(*ptep), 0);
		set_pte_ext(ptep, pte_mkwrite(*ptep), 0);
		break;		
		
	case LOGME_INVALID:
	      set_pte_ext(ptep, pte_mknotpresent(*ptep), 0);
	      set_pte_ext(ptep, pte_wrprotect(*ptep), 0);
		break;
		
	default:
		break;
	}

	flush_tlb_all();
	pte_unmap(ptep);
	return 0;
	
error_no_pte:
	return -EFAULT;
}
EXPORT_SYMBOL(logme_change_page_state);

uint8_t test_val = 0;
void __iomem *kern_ptr;
unsigned long logme_addr;
unsigned long logme_paddr;
unsigned long logme_size;
void __iomem *alternative_ptr;

int tda998x_simple_audio_mute(bool on);

static long logMe_ioctl(struct file *fname, unsigned int cmd, unsigned long arg)
{
	struct logme_log_ioctl* data;
	time_t time;
	unsigned char temp_buf[524];
	int i;
	uint64_t time_m;
	
	if (!kern_ptr)
		BUG();
	switch (cmd)
	{

	case LOGME_ON:

		data = kmalloc( sizeof(struct logme_log_ioctl), GFP_KERNEL);
        	data->pfn = 0xFDA04;	//camera
		
		//data->pfn = 0xFE12F;	//mic
	        data->log_type = LOG_TYPE_RW;
		data->num_pages = 1;
		for (i = 0; i < data->num_pages; i++) {
			if (data->log_type == LOG_TYPE_RW)
				logme_change_page_state((unsigned long)kern_ptr + (i * PAGE_SIZE), LOGME_INVALID);
			else /* LOG_TYPE_W */
				logme_change_page_state((unsigned long)kern_ptr + (i * PAGE_SIZE), LOGME_SHARED);
		}		
		logme_addr = (unsigned long) kern_ptr;
		logme_paddr = data->pfn << PAGE_SHIFT;
		logme_size = data->num_pages * PAGE_SIZE;
		alternative_ptr = (void __iomem *) 0xF9717000; //camera

		for (i = 0; i < data->num_pages; i++) {
			log_start_log((uint64_t) data->pfn + i, (uint8_t) data->log_type,
						alternative_ptr + (i * PAGE_SIZE));
		}
		kfree(data);
		return 0;

	case LOGME_OFF:
		data = kmalloc( sizeof(struct logme_log_ioctl), GFP_KERNEL);
                data->pfn = 0xFDA04;
		data->log_type = LOG_TYPE_RW;
		data->num_pages = 1;
		for (i = 0; i < data->num_pages; i++)
			logme_change_page_state((unsigned long)kern_ptr + (i * PAGE_SIZE), LOGME_MODIFIED);
		log_stop_log((uint64_t) data->pfn);
		logme_addr = 0;
		logme_paddr = 0;
		logme_size = 0;
		return 0;

	case LOGME_GET_KEY:
		time_m = get_time();
		memcpy(shared_buf, &time_m, 8);

		initialize_connection();
		encrypt_and_sign();
		memcpy_fromio(temp_buf, shared_buf, 524);
		copy_to_user( (void *)arg, temp_buf, 524);
		return 0;
	
	case LOGME_SYNC_TIME:
		copy_from_user(shared_buf, (void *) arg, 52);
		decrypt_time();
		memcpy(&time, shared_buf, sizeof(time_t));
		server_time = time;
		return 0;
	default:
		return -EINVAL;
			
	}

	return 0;
}

static struct file_operations logMe_fops = {
	.read = logMe_read,
	.write = logMe_write,
	.open = logMe_open,
	.release = logMe_release,
	.unlocked_ioctl = logMe_ioctl
};

static bool is_logme_address(unsigned long addr, unsigned long *paddr)
{
	if ((addr < logme_addr) || (addr >= (logme_addr + logme_size)))
		return false;

	*paddr = logme_paddr + (addr & ~PAGE_MASK);
	return true;
}

union reg_val {
	uint64_t reg_val_64;
	struct reg_val_8_struct {
		uint8_t reg1;
		uint8_t reg2;
		uint8_t reg3;
		uint8_t reg4;
		uint8_t reg5;
		uint8_t reg6;
		uint8_t reg7;
		uint8_t reg8;
	} reg_val_8;
};

#define FSR_WRITE		(1 << 11)
int __logme_kernel_fault(struct mm_struct *mm, unsigned long addr, unsigned int fsr,
		  	 struct pt_regs *regs)
{
	unsigned long paddr;
	unsigned long dst_addr;
	char pc_1_val, pc_2_val, pc_3_val;
	int size_rw, size_rw1, size_rw2;
	int src_reg_index;
	int reg_val_b1, reg_val_b2, reg_val_b3, reg_val_b4;

	if (!is_logme_address(addr, &paddr)) {
		return -ENOMEM;
	}

	if ((addr >= 0xf9017000) & (addr < 0xf9018000)) {
		goto cont;
	}
	else {
		return -ENOMEM;
	}
cont:
	dst_addr = addr + 0x700000;
	pc_2_val = *((char *) (regs->ARM_pc + 2));
	pc_3_val = *((char *) (regs->ARM_pc + 3));
	size_rw1 = (pc_2_val & 0x40) >> 6; // Byte or word
	size_rw2 = (pc_3_val & 0x04) >> 2; // Single data transfer or half word
	if (!size_rw2) {
		size_rw = 1; //half word
	}
	else if  (size_rw1) {
		size_rw = 0;
	}
	else {
		size_rw = 2;
	}

	pc_1_val = *((char *) regs->ARM_pc + 1);
	src_reg_index = pc_1_val & 0xf0; 
	src_reg_index = src_reg_index >> 4;
	if (!(fsr & FSR_WRITE)) {
		switch (size_rw) {
		case 0:
			regs->uregs[src_reg_index] = (uint8_t) readb(dst_addr);
			break;
		case 1:
			regs->uregs[src_reg_index] = (uint16_t) readw(dst_addr);
			break;
		case 2:
			regs->uregs[src_reg_index] = (uint32_t) readl(dst_addr);
			break;
		}
	}
	reg_val_b1 = (regs->uregs[src_reg_index]) & 0xFF;
	reg_val_b2 = ((regs->uregs[src_reg_index]) & 0xFF00) >> 8;
	reg_val_b3 = ((regs->uregs[src_reg_index]) & 0xFF0000) >> 16;
	reg_val_b4 = ((regs->uregs[src_reg_index]) & 0xFF000000) >> 24;

#if SELECTIVE_LOGGING
	if (fsr & FSR_WRITE) {
            switch (size_rw) {
            case 0:
		writeb(regs->uregs[src_reg_index], dst_addr);
		if( (addr & 0xff)==0x30 )
			log_reg_write((uint64_t) addr, (uint8_t) (reg_val_b1));
                break;
            case 1:
                writew(regs->uregs[src_reg_index], dst_addr);
		if( (addr & 0xff)==0x30 ) {
			log_reg_write((uint64_t) addr, (uint8_t) (reg_val_b1));
			log_reg_write((uint64_t) (addr + 1), (uint8_t) (reg_val_b2));
		}
                break;
            case 2:
                writel(regs->uregs[src_reg_index], dst_addr);
		if( (addr & 0xff)==0x30 ) {
	                log_reg_write((uint64_t) addr, (uint8_t) (reg_val_b1));
			log_reg_write((uint64_t) (addr + 1), (uint8_t) (reg_val_b2));
	                log_reg_write((uint64_t) (addr + 2), (uint8_t) (reg_val_b3));
			log_reg_write((uint64_t) (addr + 3), (uint8_t) (reg_val_b4));
		}
		break;
           default:
                break;
            }
	} else {
            switch (size_rw) {
            case 0:
		if( (addr & 0xff)==0x30 ) {
			log_reg_read((uint64_t) addr, (uint8_t) (reg_val_b1));
		}
                break;
            case 1:
       		if( (addr & 0xff)==0x30 ) {
	                log_reg_read((uint64_t) addr, (uint8_t) (reg_val_b1));
			log_reg_read((uint64_t) (addr + 1), (uint8_t) (reg_val_b2));
		}
                break;
            case 2:
		if( (addr & 0xff)==0x30 ) {
	                log_reg_read((uint64_t) addr, (uint8_t) (reg_val_b1));
			log_reg_read((uint64_t) (addr + 1), (uint8_t) (reg_val_b2));
                	log_reg_read((uint64_t) (addr + 2), (uint8_t) (reg_val_b3));
			log_reg_read((uint64_t) (addr + 3), (uint8_t) (reg_val_b4));
	    	}
                break;
            default:
                break;
            }
        }
#else
	if (fsr & FSR_WRITE) {
            switch (size_rw) {
            case 0:
		writeb(regs->uregs[src_reg_index], dst_addr);
		log_reg_write((uint64_t) addr, (uint8_t) (reg_val_b1));
                break;
            case 1:
                writew(regs->uregs[src_reg_index], dst_addr); 
		log_reg_write((uint64_t) addr, (uint8_t) (reg_val_b1));
		log_reg_write((uint64_t) (addr + 1), (uint8_t) (reg_val_b2));
                break;
            case 2:
                writel(regs->uregs[src_reg_index], dst_addr);
                log_reg_write((uint64_t) addr, (uint8_t) (reg_val_b1));
		log_reg_write((uint64_t) (addr + 1), (uint8_t) (reg_val_b2));
                log_reg_write((uint64_t) (addr + 2), (uint8_t) (reg_val_b3));
		log_reg_write((uint64_t) (addr + 3), (uint8_t) (reg_val_b4));
		break;
           default:
                break;
            }
	} else {
            switch (size_rw) {
            case 0:
		log_reg_read((uint64_t) addr, (uint8_t) (reg_val_b1));
                break;
            case 1:
                log_reg_read((uint64_t) addr, (uint8_t) (reg_val_b1));
		log_reg_read((uint64_t) (addr + 1), (uint8_t) (reg_val_b2));
                break;
            case 2:
                log_reg_read((uint64_t) addr, (uint8_t) (reg_val_b1));
		log_reg_read((uint64_t) (addr + 1), (uint8_t) (reg_val_b2));
                log_reg_read((uint64_t) (addr + 2), (uint8_t) (reg_val_b3));
		log_reg_read((uint64_t) (addr + 3), (uint8_t) (reg_val_b4));
                break;
            default:
                break;
            }
        }
#endif

	regs->ARM_pc += 4;
	return 0;
}

extern int (*logme_kernel_fault) (struct mm_struct *mm, unsigned long addr, unsigned int fsr,
 		                  struct pt_regs *regs);

static int __init logMe_init(void)
{
	int err = 0, ret;
	dev_t dev = 0;
	dev_t devno;
	struct device *device = NULL;

	void **temp;
	void *temp2;
	void *ptr;
	int i, j;
	
	printk("saeed init logme\n");
	err = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
	if (err < 0) {
		return err;
	}
	major = MAJOR(dev);
	
	/* Create device */
	logMe_class = class_create(THIS_MODULE, DEVICE_NAME);
	if (IS_ERR(logMe_class)) {
		err = PTR_ERR(logMe_class);
		goto failed;
	}

	cdev_init(&logMe_cdev, &logMe_fops);
	logMe_cdev.owner = THIS_MODULE;

	/* We only need one device, so hard code minor number */
	devno = MKDEV(major, 0);
	err = cdev_add(&logMe_cdev, devno, 1);
	if (err)
	{
		class_destroy(logMe_class);
		goto failed;
	}

	device = device_create(logMe_class, NULL, devno, NULL, DEVICE_NAME);
	if (IS_ERR(device)) {
		err = PTR_ERR(device);
		class_destroy(logMe_class);
		cdev_del(&logMe_cdev);
		goto failed;
	}

	device_is_open = CLOSED;
	
	my_wq = alloc_workqueue("my_queue", WQ_HIGHPRI | WQ_CPU_INTENSIVE, 128);
        if (!my_wq)
		goto failed;

	logme_kernel_fault = __logme_kernel_fault;	

	kern_ptr = (void __iomem *) 0xF9017000; //camera
	printk("kern mod device opened\n");
	return 0;

failed:
	printk("error\n");
	unregister_chrdev_region(MKDEV(major, 0), 1);
	return err;
}

static void __exit logMe_exit(void)
{
	cdev_del(&logMe_cdev);
	device_destroy(logMe_class, MKDEV(major, 0));
	class_destroy(logMe_class);
	unregister_chrdev_region(MKDEV(major, 0), 1);
}

module_init(logMe_init);
module_exit(logMe_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Saeed Mirzamohammadi <saeed@uci.edu>");

