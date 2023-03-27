#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "exec_parser.h"
#include "../generic_array/generic_array.h"
#include <errno.h>

// defines for zero-filling
#define FILL_ALL 0
#define FILL_START 1
#define FILL_END 2

static so_exec_t *exec;
static int fd;

static int get_prot(unsigned int perm)
{
	int prot = 0;

	if (perm & PERM_R)
		prot |= PROT_READ;

	if (perm & PERM_W)
		prot |= PROT_WRITE;

	if (perm & PERM_X)
		prot |= PROT_EXEC;

	if (prot == 0)
		prot |= PROT_NONE;

	return prot;
}

static int get_page_start(uintptr_t addr)
{
	return addr - addr % getpagesize();
}

static int contained_in_segment(so_seg_t segment, uintptr_t addr)
{
	uintptr_t start = segment.vaddr;

	uintptr_t offset_to_final_page = getpagesize() - (segment.mem_size % getpagesize());
	uintptr_t end = segment.vaddr + segment.mem_size + offset_to_final_page;

	if (addr >= start && addr < end)
		return 1;

	return 0;
}

static int get_segment(uintptr_t addr, so_seg_t *segment, uintptr_t *page_addr)
{
	/* return 0 if addr corresponds the any segment, otherwise -1
	 *	save at the address indicated by segment the segment data
	 */

	for (int i = 0; i < exec->segments_no; i++) {
		so_seg_t current = exec->segments[i];

		if (contained_in_segment(current, (uintptr_t) addr)) {
			*segment = current;
			*page_addr = get_page_start(addr);
			return 0;
		}
	}

	return -1;
}

static int check_already_mapped(so_seg_t segment, uintptr_t page_addr)
{
	/*
	 *checks if page_addr was already mapped
	 *returns 0 if the page is not mapped; otherwise -1
	 */
	struct array *arr = (struct array *)segment.data;
	int len = arr->nr_elems;

	//printf("%d\n", len);

	for (int i = 0; i < len; i++) {
		uintptr_t *addr = get_ith_elem(arr, i);

		if (*addr == page_addr)
			return -1;
	}

	return 0;
}

static int within_file_size(so_seg_t segment, uintptr_t addr)
{
	if (addr >= segment.vaddr && addr < segment.vaddr + segment.file_size)
		return 1;

	return 0;
}

static int addr_in_last_page(so_seg_t segment, uintptr_t addr)
{
	uintptr_t addr_page = get_page_start(addr);
	uintptr_t last_page;

	if (segment.file_size == 0)
		last_page = get_page_start(segment.vaddr);
	else
		last_page = get_page_start(segment.vaddr + segment.file_size - 1);

	return addr_page == last_page;
}

static unsigned int get_offset(so_seg_t segment, uintptr_t addr)
{
	return segment.offset + (addr - segment.vaddr);
}

static size_t compute_mapped_length(so_seg_t segment, uintptr_t addr)
{
	size_t remaining = segment.vaddr + segment.file_size - addr;

	if (remaining > getpagesize())
		return getpagesize();
	else
		return remaining;
}

static void map_with_zeroes(so_seg_t segment, uintptr_t page_addr, int mode)
{
	unsigned int offset = get_offset(segment, page_addr);

	uintptr_t zero_start;
	size_t nr_zeros;
	size_t length;
	int type = MAP_PRIVATE;

	if (mode == FILL_ALL) {
		zero_start = page_addr;
		nr_zeros = getpagesize();
		length = getpagesize();
		type |= MAP_ANONYMOUS;

	} else if (mode == FILL_START) {
		zero_start = page_addr;
		nr_zeros = segment.mem_size % getpagesize();
		length = getpagesize();
		type |= MAP_ANONYMOUS;

	} else if (mode == FILL_END) {
		zero_start = page_addr + (segment.file_size % getpagesize());
		nr_zeros = getpagesize() - (segment.file_size % getpagesize());
		length = segment.file_size % getpagesize();

	} else {
		printf("undefined mode\n");
		exit(1);
	}

	char *p = mmap((void *) page_addr, length, PROT_READ | PROT_WRITE, type, fd, offset);

	if (p == MAP_FAILED) {
		printf("mapping failed\n");
		exit(1);
	}

	char *zeros = calloc(nr_zeros, sizeof(char));

	if (!zeros)
		exit(1);

	memcpy((void *) zero_start, zeros, nr_zeros);
	free(zeros);

	// setting the permission back
	int result = mprotect((void *) page_addr, getpagesize(), get_prot(segment.perm));

	if (result == -1) {
		printf("Failed setting permissions\n");
		exit(1);
	}
}

static int between_file_mem(so_seg_t segment, uintptr_t addr)
{
	uintptr_t file_size = segment.vaddr + segment.file_size;
	uintptr_t mem_size = segment.vaddr + segment.mem_size;

	return addr >= file_size && addr < mem_size;
}

static void segv_handler(int signum, siginfo_t *info, void *context)
{
	so_seg_t segment;
	uintptr_t page_addr = 0;
	uintptr_t fault_addr = (uintptr_t) info->si_addr;
	int result;

	memset(&segment, 0, sizeof(so_seg_t));

	// check if the address does not correspond to any segment
	result = get_segment(fault_addr, &segment, &page_addr);
	if (result == -1) {
		printf("Segmentation fault - not corresponding to any segment\n");
		exit(139);
	}

	// check if page fault occurs at an already mapped segment
	result = check_already_mapped(segment, page_addr);
	if (result == -1) {
		printf("Segmentation fault - already mapped\n");
		exit(139);
	}

	// page is not mapped; proceed to map it
	char *p;

	if (within_file_size(segment, fault_addr)) {
		unsigned int mem_size = segment.mem_size;
		unsigned int file_size = segment.file_size;
		unsigned int offset = get_offset(segment, page_addr);

		if (addr_in_last_page(segment, fault_addr) && mem_size != file_size) {
			map_with_zeroes(segment, page_addr, FILL_END);

		} else {
			size_t length = compute_mapped_length(segment, page_addr);

			p = mmap((void *) page_addr, length, get_prot(segment.perm), MAP_PRIVATE, fd, offset);
			if (p == MAP_FAILED) {
				printf("mapping failed\n");
				exit(1);
			}
		}

	} else if (between_file_mem(segment, fault_addr)) {

		if (get_page_start(fault_addr) == get_page_start(segment.vaddr + segment.file_size - 1))
			map_with_zeroes(segment, page_addr, FILL_END);
		else if (get_page_start(fault_addr) == get_page_start(segment.vaddr + segment.mem_size - 1))
			map_with_zeroes(segment, page_addr, FILL_START);
		else
			map_with_zeroes(segment, page_addr, FILL_ALL);
	}

	insert((struct array *)segment.data, &page_addr);
}

static int set_signal(void)
{
	struct sigaction action;
	int rc;

	memset(&action, 0, sizeof(struct sigaction));
	action.sa_flags = SA_SIGINFO;
	action.sa_sigaction = segv_handler;
	sigemptyset(&action.sa_mask);

	rc = sigaction(SIGSEGV, &action, NULL);

	return rc;
}

int so_init_loader(void)
{
	/* TODO: initialize on-demand loader */
	int rc = set_signal();

	if (rc == -1)
		return -1;

	return 0;
}

int so_execute(char *path, char *argv[])
{
	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	for (int i = 0; i < exec->segments_no; i++)
		exec->segments[i].data = alloc_array(sizeof(int));

	fd = open(path, O_RDWR, S_IRUSR | S_IWUSR | S_IXUSR);
	if (fd == -1)
		return -1;

	so_start_exec(exec, argv);

	return 0;
}
