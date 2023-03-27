# executable-loader

The task is to implement a shared/dynamic library as a loader for ELF executable files on Linux. The loader will load the executable file into memory page by page, using a demand paging mechanism - a page will be loaded only when it is needed. For simplicity, the loader will only run static executables - those that are not linked with shared/dynamic libraries.

To run an executable file, the loader will perform the following steps:

Initialize its internal structures.
Parse the binary file - you have an ELF file parser available in the project skeleton.

Run the first instruction of the executable (entry point).

During execution, a page fault will be generated for each access to an unmapped page in memory.

Detect each access to an unmapped page, and check which segment of the executable it belongs to.

If it is not found in a segment, it means it is an invalid memory access - the default page fault handler is run.

If the page fault is generated in an already mapped page, then an unauthorized memory access is attempted (the segment does not have the necessary permissions) - the default page fault handler is run again.

If the page is found in a segment, and it has not yet been mapped, then it is mapped to the appropriate address, with the permissions of that segment.

The mmap function (Linux) will be used to allocate virtual memory within the process.

The page must be mapped to the address indicated within the segment.
