/*
 * Copyright (C) 2017 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#ifndef _UAPI_LINUX_VSOC_SHM_H
#define _UAPI_LINUX_VSOC_SHM_H

/**
 * A permission is a token that signals that permits a receiver to read
 * and/or write a region of memory.
 *
 * An fd_scoped permission grants both read and write access, and can be
 * can be attached to a file description (see open(2)).
 * Ownership of the region can then be passed by passing a file descriptor
 * among processes.
 *
 * region_begin_offset and region_end_offset define the region of memory that
 * is controlled by the permission. owner_offset points to a word, also in
 * shared memory, that controls ownership of the region.
 *
 * ownership of the region expires when the associated file description is
 * released.
 *
 * At most one permission can be attached to each file description.
 *
 * This is useful when implementing HALs like gralloc that scope and pass
 * ownership of shared resources via file descriptors.
 *
 * The caller is responsibe for doing any fencing.
 *
 * The calling process will normally identify a currently free region of
 * memory. It will construct a proposed fd_scoped_permission structure:
 *
 *   region_begin_offset and region_end_offset describe the region being claimed
 *
 *   owner_offset points to the location in shared memory that indicates the
 *   owner of the region
 *
 *   before_owned_value gives the value that the caller found at owner_offset
 *   that indicated that the region was free.
 *
 *   after_owned_value is the value that will be stored at owner_offset when
 *   the description is released, destroying the permission.
 *
 *   owned_value is the value that will be stored in owner_offset iff the
 *   permission can be granted. It must be different than before_owned_value.
 *
 * Two fd_scoped_permission structures are compatible if they vary only by
 * their owned_value fields.
 *
 * The driver ensures that, for any group of simultaneous callers proposing
 * compatible fd_scoped_permissions, it will accept exactly one of the
 * propopsals. The other callers will get a failure with errno of EAGAIN.
 *
 * A process receiving a file descriptor can identify the region being
 * granted using the VSOC_GET_FD_SCOPED_PERMISSION ioctl.
 */
typedef struct {
	uint32_t region_begin_offset;
	uint32_t region_end_offset;
	uint32_t owner_offset;
	uint32_t before_owned_value;
	uint32_t after_owned_value;
	uint32_t owned_value;
} fd_scoped_permission;

static const uint32_t VSOC_NODE_FREE = 0;

// Describes a signal table in shared memory. Each non-zero entry in the
// table indicates that the receiver should signal the futex at the given
// offset. Offsets are relative to the region, not the shared memory window.
typedef struct {
	// log_2(Number of signal table entries)
	uint32_t num_nodes_lg2;
	// Offset to the first signal table entry relative to the start
	// of the region
	uint32_t offset;
	// Offset to an atomic uint32_t. Threads use this to get
	// semi-unique access to an entry in the table
	uint32_t node_alloc_hint_offset;
	// The doorbell number is implicitly assigned to the region number
} vsoc_signal_table_layout;

/**
 * Each HAL would talk to a single device region
 * Mulitple entities care about these regions:
 * * The ivshmem_server will populate the regions in shared memory
 * * The guest kernel will read the region, create minor device nodes, and
 *   allow interested parties to register for FUTEX_WAKE events in the region
 * * HALs will access via the minor device nodes published by the guest kernel
 * * Host side processes will access the region via the ivshmem_server:
 *   1. Pass name to ivshmem_server at a UNIX socket
 *   2. ivshmemserver will reply with 2 fds:
 *     * host->guest doorbell fd
 *     * guest->host doorbell fd
 *     * fd for the shared memory region
 *     * region offset
 *   3. Start a futex receiver thread on the doorbell fd pointed at the
 *      signal_nodes
 */
typedef struct {
	uint16_t current_version;
	uint16_t min_compatible_version;
	uint32_t region_begin_offset;
	uint32_t region_end_offset;
	uint32_t offset_of_region_data;
	vsoc_signal_table_layout guest_to_host_signal_table;
	vsoc_signal_table_layout host_to_guest_signal_table;
	/* Name of the device. Must always be terminated with a '\0', so
	 * the longest supported device name is 15 characters.
	 */
	char device_name[16];
} vsoc_device_region;

/*
 * The vsoc layout descriptor.
 * The first 4K should be reserved for the shm header and region descriptors.
 * The regions should be page aligned.
 */

typedef struct {
	uint16_t major_version;
	uint16_t minor_version;

	/* size of the shm. This may be redundant but nice to have */
	uint32_t size;

	/* number of shared memory regions */
	uint32_t region_count;

	/* The offset to the start of region descriptors */
	uint32_t vsoc_region_desc_offset;
} vsoc_shm_layout_descriptor;

/*
 * This specifies the current version that should be stored in
 * vsoc_shm_layout_descriptor.major_version and
 * vsoc_shm_layout_descriptor.minor_version.
 * It should be updated only if the vsoc_device_region and
 * vsoc_shm_layout_descriptor structures have changed.
 * Versioning within each region is transfered
 * via the min_compatible_version and current_version fields in
 * vsoc_device_region. The driver does not consult these fields: they are left
 * for the HALs and host processes and will change independently of the layout
 * version.
 */
#define CURRENT_VSOC_LAYOUT_MAJOR_VERSION 1
#define CURRENT_VSOC_LAYOUT_MINOR_VERSION 0

#define VSOC_CREATE_FD_SCOPED_PERMISSION _IOW(0xF5, 0, fd_scoped_permission)
#define VSOC_GET_FD_SCOPED_PERMISSION _IOR(0xF5, 1, fd_scoped_permission)

/* This is used to signal the host to scan the guest_to_host_signal_table
 * for new futexes to wake.
 */
#define VSOC_SEND_INTERRUPT_TO_HOST _IO(0xF5, 2)

/* When this returns the guest will scan host_to_guest_signal_table to
 * check for new futexes to wake.
 */
/* TODO(ghartman): Consider moving this to the bottom half */
#define VSOC_WAIT_FOR_INCOMING_INTERRUPT _IO(0xF5, 3)

/* Guest HALs will use this to retrieve the region description after
 * opening their device node.
 */
#define VSOC_DESCRIBE_REGION _IOR(0xF5, 4, vsoc_device_region)

#endif /* _UAPI_LINUX_BINDER_H */
