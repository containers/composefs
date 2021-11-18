/*
 * composefs
 *
 * Copyright (C) 2000 Linus Torvalds.
 *               2000 Transmeta Corp.
 * Copyright (C) 2021 Giuseppe Scrivano
 *
 * This file is released under the GPL.
 */

#include <linux/fs.h>

struct vfsmount *cfs_mount(void *raw_data);
