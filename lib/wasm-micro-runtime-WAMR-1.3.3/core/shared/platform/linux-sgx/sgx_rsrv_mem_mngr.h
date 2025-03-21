/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * This file is copied from
 * https://github.com/intel/linux-sgx/blob/4589daddd58bec7367a6a9de3fe301e6de17671a/common/inc/internal/sgx_rsrv_mem_mngr.h
 * The reason we copied here is that the official SGX SDK release has
 * not included this header file yet.
 */

#pragma once

#ifndef _SGX_RSRV_MEM_MNGR_H_
#define _SGX_RSRV_MEM_MNGR_H_

#include "stdint.h"
#include "sgx_error.h"

#define SGX_PROT_READ 0x1  /* page can be read */
#define SGX_PROT_WRITE 0x2 /* page can be written */
#define SGX_PROT_EXEC 0x4  /* page can be executed */
#define SGX_PROT_NONE 0x0  /* page can not be accessed */

#ifdef __cplusplus
extern "C" {
#endif

/* Allocate a range of EPC memory from the reserved memory area with RW
 * permission
 *
 * Parameters:
 * Inputs: length [in]: Size of region to be allocated in bytes. Page aligned.
 * Return: Starting address of the new allocated memory area on success;
 * otherwise NULL
 */
void *
sgx_alloc_rsrv_mem(size_t length);

/* Free a range of EPC memory from the reserved memory area
 *
 * Parameters:
 * Inputs: addr[in]: Starting address of region to be freed. Page aligned.
 *         length[in]: The length of the memory to be freed in bytes.
 *                     Page aligned.
 * Return: 0 on success; otherwise -1
 */
int
sgx_free_rsrv_mem(void *addr, size_t length);

/* Modify the access permissions of the pages in the reserved memory area.
 *
 * Parameters:
 * Inputs: addr[in]: Starting address of region which needs to change access
 *                   permission. Page aligned.
 *         length[in]: The length of the memory to be manipulated in bytes.
 *                     Page aligned.
 *         prot[in]: The target memory protection.
 * Return: sgx_status_t - SGX_SUCCESS or failure as defined in sgx_error.h
 */
sgx_status_t
sgx_tprotect_rsrv_mem(void *addr, size_t len, int prot);

#ifdef __cplusplus
}
#endif

#endif
