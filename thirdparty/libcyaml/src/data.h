/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (C) 2017-2020 Michael Drake <tlsa@netsurf-browser.org>
 */

/**
 * \file
 * \brief CYAML functions for manipulating client data structures.
 */

#ifndef CYAML_DATA_H
#define CYAML_DATA_H

#include "cyaml/cyaml.h"
#include "util.h"

/**
 * Write a value of up to eight bytes to data_target.
 *
 * \param[in]  value       The value to write.
 * \param[in]  entry_size  The number of bytes of value to write.
 * \param[in]  data_tgt    The address to write to.
 * \return \ref CYAML_OK on success, or appropriate error code otherwise.
 */
static inline cyaml_err_t cyaml_data_write(
		uint64_t value,
		uint64_t entry_size,
		uint8_t *data_tgt)
{
	const uint8_t *value_bytes = (uint8_t *)&value;

	if (entry_size == 0 || entry_size > sizeof(value)) {
		return CYAML_ERR_INVALID_DATA_SIZE;
	}

	if (cyaml__host_is_big_endian()) {
		value_bytes += sizeof(value) - entry_size;
	}

	memcpy(data_tgt, value_bytes, entry_size);

	return CYAML_OK;
}

/**
 * Write a pointer to data.
 *
 * This is a wrapper for \ref cyaml_data_write that does a compile time
 * assertion on the pointer size, so it can never return a runtime error.
 *
 * \param[in]  ptr         The pointer address to write.
 * \param[in]  data_target The address to write to.
 */
static inline void cyaml_data_write_pointer(
		const void *ptr,
		uint8_t *data_target)
{
	/* Refuse to build on platforms where sizeof pointer would
	 * lead to \ref CYAML_ERR_INVALID_DATA_SIZE. */
	cyaml_static_assert(sizeof(char *) >  0);
	cyaml_static_assert(sizeof(char *) <= sizeof(uint64_t));

	CYAML_UNUSED(cyaml_data_write((uint64_t)ptr, sizeof(ptr), data_target));

	return;
}

/**
 * Read a value of up to eight bytes from data.
 *
 * \param[in]  entry_size  The number of bytes to read.
 * \param[in]  data        The address to read from.
 * \param[out] error_out   Returns the error code.  \ref CYAML_OK on success,
 *                         or appropriate error otherwise.
 * \return On success, returns the value read from data.
 *         On failure, returns 0.
 */
static inline uint64_t cyaml_data_read(
		uint64_t entry_size,
		const uint8_t *data,
		cyaml_err_t *error_out)
{
	uint64_t ret = 0;
	uint8_t *ret_bytes = (uint8_t *)&ret;

	if (entry_size == 0 || entry_size > sizeof(ret)) {
		*error_out = CYAML_ERR_INVALID_DATA_SIZE;
		return ret;
	}

	if (cyaml__host_is_big_endian()) {
		ret_bytes += sizeof(ret) - entry_size;
	}

	memcpy(ret_bytes, data, entry_size);

	*error_out = CYAML_OK;
	return ret;
}

/**
 * Read a pointer from data.
 *
 * This is a wrapper for \ref cyaml_data_read that does a compile time
 * assertion on the pointer size, so it can never return a runtime error.
 *
 * \param[in]  data        The address to read from.
 * \return Returns the value read from data.
 */
static inline uint8_t * cyaml_data_read_pointer(
		const uint8_t *data)
{
	cyaml_err_t err;

	/* Refuse to build on platforms where sizeof pointer would
	 * lead to \ref CYAML_ERR_INVALID_DATA_SIZE. */
	cyaml_static_assert(sizeof(char *) >  0);
	cyaml_static_assert(sizeof(char *) <= sizeof(uint64_t));

	return (void *)cyaml_data_read(sizeof(char *), data, &err);
}

#endif
