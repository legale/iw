/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
/*
 * Simple streaming JSON writer
 *
 * This takes care of the annoying bits of JSON syntax like the commas
 * after elements
 *
 * Authors:	Stephen Hemminger <stephen@networkplumber.org>
 */
#ifndef _JSON_WRITER_H_
#define _JSON_WRITER_H_
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
/* Opaque class structure */
typedef struct json_writer {
	FILE *out;					/* output file */
	unsigned int depth; 		/* nesting */
	bool pretty;				/* optional whitepace */
	char sep;					/* either nul or comma */
} json_writer_t;

/* Create a new JSON stream */
json_writer_t *jsonw_new(FILE *f);
/* End output to JSON stream */
void jsonw_destroy(json_writer_t **self_p);
/* Cause output to have pretty whitespace */
void jsonw_pretty(json_writer_t *self, bool on);
/* Add property name */
void jsonw_name(json_writer_t *self, const char *name);
/* Add value  */
__attribute__((format(printf, 2, 3))) void jsonw_printf(json_writer_t *self, const char *fmt, ...);
void jsonw_float_fmt(json_writer_t *self, const char *fmt, double num);

void jsonw_string(json_writer_t *self, const char *value);
void jsonw_num(json_writer_t *self, const char *value);
void jsonw_bool(json_writer_t *self, bool val);
void jsonw_null(json_writer_t *self);
void jsonw_float(json_writer_t *self, double num);
void jsonw_int(json_writer_t *self, int num);
void jsonw_uint(json_writer_t *self, unsigned int);
void jsonw_xint(json_writer_t *self, uint64_t num);
void jsonw_u8(json_writer_t *self, uint8_t num);
void jsonw_u16(json_writer_t *self, uint16_t num);
void jsonw_u32(json_writer_t *self, uint32_t num);
void jsonw_u64(json_writer_t *self, uint64_t num);
void jsonw_s8(json_writer_t *self, int8_t num);
void jsonw_s16(json_writer_t *self, int16_t num);
void jsonw_s32(json_writer_t *self, int32_t num);
void jsonw_s64(json_writer_t *self, int64_t num);

/* Useful Combinations of name and value */
void jsonw_string_field(json_writer_t *self, const char *prop, const char *val);
void jsonw_num_field(json_writer_t *self, const char *prop, const char *val);
void jsonw_bool_field(json_writer_t *self, const char *prop, bool value);
void jsonw_null_field(json_writer_t *self, const char *prop);
void jsonw_float_field(json_writer_t *self, const char *prop, double num);
void jsonw_int_field(json_writer_t *self, const char *prop, int num);
void jsonw_uint_field(json_writer_t *self, const char *prop, unsigned int num);
void jsonw_xint_field(json_writer_t *self, const char *prop, uint64_t num);
void jsonw_u8_field(json_writer_t *self, const char *prop, unsigned char num);
void jsonw_u16_field(json_writer_t *self, const char *prop, uint16_t num);
void jsonw_u32_field(json_writer_t *self, const char *prop, uint32_t num);
void jsonw_u64_field(json_writer_t *self, const char *prop, uint64_t num);
void jsonw_s8_field(json_writer_t *self, const char *prop, int8_t num);
void jsonw_s16_field(json_writer_t *self, const char *prop, int16_t num);
void jsonw_s32_field(json_writer_t *self, const char *prop, int32_t num);
void jsonw_s64_field(json_writer_t *self, const char *prop, int64_t num);
/* Collections */
void jsonw_start_object(json_writer_t *self);
void jsonw_end_object(json_writer_t *self);
void jsonw_start_array(json_writer_t *self);
void jsonw_end_array(json_writer_t *self);
/* Override default exception handling */
typedef void(jsonw_err_handler_fn)(const char *);
#endif /* _JSON_WRITER_H_ */
