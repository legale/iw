#ifndef _JSON_PRINT_H_
#define _JSON_PRINT_H_
#include "json_writer.h"

extern int iw_json;

json_writer_t *iw_get_json_writer(void);

void iw_obj_new(int json, bool is_pretty);
void iw_obj_del(void);
void iw_obj_openf(const char *fmt, ...);
void iw_obj_close(void);
void iw_arr_openf(const char *fmt, ...);
void iw_arr_close(void);

#define _PRINT_FUNC(type_name, type)         \
	void json_print_##type_name(const char *key, type value)
_PRINT_FUNC(u8, uint8_t);
_PRINT_FUNC(u16, uint16_t);
_PRINT_FUNC(u32, uint32_t);
_PRINT_FUNC(u64, uint64_t);
_PRINT_FUNC(s8, int8_t);
_PRINT_FUNC(s16, int16_t);
_PRINT_FUNC(s32, int32_t);
_PRINT_FUNC(s64, int64_t);
_PRINT_FUNC(int, int);
_PRINT_FUNC(float, double);
_PRINT_FUNC(bool, bool);
#undef _PRINT_FUNC

void iw_print_stringf(const char *key, const char *fmt, ...);
void iw_print_numf(const char *key, const char *fmt, ...);
void iw_printf(const char *key, const char *fmt, ...);

#endif /* _JSON_PRINT_H_ */
