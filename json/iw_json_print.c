/*
* iw_json_print.c 
* print text or json output, based on json_writer and json_print
* License: BSD-2-CLAUSE
*/
#include "iw_json_print.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

int iw_json = 0;

static json_writer_t *_jw;

static void iw_print_intend() {
    for (unsigned i = 0; i < _jw->depth; i++) {
        printf("\t");
    }
}

static const char *iw_format_key(const char *key, size_t keysize) {
    //buffer
    static char buf[1024];
    size_t bufsize = sizeof(buf);

    //check keysize
    assert(keysize < bufsize);

    // copy key to buffer
    memcpy(buf, key, keysize);
    buf[keysize] = '\0';

    // replace comma with space
    for (size_t i = 0; i < keysize; i++) {
        if (buf[i] == ',') {
            buf[i] = ' ';
        }
    }

    // replace space with _ and convert uppercase letters to lowercase
    size_t write_index = 0;
    int prev_is_space = 0;
    for (size_t i = 0; i < keysize; i++) {
        char lower_char = tolower(buf[i]); // convert to lowercase
        if (!isspace(lower_char)) {
            buf[write_index++] = lower_char;
            prev_is_space = 0;
        } else {
            if (!prev_is_space) {
                buf[write_index++] = '_';
            }
            prev_is_space = 1;
        }
    }

    buf[write_index] = '\0';

    return buf;
}

void iw_obj_new(int json, bool is_pretty) {
	iw_json = json;
	_jw = jsonw_new(stdout);
	if (!_jw) {
		perror("json object");
		exit(1);
	}
	jsonw_pretty(_jw, is_pretty);
	if(iw_json) jsonw_start_object(_jw);
}
void iw_obj_del(void) {
	if (_jw) {
		if(iw_json) jsonw_end_object(_jw);
		jsonw_destroy(&_jw);
	}
}

json_writer_t *iw_get_json_writer(void) {
	return _jw;
}
void iw_obj_openf(const char *fmt, ...) {
	char buf[1024];
	va_list args;
	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	if(!iw_json){
		iw_print_intend();
		printf("%s:\n", (*buf != '\0') ? buf : "object");
		++_jw->depth;
	} else {
		if(*buf != '\0') jsonw_name(_jw, iw_format_key(buf, strlen(buf) + 1));
		jsonw_start_object(_jw);
	}

	va_end(args);
}

void iw_obj_close(void) {
	if(iw_json){
		jsonw_end_object(_jw);
	}else{
		assert(_jw->depth > 0);
		--_jw->depth;
	}
}

void iw_arr_openf(const char *fmt, ...) {
	char buf[1024];
	va_list args;
	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	// if not empty
	assert(buf);
	if(!iw_json){
		iw_print_intend();
		printf("%s:\n", (*buf != '\0') ? buf : "array");
		++_jw->depth;
	} else {
		if(*buf != '\0') jsonw_name(_jw, iw_format_key(buf, strlen(buf) + 1));
		jsonw_start_array(_jw);
	}

	va_end(args);
}

void iw_arr_close() {
	if(iw_json){
		jsonw_end_array(_jw);
	}else{
		assert(_jw->depth > 0);
		--_jw->depth;
	}
}

#define _PRINT_FUNC(type_name, type)                       \
void json_print_##type_name(const char *key, type value) { \
		if (!key)                                          \
			jsonw_##type_name(_jw, value);                 \
		else                                               \
			jsonw_##type_name##_field(_jw, key, value);    \
}

_PRINT_FUNC(u8, uint8_t);
_PRINT_FUNC(u16, uint16_t);
_PRINT_FUNC(u32, uint32_t);
_PRINT_FUNC(u64, uint64_t);
_PRINT_FUNC(s8, int8_t);
_PRINT_FUNC(s16, int16_t);
_PRINT_FUNC(s32, int32_t);
_PRINT_FUNC(s64, int64_t);
_PRINT_FUNC(int, int);
_PRINT_FUNC(uint, unsigned int);
_PRINT_FUNC(float, double);
_PRINT_FUNC(bool, bool);
#undef _PRINT_FUNC

void iw_print_stringf(const char *key, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);

	char buf[1024];
	vsnprintf(buf, sizeof(buf), fmt, args);
	if (key) {
		jsonw_string_field(_jw, iw_format_key(key, strlen(key) +1), buf);
	} else {
		jsonw_string(_jw, buf);
	}

	va_end(args);
}

void iw_print_numf(const char *key, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);

	char buffer[1024];
	vsnprintf(buffer, sizeof(buffer), fmt, args);
	if (key) {
		jsonw_num_field(_jw, iw_format_key(key, strlen(key) +1), buffer);
	} else {
		jsonw_num(_jw, buffer);
	}

	va_end(args);
}

enum format_type {
	FORMAT_STRING,
	FORMAT_NUMBER
};

// all number formats
const char* num_formats[] = {
  "%d",         // 4 bytes - int
  "%i",         // 4 bytes - int
  "%u",         // 4 bytes - unsigned int
  "%f",         // 4 bytes - float
  "%lf",        // 8 bytes - double
  "%e",         // 4 bytes - float
  "%E",         // 4 bytes - float
  "%g",         // 4 bytes - float
  "%G",         // 4 bytes - float
  "%ld",        // 4 bytes - long int
  "%li",        // 4 bytes - long int
  "%lu",        // 4 bytes - unsigned long int
  "%lld",       // 8 bytes - long long int
  "%lli",       // 8 bytes - long long int
  "%llu",       // 8 bytes - unsigned long long int
  "%hhd",       // 1 byte - signed char
  "%hhi",       // 1 byte - signed char
  "%hhu",       // 1 byte - unsigned char
  "%hd",        // 2 bytes - short int
  "%hi",        // 2 bytes - short int
  "%hu",        // 2 bytes - unsigned short int
  "%Lf",        // 16 bytes - long double
  "%zd",        // varies by system - size_t
  "%zi",        // varies by system - ssize_t
  "%zu",        // varies by system - size_t
  "%p",         // varies by system - pointer
  "%d.%d",      // double integer value
  "%i.%i"       // double integer value
};

#define MAX_FORMAT_TYPE sizeof(num_formats) / sizeof(num_formats[0])
static enum format_type get_format_type(const char* fmt) {
	for (unsigned i = 0; i < MAX_FORMAT_TYPE; i++) {
		if (strcmp(fmt, num_formats[i]) == 0) {
			return FORMAT_NUMBER;
		}
	}
	return FORMAT_STRING;
}

void iw_printf(const char *key, const char *fmt, ...) {
	va_list args;
	static char buf[1024];
	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);


	enum format_type type = get_format_type(fmt);

	if (iw_json) {
		switch (type) {
			case FORMAT_NUMBER:
				iw_print_numf(key, "%s", buf);
				break;
			case FORMAT_STRING:
			default:
				iw_print_stringf(key, "%s", buf);
				break;
		}
	} else {
		//tab intend based on json depth
		iw_print_intend();
		key ? printf("%s: %s\n", key, buf) : printf("%s\n", buf);
	}
}