#include <stdio.h>
#include <stdint.h>

#include "iw_json_print.h"


int main() {
    // init json print without pretty print
	printf("compact json\n");
	iw_obj_new(1, 0);
	iw_obj_openf("tx");
	json_print_u8("bytes", 255);
	json_print_u32("packets", 65536);
	json_print_s32("errors", 65536);
	json_print_u64("dropped", 1);
    iw_arr_openf("hobbies"); // create object entry hobbies with array
    iw_print_stringf(NULL, "%s", "Reading");
    iw_print_stringf(NULL, "%s", "Hiking");
    iw_print_stringf(NULL, "%s", "Coding");
	iw_arr_close();
	iw_obj_close();

    iw_obj_del();

	printf("text output\n");
	iw_obj_new(0, 0);
	iw_printf("k1", "%s", "Sleeping");
    iw_printf("k2", "%u", 1241);
	iw_arr_openf("my_array");
	iw_printf(NULL, "%s", "Sleeping");
    iw_printf(NULL, "%u", 1241);
	iw_arr_close();
    iw_obj_del();

	printf("json pretty print\n");
	iw_obj_new(1, 1);
	iw_printf("k1", "%s", "Sleeping");
    iw_printf("k2", "%llu", 432425435435345435);
	iw_arr_openf("my_array");
	iw_printf(NULL, "%s", "Walking");
    iw_printf(NULL, "%u", 1241);
	iw_arr_close();
    iw_obj_del();



    return 0;
}

