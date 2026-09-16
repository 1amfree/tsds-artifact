#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

volatile size_t tsds_observed_length;

__attribute__((noinline))
void tsds_observe(const char *input) {
    tsds_observed_length = strlen(input);
}

__attribute__((noinline))
void tsds_copy_alnum(char *dst, size_t cap, const char *src) {
    size_t out = 0;
    if (cap == 0) return;
    for (size_t i = 0; src[i] != '\0' && out + 1 < cap; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (isalnum(c) || c == '_') dst[out++] = (char)c;
    }
    dst[out] = '\0';
}

__attribute__((noinline))
void tsds_copy_alnum_prefix(char *dst, size_t cap, const char *src, size_t limit) {
    size_t out = 0;
    if (cap == 0) return;
    for (size_t i = 0; src[i] != '\0' && i < limit && out + 1 < cap; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (isalnum(c) || c == '_') dst[out++] = (char)c;
    }
    dst[out] = '\0';
}

__attribute__((noinline))
void tsds_escape_meta(char *dst, size_t cap, const char *src) {
    size_t out = 0;
    if (cap == 0) return;
    for (size_t i = 0; src[i] != '\0' && out + 1 < cap; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c == ';' || c == '|' || c == '&' || c == '$' || c == '`' ||
            c == '\n' || c == '\t' || c == '>' || c == '<') c = '_';
        dst[out++] = (char)c;
    }
    dst[out] = '\0';
}

__attribute__((noinline))
void tsds_copy_space_safe(char *dst, size_t cap, const char *src) {
    size_t out = 0;
    if (cap == 0) return;
    for (size_t i = 0; src[i] != '\0' && out + 1 < cap; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c != ';' && c != '|' && c != '&' && c != '$' && c != '`' &&
            c != '\n' && c != '\t' && c != '>' && c != '<') dst[out++] = (char)c;
    }
    dst[out] = '\0';
}

__attribute__((noinline))
void tsds_render(char *dst, size_t cap, const char *input) {
    snprintf(dst, cap, "echo %s", input);
}

__attribute__((noinline)) void tsds_case_00(const char *input) { char command[256]; snprintf(command, sizeof(command), "echo %s", input); system(command); }
__attribute__((noinline)) void tsds_case_01(const char *input) { char command[256]; strcpy(command, "echo "); strncat(command, input, sizeof(command) - strlen(command) - 1); system(command); }
__attribute__((noinline)) void tsds_case_02(const char *input) { char command[256]; command[0] = 0; strcat(command, "echo "); strcat(command, input); system(command); }
__attribute__((noinline)) void tsds_case_03(const char *input) { char command[256]; snprintf(command, sizeof(command), "printf fixed && echo %s", input); system(command); }
__attribute__((noinline)) void tsds_case_04(const char *input) { char command[256]; snprintf(command, sizeof(command), "echo '%s'", input); system(command); }
__attribute__((noinline)) void tsds_case_05(const char *input) { char command[256]; snprintf(command, sizeof(command), "echo \"%s\"", input); system(command); }
__attribute__((noinline)) void tsds_case_06(const char *input) { char command[256]; snprintf(command, sizeof(command), "echo %s", input); system(command); }
__attribute__((noinline)) void tsds_case_07(const char *input) { char command[256]; snprintf(command, sizeof(command), "echo %s", input); system(command); }
__attribute__((noinline)) void tsds_case_08(const char *input) { char command[256]; snprintf(command, sizeof(command), "echo %s", input); system(command); }
__attribute__((noinline)) void tsds_case_09(const char *input) { char command[256]; snprintf(command, sizeof(command), "echo %s", input); system(command); }
__attribute__((noinline)) void tsds_case_10(const char *input) { char clean[128]; char command[256]; tsds_copy_alnum(clean, sizeof(clean), input); snprintf(command, sizeof(command), "echo %s", clean); system(command); }
__attribute__((noinline)) void tsds_case_11(const char *input) { char clean[128]; char command[256]; tsds_escape_meta(clean, sizeof(clean), input); snprintf(command, sizeof(command), "echo %s", clean); system(command); }
__attribute__((noinline)) void tsds_case_12(const char *input) { char clean[128]; char command[256]; tsds_copy_alnum(clean, sizeof(clean), input); snprintf(command, sizeof(command), "echo '%s'", clean); system(command); }
__attribute__((noinline)) void tsds_case_13(const char *input) { char command[256]; tsds_observe(input); snprintf(command, sizeof(command), "echo fixed && echo fixed2"); system(command); }
__attribute__((noinline)) void tsds_case_14(const char *input) { char scratch[128]; char command[256]; strcpy(scratch, input); snprintf(command, sizeof(command), "echo fixed"); system(command); }
__attribute__((noinline)) void tsds_case_15(const char *input) { char clean[128]; char command[256]; tsds_escape_meta(clean, sizeof(clean), input); snprintf(command, sizeof(command), "echo \"%s\"", clean); system(command); }
__attribute__((noinline)) void tsds_case_16(const char *input) { char command[256]; snprintf(command, sizeof(command), "echo %.48s", input); system(command); }
__attribute__((noinline)) void tsds_case_17(const char *input) { char clean[16]; char command[256]; tsds_copy_alnum_prefix(clean, sizeof(clean), input, 8); snprintf(command, sizeof(command), "echo %s", clean); system(command); }
__attribute__((noinline)) void tsds_case_18(const char *input) { char command[256]; if (input[0] == 'A') snprintf(command, sizeof(command), "echo %s", input); else snprintf(command, sizeof(command), "echo '%s'", input); system(command); }
__attribute__((noinline)) void tsds_case_19(const char *input) { char command[256]; if (input[0] == 'A') snprintf(command, sizeof(command), "echo fixed-A"); else snprintf(command, sizeof(command), "echo fixed-B"); system(command); }
__attribute__((noinline)) void tsds_case_20(const char *input) { char command[256]; snprintf(command, sizeof(command), "echo %s-%s", input, input); system(command); }
__attribute__((noinline)) void tsds_case_21(const char *input) { char command[256]; tsds_render(command, sizeof(command), input); system(command); }
__attribute__((noinline)) void tsds_case_22(const char *input) { char command[256]; snprintf(command, sizeof(command), "echo %u", (unsigned int)(unsigned char)input[0]); system(command); }
__attribute__((noinline)) void tsds_case_23(const char *input) { char clean[128]; char command[256]; tsds_copy_space_safe(clean, sizeof(clean), input); snprintf(command, sizeof(command), "echo %s", clean); system(command); }
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    int id = atoi(argv[1]);
    const char *input = argv[2];
    switch (id) {
        case 0: tsds_case_00(input); break;
        case 1: tsds_case_01(input); break;
        case 2: tsds_case_02(input); break;
        case 3: tsds_case_03(input); break;
        case 4: tsds_case_04(input); break;
        case 5: tsds_case_05(input); break;
        case 6: tsds_case_06(input); break;
        case 7: tsds_case_07(input); break;
        case 8: tsds_case_08(input); break;
        case 9: tsds_case_09(input); break;
        case 10: tsds_case_10(input); break;
        case 11: tsds_case_11(input); break;
        case 12: tsds_case_12(input); break;
        case 13: tsds_case_13(input); break;
        case 14: tsds_case_14(input); break;
        case 15: tsds_case_15(input); break;
        case 16: tsds_case_16(input); break;
        case 17: tsds_case_17(input); break;
        case 18: tsds_case_18(input); break;
        case 19: tsds_case_19(input); break;
        case 20: tsds_case_20(input); break;
        case 21: tsds_case_21(input); break;
        case 22: tsds_case_22(input); break;
        case 23: tsds_case_23(input); break;
        default: return 3;
    }
    return 0;
}
