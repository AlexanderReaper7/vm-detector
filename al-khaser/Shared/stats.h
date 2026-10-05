#pragma once

/*
Per-category pass/fail tallying. Every check result flows through
_print_check_result (Common.cpp), which calls stats_record against the
category currently set in g_current_category. Blocks set g_current_category
once at their start; blocks that should not be counted (initialisation, code
injection, anti-disassembly, dumping) set it to CAT_NONE.

Order of the Category values and of category_names[] must stay in sync.
*/
typedef enum {
	CAT_NONE = -1, // not counted
	CAT_TLS = 0,
	CAT_DEBUG,
	CAT_INJECTION,
	CAT_GEN_SANDBOX,
	CAT_VBOX,
	CAT_VMWARE,
	CAT_VPC,
	CAT_QEMU,
	CAT_KVM,
	CAT_XEN,
	CAT_WINE,
	CAT_PARALLELS,
	CAT_HYPERV,
	CAT_TIMING_ATTACKS,
	CAT_ANALYSIS_TOOLS,
	CAT_COUNT // always last: number of counted categories
} Category;

typedef struct {
	int passed;
	int failed;
} CategoryStat;

extern const char* category_names[CAT_COUNT];
extern Category g_current_category;

void stats_init(void);
void stats_record(Category cat, int result); // result: TRUE = detected (failed), FALSE = passed
void stats_print(void);
