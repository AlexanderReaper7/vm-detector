#include "stats.h"
#include <cstdio>
#include <cstring>

/* Must match the Category enum order in stats.h. */
const char* category_names[CAT_COUNT] = {
	"TLS Callbacks",
	"Debugger Detection",
	"DLL Injection Detection",
	"Generic Sandbox/VM Detection",
	"VirtualBox Detection",
	"VMWare Detection",
	"Virtual PC Detection",
	"QEMU Detection",
	"KVM Detection",
	"Xen Detection",
	"Wine Detection",
	"Parallels Detection",
	"Hyper-V Detection",
	"Timing Attacks",
	"Analysis Tools",
	"Kernel VM Detection",
};

Category g_current_category = CAT_NONE;

static CategoryStat category_stats[CAT_COUNT];
static int total_passed = 0, total_failed = 0;
static int total_observed = 0, total_errors = 0;

void stats_init(void)
{
	memset(category_stats, 0, sizeof(category_stats));
	total_passed = 0;
	total_failed = 0;
	total_observed = 0;
	total_errors = 0;
	g_current_category = CAT_NONE;
}

void stats_record(Category cat, int result)
{
	if (cat < 0 || cat >= CAT_COUNT)
		return;

	/* A check returning TRUE means an analysis artifact was detected, i.e. the
	   environment "failed" the check; FALSE means it looked clean ("passed"). */
	if (result == CHECK_BAD) {
		category_stats[cat].failed++;
		total_failed++;
	} else if (result == CHECK_GOOD) {
		category_stats[cat].passed++;
		total_passed++;
	} else if (result == CHECK_OBSERVATION) {
		category_stats[cat].observed++;
		total_observed++;
	} else if (result == CHECK_ERROR) {
		category_stats[cat].errors++;
		total_errors++;
	}
}

void stats_print(void)
{
	printf("\n==== Per-Category Statistics ====\n");
	for (int i = 0; i < CAT_COUNT; ++i) {
		printf("%-40s: Passed %3d | Failed %3d | Observations %3d | Errors %3d\n",
			category_names[i], category_stats[i].passed, category_stats[i].failed,
			category_stats[i].observed, category_stats[i].errors);
	}
	printf("\n==== Overall Statistics ====\n");
	printf("Total checks passed: %d\n", total_passed);
	printf("Total checks failed: %d\n", total_failed);
	printf("Total observations: %d\n", total_observed);
	printf("Total check errors: %d\n", total_errors);
}
