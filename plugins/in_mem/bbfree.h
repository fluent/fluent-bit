// kept in separate file for visibility over copied code
// also, definition included in the header file so it can be inlined into mem.c
#ifndef IN_MEM_BBFREE_H
#define IN_MEM_BBFREE_H

# define G_unit_steps 10

struct globals {
	unsigned mem_unit;
	unsigned long cached_kb, available_kb, reclaimable_kb;
};

FILE* xfopen_for_read(const char *path)
{
	FILE *fp = fopen(path, "r");
	return fp;
}

// direct copy from https://github.com/mirror/busybox/blob/2cd37d65e221f7267e97360d21f55a2318b25355/procps/free.c#L56
static int parse_meminfo(struct globals *g)
{
	char buf[60]; /* actual lines we expect are ~30 chars or less */
	FILE *fp;
	int seen_cached_and_available_and_reclaimable;

	fp = xfopen_for_read("/proc/meminfo");
	g->cached_kb = g->available_kb = g->reclaimable_kb = 0;
	seen_cached_and_available_and_reclaimable = 3;
	while (fgets(buf, sizeof(buf), fp)) {
		if (sscanf(buf, "Cached: %lu %*s\n", &g->cached_kb) == 1)
			if (--seen_cached_and_available_and_reclaimable == 0)
				break;
		if (sscanf(buf, "MemAvailable: %lu %*s\n", &g->available_kb) == 1)
			if (--seen_cached_and_available_and_reclaimable == 0)
				break;
		if (sscanf(buf, "SReclaimable: %lu %*s\n", &g->reclaimable_kb) == 1)
			if (--seen_cached_and_available_and_reclaimable == 0)
				break;
	}
	/* Have to close because of NOFORK */
	fclose(fp);

	return seen_cached_and_available_and_reclaimable == 0;
}

#endif
