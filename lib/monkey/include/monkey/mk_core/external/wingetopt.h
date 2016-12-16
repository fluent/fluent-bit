/*
POSIX getopt for Windows

AT&T Public License

Code given out at the 1985 UNIFORUM conference in Dallas.
*/

#ifndef __GNUC__

#ifndef _WINGETOPT_H_
#define _WINGETOPT_H_

#ifdef __cplusplus
extern "C" {
#endif

extern int opterr;
extern int optind;
extern int optopt;
extern char *optarg;
extern int getopt(int argc, char **argv, char *opts);

#define getopt_long(a, b, c, d, e) getopt(a, b, c)

#ifdef __cplusplus
}
#endif

#endif  /* _GETOPT_H_ */
#endif  /* __GNUC__ */
