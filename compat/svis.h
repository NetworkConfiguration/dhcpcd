#ifndef SVIS_H
#define SVIS_H

#define	VIS_OCTAL	0x0001	/* use octal \ddd format */
#define	VIS_CSTYLE	0x0002	/* use \[nrft0..] where appropiate */

char *vis(char *dst, int c, int flag, int nextc);
char *svis(char *dst, int c, int flag, int nextc, const char *meta);

#endif
