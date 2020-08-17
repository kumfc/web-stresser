#ifndef _GETROUTES_H
# define _GETROUTES_H

int getroutes(	char **			/* interface string	*/,
		struct sockaddr *	/* target address	*/,
		struct sockaddr **	/* gateway address	*/
	);

#endif
