/* tclink.h - Header file for TCLink library.
 * 
 * All code contained herein is copyright (c) 2001 TrustCommerce.
 * It is distributed to our clients for your convenience; it is for
 * use by those authorized persons ONLY and for no other purpose beyond
 * integrated with TrustCommerce's payment gateway.
 *
 * That said, please feel free to use this code in any way you see fit for
 * the purpose of TrustCommerce integration.  Should you find any bugs or
 * make interesting improvements/optimizations, please contact us via
 * developer@trustcommerce.com.
 */

#ifndef _TCLINK_H
#define _TCLINK_H

typedef int TCLinkHandle;

/* Create a new TCLinkHandle.
 */
TCLinkHandle TCLinkCreate();

/* Add a parameter to be sent to the server.
 */
void TCLinkPushParam(TCLinkHandle handle, const char *name, const char *value);

/* Flush the parameters to the server.
 * Returns 1 on success, 0 on failure (can't connect).
 */
int TCLinkSend(TCLinkHandle handle);

/* Look up a response value from the server.
 * Returns NULL if no such parameter, or stores the value in 'value' and
 * returns a pointer to value.
 */
char *TCLinkGetResponse(TCLinkHandle handle, const char *name, char *value);

/* Get all response values from the server in one giant string.
 * Stores the string into buf and returns a pointer to it.  Size should be
 * sizeof(buf), which will limit the string so that no buffer overruns occur.
 */
char *TCLinkGetEntireResponse(TCLinkHandle handle, char *buf, int size);

/* Store version string into buf.  Returns a pointer to buf. */
char *TCLinkGetVersion(char *buf);

/* The following function is for debugging ONLY and should not be used
 * in a production environment.  (Call with a NULL parameter to reset to default.)
 */
void TCLinkForceHost(char *host);

#endif

