#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "laffun.h"

/**
 * Connect to the DBUS bus and send a broadcast signal
 */
void send_signal(DBusConnection *conn, char* sigvalue)
{
	DBusMessage* msg;
	DBusMessageIter args;
	dbus_uint32_t serial = 0;

	if (DEBUG)
		printf("Sending signal with value %s\n", sigvalue);

	// create a signal & check for errors 
	msg = dbus_message_new_signal(	"/laf/signal/alert",	// object name of the signal
									"laf.signal.source",	// interface name of the signal
									"event");				// name of the signal
	if (NULL == msg) 
	{ 
	  fprintf(stderr, "Message Null\n"); 
	  exit(1); 
	}

	// append arguments onto signal
	dbus_message_iter_init_append(msg, &args);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &sigvalue)) {
		fprintf(stderr, "Out Of Memory!\n"); 
		exit(1);
	}

	// send the message and flush the connection
	if (!dbus_connection_send(conn, msg, &serial)) {
	  fprintf(stderr, "Out Of Memory!\n"); 
	  exit(1);
	}
	dbus_connection_flush(conn);

	if (DEBUG)
		printf("Signal Sent\n");

	// free the message and close the connection
	dbus_message_unref(msg);
	}

	int main(int argc, char** argv)
	{
	DBusConnection* conn;
	DBusError err;
	int ret;
	char* buffer;
	int nls;

	pid_t pid;

	pid = fork();

	if (pid < 0)
		exit(EXIT_FAILURE);

	if (pid > 0)
		exit(EXIT_SUCCESS);

	if (setsid() < 0)
		exit(EXIT_FAILURE);

	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	pid = fork();

	if (pid < 0)
		exit(EXIT_FAILURE);

	if (pid > 0)
		exit(EXIT_SUCCESS);

	// initialise the error value
	dbus_error_init(&err);

	// connect to the DBUS system bus, and check for errors
	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
	if (dbus_error_is_set(&err)) { 
		fprintf(stderr, "Connection Error (%s)\n", err.message); 
		dbus_error_free(&err); 
	}
	if (NULL == conn) { 
		exit(1); 
	}

	// register our name on the bus, and check for errors
	ret = dbus_bus_request_name(conn, "laf.signal.source", DBUS_NAME_FLAG_REPLACE_EXISTING , &err);
	if (dbus_error_is_set(&err)) { 
		fprintf(stderr, "Name Error (%s)\n", err.message); 
		dbus_error_free(&err); 
	}
	if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret) { 
		exit(1);
	}

	/* open netlink socket */
	nls = open_netlink();
	if (nls < 0)
		return nls;

	buffer = malloc(MAX_WL_SIZE);
	bzero(buffer,MAX_WL_SIZE);

	while (1) {
		read_event_buf(nls, MSG_WAITALL, buffer, MAX_WL_SIZE);
		send_signal(conn, buffer);
		bzero(buffer,MAX_WL_SIZE);
	}

	dbus_connection_close(conn);
	free(buffer);
	close(nls);

	return 0;
}

