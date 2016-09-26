#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>

#include "lwm2mclient.h"

#define MAX_READ_SIZE		1024
#define COMMAND_END_LIST    {NULL, NULL, NULL, NULL, NULL}
#define HELP_COMMAND        "help"
#define HELP_DESC           "Type '"HELP_COMMAND" [COMMAND]' for more details."
#define UNKNOWN_CMD_MSG     "Unknown command. Type '"HELP_COMMAND"' for help."

typedef void (*command_handler_t) (char * args, void * user_data);

typedef struct
{
    char *            name;
    char *            shortDesc;
    char *            longDesc;
    command_handler_t callback;
    void *            userData;
} command_desc_t;

static void handle_command(command_desc_t *commandArray, char *buffer);
static void prv_displayHelp(command_desc_t *commandArray, char *buffer);
static void prv_quit(char *buffer, void *user_data);
static void prv_change_obj(char *buffer, void *user_data);
static void prv_read_obj(char *buffer, void *user_data);

static bool quit_client = false;

command_desc_t commands[] = {
    { "change", "Change the value of a resource. (e.g. \"change /3/0/14 +01:00\")", NULL, prv_change_obj, NULL },
    { "read", "Read the value of a resource. (e.g. \"read /3/0/14\")", NULL, prv_read_obj, NULL },
    { "quit", "Quit the client.", NULL, prv_quit, NULL },
    { NULL, NULL, NULL, NULL, NULL }
};

void cmdline_init(client_handle_t handle)
{
    int i = 0;

    for (i = 0; commands[i].name != NULL; i++)
    {
        commands[i].userData = (void *)handle;
    }

    fprintf(stdout, "> "); fflush(stdout);
}

int cmdline_process(int timeout)
{
    int result;
    int numBytes;
    uint8_t buffer[MAX_READ_SIZE];
    fd_set readfd;
    struct timeval tv;

    FD_ZERO(&readfd);
    FD_SET(STDIN_FILENO, &readfd);

    tv.tv_usec = 0;
    tv.tv_sec = timeout;

    result = select(FD_SETSIZE, &readfd, NULL, NULL, &tv);
    if (result < 0)
    {
        if (errno != EINTR)
        {
            fprintf(stderr, "Error in select(): %d %s\r\n", errno, strerror(errno));
            return LWM2M_CLIENT_ERROR;
        }
    }
    else if (result > 0)
    {
        numBytes = read(STDIN_FILENO, buffer, MAX_READ_SIZE - 1);

        if (numBytes > 1)
        {
            buffer[numBytes] = 0;
            /*
             * We call the corresponding callback of the typed command passing it the buffer for further arguments
             */
            handle_command(commands, (char*)buffer);
        }

        fprintf(stdout, "\r\n");
    }

    return quit_client ? LWM2M_CLIENT_QUIT : LWM2M_CLIENT_OK;
}

static command_desc_t * prv_find_command(command_desc_t *commandArray, char *buffer, size_t length)
{
    int i;

    if (length == 0) return NULL;

    i = 0;
    while (commandArray[i].name != NULL
        && (strlen(commandArray[i].name) != length || strncmp(buffer, commandArray[i].name, length)))
    {
        i++;
    }

    if (commandArray[i].name == NULL)
    {
        return NULL;
    }
    else
    {
        return &commandArray[i];
    }
}

void handle_command(command_desc_t *commandArray, char *buffer)
{
    command_desc_t * cmdP;
    int length;

    // find end of command name
    length = 0;
    while (buffer[length] != 0 && !isspace(buffer[length]&0xFF))
        length++;

    cmdP = prv_find_command(commandArray, buffer, length);
    if (cmdP != NULL)
    {
        while (buffer[length] != 0 && isspace(buffer[length]&0xFF))
            length++;
        cmdP->callback(buffer + length, cmdP->userData);
    }
    else
    {
        if (!strncmp(buffer, HELP_COMMAND, length))
        {
            while (buffer[length] != 0 && isspace(buffer[length]&0xFF))
                length++;
            prv_displayHelp(commandArray, buffer + length);
        }
        else
        {
            fprintf(stdout, UNKNOWN_CMD_MSG"\r\n");
        }
    }
}

void prv_displayHelp(command_desc_t *commandArray, char *buffer)
{
    command_desc_t * cmdP;
    int length;

    // find end of first argument
    length = 0;
    while (buffer[length] != 0 && !isspace(buffer[length]&0xff))
        length++;

    cmdP = prv_find_command(commandArray, buffer, length);

    if (cmdP == NULL)
    {
        int i;

        fprintf(stdout, HELP_COMMAND"\t"HELP_DESC"\r\n");

        for (i = 0 ; commandArray[i].name != NULL ; i++)
        {
            fprintf(stdout, "%s\t%s\r\n", commandArray[i].name, commandArray[i].shortDesc);
        }
    }
    else
    {
        fprintf(stdout, "%s\r\n", cmdP->longDesc?cmdP->longDesc:cmdP->shortDesc);
    }
}

static char*prv_end_of_space(char* buffer)
{
    while (isspace(buffer[0]&0xff))
    {
        buffer++;
    }
    return buffer;
}

static char*get_end_of_arg(char* buffer)
{
    while (buffer[0] != 0 && !isspace(buffer[0]&0xFF))
    {
        buffer++;
    }
    return buffer;
}

static char *get_next_arg(char * buffer, char** end)
{
    // skip arg
    buffer = get_end_of_arg(buffer);
    // skip space
    buffer = prv_end_of_space(buffer);
    if (NULL != end)
    {
        *end = get_end_of_arg(buffer);
    }

    return buffer;
}

void prv_change_obj(char *buffer, void *user_data)
{
    client_handle_t handle = (client_handle_t)user_data;
    char *end = NULL;
    lwm2m_resource_t res;

    end = get_end_of_arg(buffer);
    if (end[0] == 0)
    {
        fprintf(stdout, "Syntax error !\n");
        return;
    }

    strncpy(res.uri, buffer, end - buffer);
    res.buffer = (uint8_t*)get_next_arg(end, &end);
    res.length = (int)(end - (char*)res.buffer);

    lwm2m_write_resource(handle, &res);
}

void prv_read_obj(char *buffer, void *user_data)
{
    client_handle_t handle = (client_handle_t)user_data;
    char *end = NULL;
    char *val = NULL;
    lwm2m_resource_t res;
    int i = 0;

    end = get_end_of_arg(buffer);
    if (end[0] == 0)
    {
        fprintf(stdout, "Syntax error !\n");
        return;
    }

    strncpy(res.uri, buffer, end - buffer);

    if (lwm2m_read_resource(handle, &res))
    {
        fprintf(stdout, "Read failed !\n");
        return;
    }

    val = strndup((char*)res.buffer, res.length);

    fprintf(stdout, "URI: %s - Value: %s\r\n> ", res.uri, val);

    free(res.buffer);
    free(val);
}

void prv_quit(char *buffer, void *user_data)
{
    quit_client = true;
}
