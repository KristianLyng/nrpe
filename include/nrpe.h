/************************************************************************
 *
 * NRPE.H - NRPE Include File
 * Copyright (c) 1999-2006 Ethan Galstad (nagios@nagios.org)
 * Last Modified: 01-21-2006
 *
 * License:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 ************************************************************************/


/**************** COMMAND STRUCTURE DEFINITION **********/

typedef struct command_struct{
	char *command_name;
	char *command_line;
	struct command_struct *next;
        }command;

int process_arguments(int,char **);
void wait_for_connections(void);
void handle_connection(int);
int read_config_file(char *);
int read_config_dir(char *);
int add_command(char *,char *);
command *find_command(char *);
void sighandler(int);
int drop_privileges(char *,char *);
int write_pid_file(void);
int check_privileges(void);
void free_memory(void);
int is_an_allowed_host(char *);
int validate_request(packet *);
int contains_nasty_metachars(char *);
int process_macros(char *,char *,int);
int my_system(char *,int,int *,char *,int);            	/* executes a command via popen(), but also protects against timeouts */
void my_system_sighandler(int);				/* handles timeouts when executing commands via my_system() */


