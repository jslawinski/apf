/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003,2004,2005 jeremian <jeremian [at] poczta.fm>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>

static char* home_dir = NULL;
static char* home_dir_key = NULL;
static char* home_dir_cer = NULL;

int
create_apf_dir()
{
  int length;
  struct stat buf;
  struct passwd *user = getpwuid(getuid());
  if (user == NULL) {
    return 1; /* some problems witch fetching user info*/
  }
  if (user->pw_dir == NULL) {
    return 2; /* home directory is not set? */
  }
  if (home_dir) {
    free(home_dir);
    home_dir = NULL;
  }
  length = strlen(user->pw_dir);
  home_dir = calloc(1, length + 6);
  if (home_dir == NULL) {
    return 3; /* calloc failed */
  }
  strcpy(home_dir, user->pw_dir);
  if (home_dir[length] == '/') {
  strcpy(&home_dir[length], ".apf");
  }
  else {
  strcpy(&home_dir[length], "/.apf");
  }
  if (stat(home_dir, &buf)) {
    if (mkdir(home_dir, 0700)) {
      return 4; /* creating directory failed */
    }
  }
  return 0;
}

int
generate_rsa_key(char** keyfile)
{
  int key_length, home_length, status;
  char openssl_cmd[101];
  struct stat buf;
  /* check in local directory first */
  if (stat(*keyfile, &buf) == 0) {
    return 0;
  }
  /* check in home_dir */
  key_length = strlen(*keyfile);
  home_length = strlen(home_dir);
  if (home_dir_key) {
    free(home_dir_key);
    home_dir_key = NULL;
  }
  home_dir_key = calloc(1, home_length + key_length + 2);
  if (home_dir_key == NULL) {
    return 1; /* calloc failed */
  }
  strcpy(home_dir_key, home_dir);
  home_dir_key[home_length] = '/';
  strcpy(&home_dir_key[home_length+1], *keyfile);
  *keyfile = home_dir_key;
  if (stat(home_dir_key, &buf) == 0) {
    return 0;
  }
  /* have to generate the key */
  if (snprintf(openssl_cmd, 101, "openssl genrsa -out %s 2048", home_dir_key) > 100) {
    return 2; /* string is too long */
  }
  status = system(openssl_cmd);
  if (status == -1) {
    return -1;
  }
  return WEXITSTATUS(status);
}

int
generate_certificate(char** cerfile, char* keyfile)
{
  int cer_length, home_length, status, tmp_fd1, tmp_fd2;
  char openssl_cmd[301];
  struct stat buf;
  /* check in local directory first */
  if (stat(*cerfile, &buf) == 0) {
    return 0;
  }
  /* check in home_dir */
  cer_length = strlen(*cerfile);
  home_length = strlen(home_dir);
  if (home_dir_cer) {
    free(home_dir_cer);
    home_dir_cer = NULL;
  }
  home_dir_cer = calloc(1, home_length + cer_length + 2);
  if (home_dir_cer == NULL) {
    return 1; /* calloc failed */
  }
  strcpy(home_dir_cer, home_dir);
  home_dir_cer[home_length] = '/';
  strcpy(&home_dir_cer[home_length+1], *cerfile);
  *cerfile = home_dir_cer;
  if (stat(home_dir_cer, &buf) == 0) {
    return 0;
  }
  /* have to generate the certificate */
  if (snprintf(openssl_cmd, 201, "echo -e \"pl\nWar-Maz\nOlsztyn\nSHEG\nUtils productions\njeremian\njeremian@poczta.fm\" | openssl req -new -x509 -key %s -out %s -days 1095", keyfile, home_dir_cer) > 300) {
    return 2; /* string is too long */
  }
  tmp_fd1 = dup(STDOUT_FILENO);
  tmp_fd2 = dup(STDERR_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
  status = system(openssl_cmd);
  dup2(tmp_fd1, STDOUT_FILENO);
  dup2(tmp_fd2, STDERR_FILENO);
  close(tmp_fd1);
  close(tmp_fd2);
  if (status == -1) {
    return -1;
  }
  return WEXITSTATUS(status);
}
