/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003-2006 jeremian <jeremian [at] poczta.fm>
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
#include <openssl/rsa.h>
#include <openssl/pem.h>

static char* home_dir = NULL;
static char* home_dir_store = NULL;
static char* home_dir_key = NULL;
static char* home_dir_cer = NULL;

typedef struct entry
{ 
  char *key;
  unsigned char *value;
} entryT;

static 
entryT entries[6] = {
  {"countryName", (unsigned char*) "PL"},
  {"stateOrProvinceName", (unsigned char*) "War-Maz"},
  {"localityName", (unsigned char*) "Olsztyn"},
  {"organizationName", (unsigned char*) "gray-world.net"},
  {"organizationalUnitName", (unsigned char*) "APF team"},
  {"commonName", (unsigned char*) "Jeremian <jeremian [at] poczta [dot] fm>"},
};  

static void
callback(int i, int j, void* k)
{
  if (k == NULL) {
    printf("%d", i);
    fflush(stdout);
  }
}

/*
 * Function name: create_apf_dir
 * Description: creates .apf directory in ~/ or apf directory locally
 * Arguments: type - type of the directory to create:
 *                     0 - .apf in ~/
 *                     1 - apf in current dir
 * Returns: 0 - success
 *          1 - problems with fetching user info
 *          2 - home directory is not set
 *          3 - calloc failure
 *          4 - directory creation failure
 */

int
create_apf_dir(char type)
{
  int length;
  struct stat buf;
  struct passwd *user = getpwuid(getuid());
  if (type == 0) {
    if (user == NULL) {
      return 1; /* some problems with fetching user info*/
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
  }
  else {
    if (home_dir) {
      free(home_dir);
      home_dir = NULL;
    }
    home_dir = calloc(1, 4);
    if (home_dir == NULL) {
      return 3; /* calloc failed */
    }
    strcpy(home_dir, "apf");
    if (stat(home_dir, &buf)) {
      if (mkdir(home_dir, 0700)) {
        return 4; /* creating directory failed */
      }
    }
  }
  return 0;
}

int
create_publickey_store(char** storefile)
{
  int store_length, home_length;
  struct stat buf;
  FILE* store_file;
  /* check in local directory first */
  if (stat(*storefile, &buf) == 0) {
    return 0;
  }
  /* check in home_dir */
  store_length = strlen(*storefile);
  home_length = strlen(home_dir);
  if (home_dir_store) {
    free(home_dir_store);
    home_dir_store = NULL;
  }
  home_dir_store = calloc(1, home_length + store_length + 2);
  if (home_dir_store == NULL) {
    return 1; /* calloc failed */
  }
  strcpy(home_dir_store, home_dir);
  home_dir_store[home_length] = '/';
  strcpy(&home_dir_store[home_length+1], *storefile);
  *storefile = home_dir_store;
  store_file = fopen(home_dir_store, "a");
  if (store_file == NULL) {
    return 1;
  }
  fclose(store_file);
  if (stat(home_dir_store, &buf) == 0) {
    return 0;
  }
  return 2;
}

int
generate_rsa_key(char** keyfile)
{
  int key_length, home_length;
  RSA* rsa_key;
  FILE* rsa_file;
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
  printf("generating rsa key: 2048 bits\n");
  rsa_key = RSA_generate_key(2048, 65537, callback, NULL);
  if (RSA_check_key(rsa_key)==1) {
    printf("   OK!\n");
  }
  else {
    printf("   FAILED!\n");
    return 1;
  }

  rsa_file = fopen(home_dir_key, "a");
  PEM_write_RSAPrivateKey(rsa_file, rsa_key, NULL, NULL, 0, NULL, NULL);
  fclose(rsa_file);
  return 0;
}

int
generate_certificate(char** cerfile, char* keyfile)
{
  int cer_length, home_length, i;
  struct stat buf;
  X509* cert;
  X509_REQ* req;
  X509_NAME* subj;
  RSA* rsa_key;
  EVP_PKEY* pkey;
  const EVP_MD *digest;
  FILE* fp;
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
  printf("generating self signed certificate\n");
  fp = fopen(keyfile, "r");
  if (fp == NULL) {
    return 2; /* can't open keyfile */
  }
  rsa_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);
  if (rsa_key == NULL) {
    return 3; /* can't read RSAPrivateKey */
  }
  pkey = EVP_PKEY_new();
  if (pkey == NULL) {
    return 4; /* creating new pkey failed */
  }
  if (EVP_PKEY_set1_RSA(pkey, rsa_key) == 0) {
    return 5; /* setting rsa key failed */
  }
  req = X509_REQ_new();
  if (req == NULL) {
    return 6; /* creating new request failed */
  }
  X509_REQ_set_pubkey(req, pkey);
  subj = X509_NAME_new();
  if (subj == NULL) {
    return 7; /* creating new subject name failed */
  }

  for (i = 0; i < 6; i++)
  {
    int nid;
    X509_NAME_ENTRY *ent;

    if ((nid = OBJ_txt2nid(entries[i].key)) == NID_undef)
    {
      return 8; /* finding NID for a key failed */
    }
    ent = X509_NAME_ENTRY_create_by_NID(NULL, nid, MBSTRING_ASC,entries[i].value, -1);
    if (ent == NULL) {
      return 9; /* creating name entry from NID failed */
    }
    if (X509_NAME_add_entry(subj, ent, -1, 0) == 0) {
      return 10; /* adding entry to name failed */
    }
  }
  if (X509_REQ_set_subject_name(req, subj) == 0) {
    return 11; /* adding subject to request failed */
  }

  digest = EVP_sha1();

  if (X509_REQ_sign(req, pkey, digest) == 0) {
    return 12; /* signing request failed */
  }

  cert = X509_REQ_to_X509(req, 1000, pkey);
  
  if (X509_set_version(cert, 2L) == 0) {
    return 13; /* setting certificate version failed */
  }
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
  
  if (cert == NULL) {
    return 14; /* creating certificate failed */
  }

  if (X509_sign(cert, pkey, digest) == 0) {
    return 15; /* signing failed */
  }
  
  fp = fopen(home_dir_cer, "w");
  if (fp == NULL) {
    return 16; /* writing certificate failed */
  }
  PEM_write_X509(fp, cert);
  fclose(fp);
  
  EVP_PKEY_free(pkey);
  X509_REQ_free(req);
  X509_free(cert);
  return 0;
}

char*
get_store_filename()
{
  return home_dir_store;
}

char*
get_key_filename()
{
  return home_dir_key;
}

char*
get_cer_filename()
{
  return home_dir_cer;
}
