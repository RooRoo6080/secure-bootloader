// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define IV_LEN 16
#define MAX_MSG_LEN 256

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

typedef struct fw_meta_s {
    uint16_t    ver;                // Version of current fw being loaded
    uint16_t    min_ver;            // Miniumum fw version (not updated when debug fw loaded) 
    uint16_t    chunks;             // Length of fw in 1kb chunks
    uint16_t    msgLen;             // Length of fw message in bytes
    uint8_t     msg[MAX_MSG_LEN];   // fw release message
} fw_meta_st;

long program_flash(void* page_addr, unsigned char * data, unsigned int data_len);

#endif

