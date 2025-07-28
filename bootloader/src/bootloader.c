/*
Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
Approved for public release. Distribution unlimited 23-02181-25.

bootloader/src/bootloader.c

The Bootloader manages which firmware gets updated to the TM4C, and will start the execution of the loaded vehicle firmware.
While it’s connected to the fw_update tool, it checks the version of the new firmware against the internal firmware version
before accepting the new firmware.

There are multiple partitions located in flash memory:

FW_BASE is the location that firmware gets executed from.
FW_CHECK_BASE is the location that the encrypted firmware lives and is verified each time before being decrypted on boot
and copied to BASE before execution begins
FW_INCOMING_BASE is the location that the incoming firmwaAe first gets written to and is not trusted to contain valid firmware.

On each boot, firmware is verified from FW_CHECK_BASE before being decrypted, moved, and run from FW_BASE.

General Function Return Information:
Each function used to verify returns 0 on success and nonzero (usually 1) on fallure.
The calling location then handles the result, often system resetting and clearing on a failure.
*/

// Standard Imports
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bootloader.h"

// Wolfcrypt Libraries
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/sha.h"

// Hardware Imports
#include "inc/hw_flash.h"
#include "inc/hw_memmap.h"
#include "inc/hw_types.h"
#include "inc/tm4c123gh6pm.h"

// Driver API Imports
#include "driverlib/adc.h"
#include "driverlib/eeprom.h"
#include "driverlib/flash.h"
#include "driverlib/interrupt.h"
#include "driverlib/sysctl.h"

// Application Imports
#include "driverlib/gpio.h"
#include "uart/uart.h"

// Secret Keys import
#include "keys.h"

// Forward declarations
void load_firmware(void);
void boot_firmware(void);
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);
void erase_partition(uint32_t, uint8_t);
uint8_t verify_signature(uint32_t, uint32_t, uint32_t, uint16_t, uint32_t);
uint8_t move_and_decrypt(uint32_t, uint32_t, uint16_t);
uint8_t move_firmware(uint32_t, uint32_t, uint16_t);
void check_canary(uint32_t);
void uart_write_str_length(uint8_t, char *, uint16_t);

// Metadata location constants
#define METADATA_BASE 0xFB00
#define METADATA_CHECK_BASE 0x28000
#define METADATA_INCOMING_BASE 0x30000

// Firmware location constants
#define FW_BASE 0x10000
#define FW_CHECK_BASE 0x18000
#define FW_INCOMING_BASE 0x20000

// Version constant
#define MAX_VERSION 0x38000

// FLASH constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// EEPROM location constants
#define AES_KEY_EEPROM_LOCATION 0x200
#define RSA_PUB_KEY_EEPROM_LOCATION 0x400

// Data & key buffers
unsigned char data[FLASH_PAGESIZE + 6];
RsaKey pub;
int inOut = 0;
byte hash[32];
byte * decry_sig_arr;
byte signature_buffer[256];
Sha256 sha256[1];
byte aes_out[1024];
uint32_t aes_key_eeprom[16];
uint32_t rsa_pub_eeprom[294];

// Global canary reference
const uint32_t canary_global = 0xDEADBEEF;

int main(void) {

    volatile uint32_t canary = canary_global;

    // Disable debugging
    HWREG(FLASH_FMA) = 0x75100000;
    HWREG(FLASH_FMD) = HWREG(FLASH_BOOTCFG) & 0x7FFFFFFC;
    HWREG(FLASH_FMC) = FLASH_FMC_WRKEY | FLASH_FMC_COMT;

    // Write AES & RSA keys to EEPROM
    SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_EEPROM0)) {
    }
    EEPROMInit();
    EEPROMProgram((uint32_t *)aes_key, AES_KEY_EEPROM_LOCATION, sizeof(aes_key));
    EEPROMProgram((uint32_t *)rsa_pub_key, RSA_PUB_KEY_EEPROM_LOCATION, sizeof(rsa_pub_eeprom));

    // Clear keys from memory
    for (int i = 0; i < 16; i++) {
        aes_key[i] = '\0';
    }
    for (int i = 0; i < 294; i++) {
        rsa_pub_key[i] = '\0';
    }

    // Load version to Flash
    uint16_t version = (uint16_t)(*(uint32_t *)MAX_VERSION);
    uint32_t start_version = 1;
    if (version == 0xFFFF) {
        FlashErase(MAX_VERSION);
        FlashProgram(&start_version, MAX_VERSION, 4);
    }

    // Erase unencrypted firmware & corresponding metadata
    erase_partition(METADATA_BASE, 2);
    erase_partition(FW_BASE, 31);

    initialize_uarts(UART0);

    uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
    uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

    int resp;
    while (1) {
        uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

        if (instruction == UPDATE) {
            uart_write_str(UART0, "U");
            load_firmware();
            uart_write_str(UART0, "Loaded new firmware.\n");
            nl(UART0);
        } else if (instruction == BOOT) {
            uart_write_str(UART0, "B");
            uart_write_str(UART0, "Booting firmware...\n");
            boot_firmware();
        }
        check_canary(canary);
    }
}

/*
Read metadata and firmware in chunks from fw_update.py script

Format of incoming protected firmware:
-------------------------------------
HEADER (unencrypted)
 - encrypted payload length (2 bytes)
 - firmware version (2 bytes)
 - message length (2 bytes)
 - message
PAYLOAD (AES encrypted)
 - firmware binary
 - padding required for AES
SIGNATURE (SHA hashed and RSA signed)
 - signature of header + payload (256 bytes)
-------------------------------------
*/
void load_firmware(void) {
    volatile uint32_t canary = canary_global;

    int frame_length = 0;
    int read = 0;
    uint32_t rcv = 0;

    uint32_t data_index = 0;
    uint32_t page_addr = FW_INCOMING_BASE;
    uint16_t version = 0;
    uint16_t size = 0;
    uint16_t message_length = 0;

    // Read metadata lengths
    rcv = uart_read(UART0, BLOCKING, &read);
    data[data_index] = rcv;
    data_index++;
    size = (uint32_t)rcv;

    rcv = uart_read(UART0, BLOCKING, &read);
    data[data_index] = rcv;
    data_index++;
    size |= (uint32_t)rcv << 8;

    rcv = uart_read(UART0, BLOCKING, &read);
    data[data_index] = rcv;
    data_index++;
    version = (uint32_t)rcv;

    rcv = uart_read(UART0, BLOCKING, &read);
    data[data_index] = rcv;
    data_index++;
    version |= (uint32_t)rcv << 8;

    rcv = uart_read(UART0, BLOCKING, &read);
    data[data_index] = rcv;
    data_index++;
    message_length = (uint32_t)rcv;

    rcv = uart_read(UART0, BLOCKING, &read);
    data[data_index] = rcv;
    data_index++;
    message_length |= (uint32_t)rcv << 8;

    if (message_length > 1024) {
        uart_write(UART0, ERROR);
        SysCtlReset();
    }

    uint32_t metadata_page_address = METADATA_INCOMING_BASE;

    // Read message
    for (int i = 0; i < message_length; i++) {
        rcv = uart_read(UART0, BLOCKING, &read);
        data[data_index] = rcv;
        data_index++;

        // Account for message length greater than FLASH_PAGESIZE - 6 (number of length bytes)
        if (data_index == FLASH_PAGESIZE) {
            if (program_flash((uint32_t *)metadata_page_address, data, data_index)) {
                uart_write(UART0, ERROR);
                SysCtlReset();
                return;
            }

            metadata_page_address += FLASH_PAGESIZE;
            data_index = 0;
        }
    }

    // Null byte to stop writing message
    data[data_index] = '\0';
    data_index++;

    // Flash metadata to METADATA_INCOMING_BASE
    if (program_flash((uint32_t *)metadata_page_address, data, data_index)) {
        uart_write(UART0, ERROR);
        SysCtlReset();
        return;
    }

    // Version check
    uint16_t old_version = (uint16_t)(*(uint32_t *)MAX_VERSION);
    if (version != 0 && version < old_version) {
        uart_write(UART0, ERROR);
        SysCtlReset();
        return;
    } else if (version != 0) {
        uint32_t new_version = (uint32_t)version;
        FlashErase(MAX_VERSION);
        FlashProgram(&new_version, MAX_VERSION, 4);
    }

    check_canary(canary);
    data_index = 0;
    uart_write(UART0, OK);

    // Read 2 bytes of incoming firmware + signature frame length and the frame data
    while (1) {
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length = (uint32_t)rcv;
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length |= (uint32_t)rcv << 8;

        for (int i = 0; i < frame_length; ++i) {
            data[data_index] = uart_read(UART0, BLOCKING, &read);
            data_index += 1;

            // Check for too large frame sizes
            if (data_index > FLASH_PAGESIZE) {
                uart_write(UART0, ERROR);
                SysCtlReset();
                return;
            }
        }

        if (data_index == FLASH_PAGESIZE || frame_length == 0) {
            if (program_flash((uint8_t *)page_addr, data, data_index)) {
                uart_write(UART0, ERROR);
                SysCtlReset();
                return;
            }

            page_addr += FLASH_PAGESIZE;
            data_index = 0;

            // Check for firmware sizes over the maximum of 30kb + signature
            if (page_addr >= FW_INCOMING_BASE + (31 * 1024)) {
                uart_write(UART0, ERROR);
                SysCtlReset();
                return;
            }

            if (frame_length == 0) {
                uart_write(UART0, OK);
                break;
            }
        }

        check_canary(canary);
        uart_write(UART0, OK);
    }
}

/*
Handles the logic to verify and decrypt new firmware and / or run existing firmware

If new firmware is loaded into *_INCOMING_BASE, verify it's signature and move it to *_CHECK_BASE
Verify signature of data in *_CHECK_BASE and decrypt + move to *_BASE
Run decrypted firmware from *_BASE

BASE     | rwx
CHECK    | rw
INCOMING | rw
*/
void boot_firmware(void) {
    volatile uint32_t canary = canary_global;

    // Check if incoming metadata / firmware is present
    int incoming_fw_present = 0;
    if (*(uint32_t *)METADATA_INCOMING_BASE != 0xFFFFFFFF) {
        incoming_fw_present = 1;
    }

    if (incoming_fw_present) {
        uint16_t size = *(uint16_t *)METADATA_INCOMING_BASE;
        uint16_t message_length = *(uint16_t *)(METADATA_INCOMING_BASE + 4);
        uint32_t sign_add = FW_INCOMING_BASE + size;

        // Verify incoming firmware signature
        if (verify_signature(sign_add, FW_INCOMING_BASE, size, message_length, METADATA_INCOMING_BASE) == 0) {

            // Erase next partition and move INCOMING to CHECK
            erase_partition(METADATA_CHECK_BASE, 2);
            erase_partition(FW_CHECK_BASE, 31);
            if (move_firmware(METADATA_INCOMING_BASE, METADATA_CHECK_BASE, 2) || move_firmware(FW_INCOMING_BASE, FW_CHECK_BASE, 31)) {
                SysCtlReset();
            }
        } else {
            uart_write_str(UART0, "Incoming signature verification failed. Booting previous firmware\n");
        }

        // Clear INCOMING for future firmwares
        erase_partition(METADATA_INCOMING_BASE, 2);
        erase_partition(FW_INCOMING_BASE, 31);
    }

    // Check if data present in CHECK
    if (*(uint32_t *)METADATA_CHECK_BASE == 0xFFFFFFFF) {
        SysCtlReset();
    }

    // Verify signature in CHECK
    uint16_t size_check = *(uint16_t *)METADATA_CHECK_BASE;
    uint16_t message_length_check = *(uint16_t *)(METADATA_CHECK_BASE + 4);
    uint32_t sign_add_check = FW_CHECK_BASE + size_check;

    if (verify_signature(sign_add_check, FW_CHECK_BASE, size_check, message_length_check, METADATA_CHECK_BASE) == 0) {
        erase_partition(METADATA_BASE, 2);
        erase_partition(FW_BASE, 31);

        if (move_firmware(METADATA_CHECK_BASE, METADATA_BASE, 2)) {
            SysCtlReset();
        }

        // AES decrypt and move firmware to BASE
        if (move_and_decrypt(FW_CHECK_BASE, FW_BASE, 31)) {
            SysCtlReset();
        }

        uart_write_str(UART0, "Booting firmware...\n");
        nl(UART0);

        // Write firmware message
        uart_write_str_length(UART0, (char *)(METADATA_BASE + 6), *(uint16_t *)(METADATA_BASE + 4));
        nl(UART0);

        check_canary(canary);

        // Run firmware
        __asm("LDR R0,=0x10001\n\t"
              "BX R0\n\t");

    } else {
        SysCtlReset();
    }
}

/*
Verify SHA-256 hashed & RSA-2048 PSS encrypted signature
*/
uint8_t verify_signature(uint32_t signature_idx, uint32_t payload_idx, uint32_t payload_length, uint16_t message_length, uint32_t metadata) {
    nl(UART0);

    volatile uint32_t canary = canary_global;
    inOut = 0;

    // Grab RSA key from EEPROM
    wc_InitRsaKey(&pub, NULL);
    EEPROMRead(rsa_pub_eeprom, RSA_PUB_KEY_EEPROM_LOCATION, sizeof(rsa_pub_eeprom));
    wc_RsaPublicKeyDecode((byte *)rsa_pub_eeprom, &inOut, &pub, 294);
    for (int i = 0; i < 294; i++) {
        rsa_pub_eeprom[i] = '\0';
    }

    // SHA-256 hash metadata + firmware
    wc_InitSha256(sha256);
    wc_Sha256Update(sha256, (byte *)metadata, message_length + 6);
    wc_Sha256Update(sha256, (byte *)payload_idx, payload_length);
    wc_Sha256Final(sha256, hash);
    
    // Read signature from flash
    memcpy(signature_buffer, (byte *)signature_idx, 256);
    
    // Verify if the message was signed with RSA PSS
    int decry_sig_len = wc_RsaPSS_VerifyInline(signature_buffer, 256, &decry_sig_arr, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &pub);
    if (decry_sig_len > 0) {
    } else {
        wc_FreeRsaKey(&pub);
        wc_Sha256Free(sha256);
        return 1;
    }

    // Check PSS data to ensure signature matches
    int result = wc_RsaPSS_CheckPadding(hash, 32, decry_sig_arr, (word32)decry_sig_len, WC_HASH_TYPE_SHA256);
    if (result == 0) {
        wc_FreeRsaKey(&pub);
        wc_Sha256Free(sha256);
        check_canary(canary);
        return 0;
    }

    // Free keys from memory
    wc_FreeRsaKey(&pub);
    wc_Sha256Free(sha256);
    return 1;
}

/*
Moves and AES decrypts from origin to destination the given number of kilobytes (often 32 for partition length).
*/
uint8_t move_and_decrypt(uint32_t origin_idx, uint32_t destination_idx, uint16_t length_in_kb) {
    volatile uint32_t canary = canary_global;
    Aes aes;

    EEPROMRead(aes_key_eeprom, AES_KEY_EEPROM_LOCATION, sizeof(aes_key_eeprom));

    wc_AesSetKey(&aes, (byte *)aes_key_eeprom, 16, aes_iv, AES_DECRYPTION);
    for (int i = 0; i < 16; i++) {
        aes_key_eeprom[i] = '\0';
    }

    for (uint32_t offset = 0; offset < (length_in_kb); offset++) {
        uint32_t page_address = (destination_idx + (offset * 1024));
        uint32_t data_to_write = origin_idx + (offset * 1024);

        wc_AesCbcDecrypt(&aes, aes_out, (const byte *)data_to_write, (word32)1024);

        if (program_flash((uint32_t *)page_address, aes_out, 1024) == -1) {
            return 1;
        }
    }
    wc_AesFree(&aes);
    check_canary(canary);
    return 0;
}

/*
Moves a given number of kilobytes (usually the firmware) from origin to destinition.
Checks the canary after moving.
*/
uint8_t move_firmware(uint32_t origin_idx, uint32_t destination_idx, uint16_t length_in_kb) {
    volatile uint32_t canary = canary_global;

    for (uint32_t offset = 0; offset < (length_in_kb); offset++) {
        uint32_t page_address = (destination_idx + (offset * 1024));
        uint32_t data_to_write = origin_idx + (offset * 1024);
        if (program_flash((uint32_t *)page_address, (byte *)data_to_write, 1024) == -1) {
            return 1;
        }
    }
    check_canary(canary);
    return 0;
}

/*
Erases a specific location in flash memory starting from a given index and being a given number of flash pages.
Is used primarily for erasing different partitions in memory (ie. BASE, CHECK, INCOMING) but also for more general memory erasing.
*/
void erase_partition(uint32_t start_idx, uint8_t length_in_kb) {
    for (int i = 0; i < length_in_kb; i++) {
        uint32_t erase = start_idx + (i * 1024);
        FlashErase(erase);
    }
}

/*
Checks for stack overflow attacks by verifying that the stack canary, 
which is initalized at the beginning of each function that uses this,
matches the global canary
*/
void check_canary(uint32_t canary) {
    if (canary != canary_global) {
        SysCtlReset();
        while (1) {
        }
    }
}

/*
Given function for programming a page of flash.
First it erases the page, does balance checking to make sure that the data is word aligned and fills
up the final word programmed, and finally flash programs the page
*/
long program_flash(void * page_addr, unsigned char * data, unsigned int data_len) {
    uint32_t word = 0;
    int ret;
    int i;

    FlashErase((uint32_t)page_addr);

    if (data_len % FLASH_WRITESIZE) {
        int rem = data_len % FLASH_WRITESIZE;
        int num_full_bytes = data_len - rem;

        ret = FlashProgram((unsigned long *)data, (uint32_t)page_addr, num_full_bytes);
        if (ret != 0) {
            return ret;
        }

        for (i = 0; i < rem; i++) {
            word = (word >> 8) | (data[num_full_bytes + i] << 24);
        }
        for (i = i; i < 4; i++) {
            word = (word >> 8) | 0xFF000000;
        }

        return FlashProgram(&word, (uint32_t)page_addr + num_full_bytes, 4);
    } else {
        return FlashProgram((unsigned long *)data, (uint32_t)page_addr, data_len);
    }
}

/*
Given function for debug purposes for printing out multiple bytes easily
*/
void uart_write_hex_bytes(uint8_t uart, uint8_t * start, uint32_t len) {
    for (uint8_t * cursor = start; cursor < (start + len); cursor += 1) {
        uint8_t data = *((uint8_t *)cursor);
        uint8_t right_nibble = data & 0xF;
        uint8_t left_nibble = (data >> 4) & 0xF;
        char byte_str[3];
        if (right_nibble > 9) {
            right_nibble += 0x37;
        } else {
            right_nibble += 0x30;
        }
        byte_str[1] = right_nibble;
        if (left_nibble > 9) {
            left_nibble += 0x37;
        } else {
            left_nibble += 0x30;
        }
        byte_str[0] = left_nibble;
        byte_str[2] = '\0';

        uart_write_str(uart, byte_str);
        uart_write_str(uart, " ");
    }
}

/* 
uart_write_str, but stops at both length and null byte for extra safety
*/
void uart_write_str_length(uint8_t uart, char * str, uint16_t len) {
    for (uint16_t i = 0; i < len; i++) {
        if (!*str) {
            return;
        }
        uart_write(uart, (uint32_t)*str++);
    }
}