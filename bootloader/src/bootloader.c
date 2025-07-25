// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

// Payload format
// -------------------------------------
// HEADER (unencrypted)
//  - encrypted payload length (4 bytes)
//  - firmware version (2 bytes)
// PAYLOAD (AES encrypted)
//  - firmware binary length (4 bytes)
//  - message length (4 bytes)
//  - firmware binary
//  - message
//  - padding required for AES
// SIGNATURE (SHA hashed and RSA signed)
//  - signature (256 bytes)
// -------------------------------------

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bootloader.h"

#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/sha.h"

// Hardware Imports
#include "inc/hw_memmap.h"    // Peripheral Base Addresses
#include "inc/hw_types.h"     // Boolean type
#include "inc/tm4c123gh6pm.h" // Peripheral Bit Masks and Registers

#include "driverlib/adc.h"

// Driver API Imports
#include "driverlib/flash.h"     // FLASH API
#include "driverlib/interrupt.h" // Interrupt API
#include "driverlib/sysctl.h"    // System control API (clock/reset)

// Application Imports
#include "driverlib/gpio.h"
#include "uart/uart.h"

#include "public_key.h"

// Forward Declarations
void load_firmware(void);
void boot_firmware(void);
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);
uint8_t erase_partition(uint32_t *, uint8_t);
uint8_t check_firmware(uint32_t *);
uint8_t verify_signature(uint32_t *, uint32_t *, uint32_t);
uint8_t aes_decrypt_move(uint32_t *, uint16_t, uint32_t *, byte *, byte *);
void move_firmware(uint32_t *, uint32_t *, uint16_t);

// Firmware Constants
#define METADATA_BASE 0xFC00     // base address of version and firmware size in Flash
#define FW_BASE 0x10000          // base address of firmware in Flash
#define FW_CHECK_BASE 0x18000    // base address of incoming firmware in Flash
#define FW_INCOMING_BASE 0x20000 // base address of incoming firmware in Flash

#define FW_BASE_SIZE 0x8000 // size of FW BLOCK and FW CHECK //maybe off by one? double check

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

#define SIGNATURE_LEN 256

// Device metadata
uint16_t * fw_version_address = (uint16_t *)METADATA_BASE;
uint16_t * fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t * fw_release_message_address;

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];

RsaKey pub;
int zero = 0;
byte hash[32];
byte * decry_sig_arr[256];

int main(void) {

    initialize_uarts(UART0);

    // wc_AesSetKey(Aes * ?firmware?, const byte * aes_key, word32 16, const byte * ?iv?, AES_ENCRYPTION)

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
    }
}

/*
 * Load the firmware into flash.
 */

// TODO: BYTE ORDER ISSUES WITH HEADER PAYULOAD LENGTH AND VERSION. MIGHT BE EASIER TO CHANGE IN PYTHON
void load_firmware(void) {
    int frame_length = 0;
    int read = 0;
    uint32_t rcv = 0;

    uint32_t data_index = 0;
    uint32_t page_addr = FW_INCOMING_BASE;
    uint32_t version = 0;
    uint32_t size = 0;

    // get size
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
    size |= (uint32_t)rcv << 16;

    rcv = uart_read(UART0, BLOCKING, &read);
    data[data_index] = rcv;
    data_index++;
    size |= (uint32_t)rcv << 24;

    // Get version.
    rcv = uart_read(UART0, BLOCKING, &read);
    data[data_index] = rcv;
    data_index++;
    version = (uint32_t)rcv;

    rcv = uart_read(UART0, BLOCKING, &read);
    data[data_index] = rcv;
    data_index++;
    version |= (uint32_t)rcv << 8;

    // Compare to old version and abort if older (note special case for version 0).
    // If no metadata available (0xFFFF), accept version 1
    uint16_t old_version = *fw_version_address;
    if (old_version == 0xFFFF) {
        old_version = 1;
    }

    if (version != 0 && version < old_version) {
        uart_write(UART0, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return;
    } else if (version == 0) {
        // If debug firmware, don't change version
        version = old_version;
    }

    // Write new firmware size and version to Flash
    // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    // uint32_t metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);
    // program_flash((uint8_t *)FW_INCOMING_BASE, (uint8_t *)(&metadata), 4);

    uart_write(UART0, OK); // Acknowledge the metadata.

    // TODO: MAKE THIS READ & FLASH IN CHUNKS
    // SO WE DONT HAVE TO STORE 30KB OF DATA IN RAM

    while (1) {

        // Get two bytes for the length.
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length = (uint32_t)rcv;
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length |= (uint32_t)rcv << 8;

        // Get the number of bytes specified
        for (int i = 0; i < frame_length; ++i) {
            data[data_index] = uart_read(UART0, BLOCKING, &read);
            data_index += 1;
        } // for

        // If we filed our page buffer, program it
        if (data_index == FLASH_PAGESIZE || frame_length == 0) {
            // Try to write flash and check for error
            if (program_flash((uint8_t *)page_addr, data, data_index)) {
                uart_write(UART0, ERROR); // Reject the firmware
                SysCtlReset();            // Reset device
                return;
            }

            // Update to next page
            page_addr += FLASH_PAGESIZE;
            data_index = 0;

            // If at end of firmware, go to main
            if (frame_length == 0) {
                uart_write(UART0, OK);
                break;
            }
        } // if

        uart_write(UART0, OK); // Acknowledge the frame.
    } // while(1)

    uint32_t sign_add = FW_INCOMING_BASE + 4 + 2 + size;
    uint32_t payload_idx = FW_INCOMING_BASE;
    uart_write_str(UART0, "hello");

    if (check_firmware((uint32_t *)FW_INCOMING_BASE) == 0) {
        uart_write_str(UART0, "nice");
    }
    uart_write_str(UART0, "fail");

    // if (verify_signature(&sign_add, &payload_idx, size + 6)) {
    //     erase_partition((uint32_t *)FW_INCOMING_BASE, (uint8_t)64);
    // } else {
    //     move_firmware((uint32_t *)FW_INCOMING_BASE, (uint32_t *)FW_CHECK_BASE, (uint16_t)FW_BASE_SIZE);
    // }
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(void * page_addr, unsigned char * data, unsigned int data_len) {
    uint32_t word = 0;
    int ret;
    int i;

    // Erase next FLASH page
    FlashErase((uint32_t)page_addr);

    // Clear potentially unused bytes in last word
    // If data not a multiple of 4 (word size), program up to the last word
    // Then create temporary variable to create a full last word
    if (data_len % FLASH_WRITESIZE) {
        // Get number of unused bytes
        int rem = data_len % FLASH_WRITESIZE;
        int num_full_bytes = data_len - rem;

        // Program up to the last word
        ret = FlashProgram((unsigned long *)data, (uint32_t)page_addr, num_full_bytes);
        if (ret != 0) {
            return ret;
        }

        // Create last word variable -- fill unused with 0xFF
        for (i = 0; i < rem; i++) {
            word = (word >> 8) | (data[num_full_bytes + i] << 24); // Essentially a shift register from MSB->LSB
        }
        for (i = i; i < 4; i++) {
            word = (word >> 8) | 0xFF000000;
        }

        // Program word
        return FlashProgram(&word, (uint32_t)page_addr + num_full_bytes, 4);
    } else {
        // Write full buffer of 4-byte words
        return FlashProgram((unsigned long *)data, (uint32_t)page_addr, data_len);
    }
}

void boot_firmware(void) {
    uint32_t size = *(int *)FW_INCOMING_BASE;
    uint32_t sign_add = FW_INCOMING_BASE + 4 + 2 + size;
    uint32_t payload_idx = FW_INCOMING_BASE;
    uart_write_str(UART0, "hello");

    if (verify_signature(&sign_add, &payload_idx, size + 6)) {
        erase_partition((uint32_t *)FW_INCOMING_BASE, (uint8_t)64);
    } else {
        move_firmware((uint32_t *)FW_INCOMING_BASE, (uint32_t *)FW_CHECK_BASE, (uint16_t)FW_BASE_SIZE);
    }
    // Check if firmware loaded
    int fw_present = 0;
    for (uint8_t * i = (uint8_t *)FW_CHECK_BASE; i < (uint8_t *)FW_CHECK_BASE + 20; i++) {
        if (*i != 0xFF) {
            fw_present = 1;
        }
    }

    if (!fw_present) {
        uart_write_str(UART0, "No firmware loaded. Please RESET device.\n");
        while (1) {
        } // Reset device
        return;
    }

    // compute the release message address, and then print it
    uint16_t fw_size = *(uint16_t *)FW_CHECK_BASE;

    // WE'LL IMPLEMENT THIS LATER LOL
    // fw_release_message_address = (uint8_t *)(FW_CHECK_BASE + fw_size);
    // uart_write_str(UART0, (char *)fw_release_message_address);

    // verify firmware
    // bad -> stop clear
    // ok -> continue
    if (check_firmware((uint32_t *)FW_CHECK_BASE) == 1) {
        SysCtlReset();
    }

    // aes decrypt and move to p1
    // aes_decrypt_move(FW_CHECK_BASE + 6, fw_size, FW_BASE + 0, &aes_key, &aes_iv);

    // run from FW_BASE
    //  Boot the firmware

    __asm("LDR R0,=0x1000F\n\t"
          "BX R0\n\t");
}

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

// erase from memory start index in length_in_kb nummber of 1kB chunks
uint8_t erase_partition(uint32_t * start_idx, uint8_t length_in_kb) {
    // erase flash memory starting from start and going length amount
    // for (uint32_t offset = 0; offset < length_in_kb; offset++) {

    //     uint32_t* erase_address = (start_idx + (offset * 1024));
    //     if (FlashErase(*(erase_address)) == -1) {
    //         // failed
    //         return 0;
    //     }
    // }
    // // all erased successfully
    // return 1;
}

// run on update after writing incoming FW to P3
uint8_t check_firmware(uint32_t * start_idx) {
    // what do we need to do?
    //  run verify signature
    uint32_t payload_length = *(int *)start_idx + 6; // this is wrong maybe right????
    uint32_t * sign_add = start_idx + 2 + payload_length;
    uint32_t * payload_idx = start_idx;
    if (verify_signature(sign_add, payload_idx, payload_length)) {
        return 1;
    }
    uint16_t new_version = *(uint16_t *)(start_idx + 4);
    uint16_t curr_version = *(uint16_t *)(FW_CHECK_BASE + 4);
    if (new_version > curr_version || new_version == 0) {
        move_firmware((uint32_t *)FW_INCOMING_BASE, (uint32_t *)FW_CHECK_BASE, payload_length);
    } else {
        return 1;
    }
    // check version #
    // thats it for now
    // how to check version number
    // and what parameters do we use
    // confused-ing
    return 0;
}

// return 0 on success, 1 on fail and error
uint8_t verify_signature(uint32_t * signature_idx, uint32_t * payload_idx, uint32_t payload_length) {
    // hash the encrypted payload with SHA256
    // decrypt the 256-byte long base with RSA pub key
    // then compare the two
    uart_write_str(UART0, "hello1");
    wc_InitRsaKey(&pub, NULL);
    wc_RsaPublicKeyDecode(public_key_der, &zero, &pub, sizeof(public_key_der));
    uart_write_str(UART0, "2");

    wc_Sha256Hash((byte *)&payload_idx, payload_length, hash);

    uart_write_str(UART0, "3");
    int decry_sig_len = wc_RsaPSS_VerifyInline((byte *)&signature_idx, 256, decry_sig_arr, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &pub);

    uart_write_str(UART0, "4");

    int result = wc_RsaPSS_CheckPadding(hash, 32, *decry_sig_arr, (word32)decry_sig_len, WC_HASH_TYPE_SHA256);
    uart_write_str(UART0, "5");
    if (result == 0) {
        uart_write_str(UART0, "good");
        return 0;
    }
    uart_write(UART0, result);
    return 1;
}

uint8_t aes_decrypt_move(uint32_t * payload_start, uint16_t length, uint32_t * destination_idx, byte * key, byte * iv) {

    Aes aes;
    uint8_t ret;

    if (length % AES_BLOCK_SIZE != 0) {
        return 1;
    }

    ret = wc_AesSetKey(&aes, key, sizeof(*key), iv, AES_DECRYPTION);

    if (ret != 0) {
        return 1;
    }

    ret = wc_AesCbcDecrypt(&aes, (byte *)&destination_idx, (byte *)&payload_start, length); // I think we need to flip

    if (ret != 0) {
        return 1;
    }

    return 0; // success!
}

void move_firmware(uint32_t * origin_idx, uint32_t * destination_idx, uint16_t length) {
    memcpy(destination_idx, origin_idx, length);
    erase_partition(origin_idx, length / 1024);
}