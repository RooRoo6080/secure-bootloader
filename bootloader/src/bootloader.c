/*
Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
Approved for public release. Distribution unlimited 23-02181-25.


Format of protected firmware output:
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

Standards used:
 - AES-128; CBC mode
    * no need for anything more complicated (GCM) that includes authenticity
    * speed benefits of CTR would go unused
 - SHA256 hashing; PSS
 - RSA 2048-bit encryption

*/

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bootloader.h"

#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/sha.h"

#include "inc/hw_flash.h"
#include "inc/hw_memmap.h"
#include "inc/hw_types.h"
#include "inc/tm4c123gh6pm.h"

#include "driverlib/adc.h"

#include "driverlib/eeprom.h"
#include "driverlib/flash.h"
#include "driverlib/interrupt.h"
#include "driverlib/sysctl.h"

#include "driverlib/gpio.h"
#include "uart/uart.h"

#include "keys.h"

void load_firmware(void);
void boot_firmware(void);
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);
void erase_partition(uint32_t, uint8_t);
uint8_t verify_signature(uint32_t, uint32_t, uint32_t, uint16_t, uint32_t);
uint8_t move_and_decrypt(uint32_t, uint32_t, uint16_t);
uint8_t move_firmware(uint32_t, uint32_t, uint16_t);

#define METADATA_BASE 0xFC00
#define METADATA_CHECK_BASE 0x28000
#define METADATA_INCOMING_BASE 0x30000
#define FW_BASE 0x10000
#define FW_CHECK_BASE 0x18000
#define FW_INCOMING_BASE 0x20000

#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

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

const uint32_t canary_global = 0xDEADBEEF;

void check_canary(uint32_t canary) {
    if (canary != canary_global) {
        uart_write_str(UART0, "Pls no stack buffer overflow attacks ty fam\n");
        SysCtlReset();
    }
}

int main(void) {

    volatile uint32_t canary = canary_global;

    // THIS MAY BRICK THE TIVA
    // DO NOT RUN UNCOMMENTED UNLESS YOU HAVE A WAY TO UNBRICK IT

    // HWREG(FLASH_FMA) = 0x75100000;
    // HWREG(FLASH_FMD) = HWREG(FLASH_BOOTCFG) & 0x7FFFFFFC;
    // HWREG(FLASH_FMC) = FLASH_FMC_WRKEY | FLASH_FMC_COMT;

    SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_EEPROM0)) {
    }
    EEPROMInit();
    EEPROMProgram((uint32_t *)aes_key, 0x200, sizeof(aes_key));
    EEPROMProgram((uint32_t *)rsa_pub_key, 0x400, sizeof(rsa_pub_eeprom));

    for (int i = 0; i < 16; i++) {
        aes_key[i] = '\0';
    }
    for (int i = 0; i < 294; i++) {
        rsa_pub_key[i] = '\0';
    }

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
        uart_write_str(UART0, "Message length over 1kb\n");
        uart_write(UART0, ERROR);
        SysCtlReset();
    }
    for (int i = 0; i < message_length; i++) {
        rcv = uart_read(UART0, BLOCKING, &read);
        data[data_index] = rcv;
        data_index++;
    }

    uint16_t old_version = *(uint16_t *)(METADATA_BASE + 2);
    if (old_version == 0xFFFF) {
        old_version = 1;
    }

    if (version != 0 && version < old_version) {
        uart_write_str(UART0, "Error: Old firmware version");
        uart_write(UART0, ERROR);
        SysCtlReset();
        return;
    } else if (version == 0) {
        data[2] = old_version;
    }

    data[data_index] = '\0';
    data_index++;

    if (program_flash((uint32_t *)METADATA_INCOMING_BASE, data, data_index)) {
        uart_write(UART0, ERROR);
        SysCtlReset();
        return;
    }
    check_canary(canary);

    data_index = 0;

    uart_write(UART0, OK);

    while (1) {

        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length = (uint32_t)rcv;
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length |= (uint32_t)rcv << 8;

        for (int i = 0; i < frame_length; ++i) {
            data[data_index] = uart_read(UART0, BLOCKING, &read);
            data_index += 1;
        }

        if (data_index == FLASH_PAGESIZE || frame_length == 0) {
            if (program_flash((uint8_t *)page_addr, data, data_index)) {
                uart_write(UART0, ERROR);
                SysCtlReset();
                return;
            }

            page_addr += FLASH_PAGESIZE;
            data_index = 0;

            if (frame_length == 0) {
                uart_write(UART0, OK);
                break;
            }
        }

        check_canary(canary);
        uart_write(UART0, OK);
    }
}

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

void boot_firmware(void) {
    volatile uint32_t canary = canary_global;

    int incoming_fw_present = 0;
    if (*(uint32_t *)METADATA_INCOMING_BASE != 0xFFFFFFFF) {
        incoming_fw_present = 1;
    }

    if (incoming_fw_present) {
        uint16_t size = *(uint16_t *)METADATA_INCOMING_BASE;
        uint16_t message_length = *(uint16_t *)(METADATA_INCOMING_BASE + 4);
        uint32_t sign_add = FW_INCOMING_BASE + size;

        if (verify_signature(sign_add, FW_INCOMING_BASE, size, message_length, METADATA_INCOMING_BASE) == 0) {

            erase_partition(METADATA_CHECK_BASE, 2);
            erase_partition(FW_CHECK_BASE, 31);

            if (move_firmware(METADATA_INCOMING_BASE, METADATA_CHECK_BASE, 2) || move_firmware(FW_INCOMING_BASE, FW_CHECK_BASE, 31)) {
                uart_write_str(UART0, "Failed to move firmware to check partition\n");
                SysCtlReset();
            }
        } else {
            uart_write_str(UART0, "Incoming signature verification failed. Booting previous firmware\n");
        }
        erase_partition(METADATA_INCOMING_BASE, 2);
        erase_partition(FW_INCOMING_BASE, 31);
    }

    if (*(uint32_t *)METADATA_CHECK_BASE == 0xFFFFFFFF) {
        uart_write_str(UART0, "No firmware found in check partition\n");
        SysCtlReset();
    }

    uint16_t size_check = *(uint16_t *)METADATA_CHECK_BASE;
    uint16_t message_length_check = *(uint16_t *)(METADATA_CHECK_BASE + 4);
    uint32_t sign_add_check = FW_CHECK_BASE + size_check;

    if (verify_signature(sign_add_check, FW_CHECK_BASE, size_check, message_length_check, METADATA_CHECK_BASE) == 0) {
        erase_partition(METADATA_BASE, 2);
        erase_partition(FW_BASE, 31);

        if (move_firmware(METADATA_CHECK_BASE, METADATA_BASE, 2)) {
            uart_write_str(UART0, "Failed moving metadata to base\n");
            SysCtlReset();
        }

        if (move_and_decrypt(FW_CHECK_BASE, FW_BASE, 31)) {
            uart_write_str(UART0, "Failed moving and decrypting firmware to base\n");
            SysCtlReset();
        }

        uart_write_str(UART0, "Booting firmware...\n");
        nl(UART0);

        uart_write_str(UART0, (char *)(METADATA_BASE + 6));
        nl(UART0);

        check_canary(canary);

        __asm("LDR R0,=0x10001\n\t"
              "BX R0\n\t");

    } else {
        uart_write_str(UART0, "Firmware in check partition failed signature verification\n");
        SysCtlReset();
    }
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

void erase_partition(uint32_t start_idx, uint8_t length_in_kb) {
    for (int i = 0; i < length_in_kb; i++) {
        uint32_t erase = start_idx + (i * 1024);
        FlashErase(erase);
    }
}

uint8_t verify_signature(uint32_t signature_idx, uint32_t payload_idx, uint32_t payload_length, uint16_t message_length, uint32_t metadata) {
    nl(UART0);

    volatile uint32_t canary = canary_global;
    inOut = 0;

    wc_InitRsaKey(&pub, NULL);

    EEPROMRead(rsa_pub_eeprom, 0x400, sizeof(rsa_pub_eeprom));
    wc_RsaPublicKeyDecode((byte *)rsa_pub_eeprom, &inOut, &pub, 294);
    for (int i = 0; i < 294; i++) {
        rsa_pub_eeprom[i] = '\0';
    }

    wc_InitSha256(sha256);
    wc_Sha256Update(sha256, (byte *)metadata, message_length + 6);
    wc_Sha256Update(sha256, (byte *)payload_idx, payload_length);
    wc_Sha256Final(sha256, hash);

    memcpy(signature_buffer, (byte *)signature_idx, 256);

    int decry_sig_len = wc_RsaPSS_VerifyInline(signature_buffer, 256, &decry_sig_arr, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &pub);
    if (decry_sig_len > 0) {
    } else {
        uart_write_str(UART0, "decry_sig_len < 0, failed verification\n");
        wc_FreeRsaKey(&pub);
        wc_Sha256Free(sha256);
        return 1;
    }

    int result = wc_RsaPSS_CheckPadding(hash, 32, decry_sig_arr, (word32)decry_sig_len, WC_HASH_TYPE_SHA256);
    if (result == 0) {
        wc_FreeRsaKey(&pub);
        wc_Sha256Free(sha256);
        check_canary(canary);
        return 0;
    }
    wc_FreeRsaKey(&pub);
    wc_Sha256Free(sha256);
    return 1;
}

uint8_t move_and_decrypt(uint32_t origin_idx, uint32_t destination_idx, uint16_t length_in_kb) {
    Aes aes;
    volatile uint32_t canary = canary_global;

    EEPROMRead(aes_key_eeprom, 0x200, sizeof(aes_key_eeprom));

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
