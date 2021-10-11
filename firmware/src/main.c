/*******************************************************************************
  Main Source File

  Company:
    Microchip Technology Inc.

  File Name:
    main.c

  Summary:
    This file contains the "main" function for a project.

  Description:
    This file contains the "main" function for a project.  The
    "main" function calls the "SYS_Initialize" function to initialize the state
    machines of all modules in the system
 *******************************************************************************/

// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************

#include <stddef.h>                     // Defines NULL
#include <stdbool.h>                    // Defines true
#include <stdlib.h>                     // Defines EXIT_FAILURE
#include "definitions.h"                // SYS function prototypes

#include "cryptoauthlib.h"

extern ATCAIfaceCfg atsha204a_0_init_data;

// 用户的自定义随机种子，用于通过Nonce生成随机数
const uint8_t nonce_in[20] = {
    0x01, 0x23, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
};

// 用户的SecureKey, 和写入到SHA204A芯片中的密码一致。
// 基于安全考虑，实际使用时需要对这个Key做一些处理，比如打散或用异或转化，使用时再组合恢复
const uint8_t key0[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// 软件计算SHA256值时需要附加的参数
uint8_t mac_bytes[24] = {
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEE,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x23, 0x00, 0x00,
};

// *****************************************************************************
// *****************************************************************************
// Section: Main Entry Point
// *****************************************************************************
// *****************************************************************************

int main ( void )
{
    ATCA_STATUS status;
    uint8_t sn[9];
    uint8_t challenge[32];
    uint8_t digest[32];
    uint8_t sha2_input[88];
    uint8_t mac_sw[32];

    /* Initialize all modules */
    SYS_Initialize ( NULL );

    printf ("\r\nInitial CryptoAuthLib: \r\n");

    // Inititalize CryptoAuthLib
    status = atcab_init (&atsha204a_0_init_data);
    if (status != ATCA_SUCCESS) {
        printf ("\tFail\r\n");
        LED_Off();
        return ( EXIT_FAILURE );
    }

    printf ("\tSuccess\r\n");
    LED_On();

    status = atcab_read_serial_number (sn);
    if (status == ATCA_SUCCESS) {
        atcab_printbin_label ("Seriel Number:\r\n", sn, 9);
    }

    // 获取随机数
    status = atcab_nonce_rand (nonce_in, challenge);
    if (status != ATCA_SUCCESS) {
        printf ("Nonce Fail\n");
        return ATCA_FUNC_FAIL;
    }
    challenge[0] ^= 0x21;
    atcab_printbin_label ("Challenge:\r\n", challenge, 32);

    // 获取器件的MAC值，使用Slot0的Key
    status = atcab_mac (0x00, 0, challenge, digest);
    if (status != ATCA_SUCCESS) {
        printf ("Slot 0 GetMac Fail\n");
        return ATCA_FUNC_FAIL;
    }
    atcab_printbin_label ("Digest:\r\n", digest, 32);

    // 使用软件SHA256算法计算MAC值
    memcpy (sha2_input, key0, 32);
    memcpy (sha2_input + 32, challenge, 32);
    memcpy (sha2_input + 64, mac_bytes, 24);
    status = atcac_sw_sha2_256 (sha2_input, 88, mac_sw);
    if (status != ATCA_SUCCESS) {
        printf ("Get SW Mac Fail\n");
        return ATCA_FUNC_FAIL;
    }
    atcab_printbin_label ("SW Digest:\r\n", mac_sw, 32);

    // 比较硬件和软件的结果是否一致，如果一致则证明外部的SHA204A是真正授权的
    if (memcmp (mac_sw, digest, 32) == 0) {
        printf ("Slot 0 CheckMac PASS\n");
    }

    atcab_release();

    while ( true ) {
        /* Maintain state machines of all polled MPLAB Harmony modules. */
        SYS_Tasks ( );
        hal_delay_ms (200);
        LED_Toggle();
    }

    /* Execution should not come here during normal operation */

    return ( EXIT_FAILURE );
}


/*******************************************************************************
 End of File
*/

