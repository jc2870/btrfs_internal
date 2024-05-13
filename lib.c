#include "lib.h"

// CRC32多项式（CRC-32-IEEE 802.3）
#define POLY 0xEDB88320
// CRC-64-ECMA-182生成多项式
#define CRC64_POLY 0x42F0E1EBA9EA3693ULL
static uint64_t crc_table[256];

// 计算一个字节的CRC32值
uint32_t crc32_one_byte(uint32_t crc, uint8_t a)
{
    for(int i = 0; i < 8; ++i)
    {
        if((crc & 0x80000000) != 0)
        {
            crc = (crc << 1) ^ POLY;
        }
        else
        {
            crc <<= 1;
        }
        a <<= 1;
    }
    return crc ^ a;
}

// 计算缓冲区的CRC32值
uint32_t crc32(const uint8_t* buffer, size_t len)
{
    uint32_t crc = 0xFFFFFFFF; // 初始化CRC值为0xFFFFFFFF
    for(size_t i = 0; i < len; ++i)
    {
        crc = crc32_one_byte(crc, buffer[i]);
    }
    return crc ^ 0xFFFFFFFF; // 最终异或，得到正确的CRC值
}


// 初始化查表
static void crc_table_init(void) {
    for (size_t i = 0; i < 256; ++i) {
        uint64_t crc = i;
        for (int j = 0; j < 8; ++j) {
            if (crc & 0x8000000000000000ULL) {
                crc = (crc << 1) ^ CRC64_POLY;
            } else {
                crc <<= 1;
            }
        }
        crc_table[i] = crc;
    }
}

// 计算64位CRC校验值（使用查表法）
uint64_t crc64(const void *data, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint64_t crc = 0xFFFFFFFFFFFFFFFFULL;

    for (size_t i = 0; i < length; ++i) {
        crc = crc_table[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }

    return crc;
}

void crc_init()
{
    crc_table_init();
}