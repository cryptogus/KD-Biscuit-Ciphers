"data unit의 offset"에 대해 정확히 설명드리겠습니다.

## Data Unit이란?
AES-XTS에서 **data unit**은 암호화의 논리적 단위입니다:
- 디스크 섹터 (보통 512바이트 또는 4KB)
- 파일 시스템 블록
- 네트워크 패킷
- 메모리 페이지 등

## Data Unit의 Offset
**data unit 내부에서의 상대적 위치**를 의미합니다.

### 예시로 이해하기
```
Data Unit (4KB 섹터) = 4096 bytes
┌─────────────────────────────────────┐
│ [0][16][32][48]...[4080][4096]     │  <- 바이트 주소
│  0   1   2   3  ...  254   255     │  <- 블록 번호
└─────────────────────────────────────┘
```

### Offset의 의미
```c
// offset = 1024라면
// "이 data unit의 1024바이트 지점부터 시작"

Data Unit 시작: 주소 0
Offset 지점:   주소 1024  <- 여기서부터 암호화 시작
Data Unit 끝:  주소 4095
```

## 절대 주소 vs 상대 주소

### 절대 주소 (전체 저장소 기준)
```
전체 디스크: [섹터0][섹터1][섹터2]...
절대 주소:     0    4096   8192
```

### 상대 주소 (data unit 기준)
```
섹터2 내부:  [0][16][32][48]...[4080]
상대 offset:  0  16  32  48     4080  <- 이것이 XTS offset
```

## 실제 사용 예시
```c
// 섹터 번호 5의 2KB 지점부터 암호화하고 싶다면:

// 1. data unit = 섹터 5 (4KB)
// 2. offset = 2048 (섹터 5 내에서 2KB 지점)

aes_init(context, key, tweak_for_sector5, 4096);
aes_xts_set_offset(context, 2048);  // 섹터 내 2KB 지점
```

## 핵심 포인트
- **Data unit**: 암호화의 논리적 단위 (예: 섹터)
- **Offset**: 그 단위 내에서의 상대적 위치
- **절대 주소가 아닌 상대 주소**

즉, "data unit의 offset"은 **"해당 암호화 단위 내에서 몇 번째 바이트부터 시작할지"**를 의미합니다.

# NIST TEST VECTOR 유의 사항

```txt
COUNT = 213
DataUnitLen = 140
Key = dc0a0e99a0478cb6fcc95860d3b3228990c6deda7a0de80bad774d575ac77f6dd69b1564185f1c0dd8858fe2a840f02755430fe3c0d75389c1519be430e91a11
i = 612365279b821727bdf1d93870cbcdcb
PT = eb8e801a28ed855b54bc147a1d05860f3310
CT = f64e2961254d9d1d3e72daebee55d951c580
```
에서 DataUnitLen는 XTS-AES로 한 번에 처리할 데이터의 크기임. DataUnitLen이 140이란건 140-bit란 뜻이고, 지금 PT가 18바이트인데 총 144-bit임. 즉, PT 뒤에 0(4-bit)이 붙은건 그냥 바이트 단위를 맞춰주기 위함이기 때문에 실제 연산의 대상이 아니다! 즉, 애네가 준 test vector에서 DataUnitLen이란 비트 단위의 input 값을 의미한다!!!

# 그럼 aes-xts는 비트단위로 stealing 할 일이 없다?
맞습니다! **AES-XTS는 비트 단위로 stealing할 일이 없습니다.** 그 이유를 구체적으로 설명드리겠습니다.

## AES-XTS에서 Ciphertext Stealing이 불필요한 이유

### **1. XTS의 기본 설계 철학**
```c
// XTS는 디스크 섹터 암호화를 위해 설계됨
// 디스크 섹터는 항상 고정 크기 (512바이트, 4096바이트 등)
struct disk_sector {
    uint8_t data[512];  // 항상 완전한 블록 크기
};

// 따라서 부분 블록이 발생할 상황이 애초에 없음
```

### **2. 표준 XTS 요구사항**
```c
// IEEE 1619 표준
int xts_encrypt(uint8_t *key, uint8_t *tweak, uint8_t *data, size_t len) {
    // 최소 128비트 (16바이트) 요구
    if (len < 16) {
        return XTS_ERROR_TOO_SHORT;
    }
    
    // 완전한 블록만 처리 (stealing 불필요)
    if (len % 16 != 0) {
        return XTS_ERROR_NON_BLOCK_ALIGNED;
    }
    
    // 모든 블록이 완전하므로 stealing 없이 처리
    for (int i = 0; i < len/16; i++) {
        xts_encrypt_block(&data[i*16], tweak);
        tweak_update(tweak);
    }
}
```

## 다른 모드와의 차이점

### **CBC 모드 (Stealing 필요)**
```c
// CBC는 임의 길이 데이터를 처리해야 함
int cbc_encrypt_with_cts(uint8_t *data, size_t len) {
    size_t complete_blocks = (len - 1) / 16;  // 마지막 블록 제외
    size_t remaining = len - (complete_blocks * 16);
    
    // 완전한 블록들 처리
    for (int i = 0; i < complete_blocks; i++) {
        cbc_encrypt_block(&data[i*16]);
    }
    
    // 마지막 부분 블록 - Ciphertext Stealing 필요!
    if (remaining > 0) {
        ciphertext_stealing(&data[complete_blocks*16], remaining);
    }
}
```

### **XTS 모드 (Stealing 불필요)**
```c
// XTS는 애초에 완전한 블록만 받음
int xts_encrypt_sector(uint8_t *sector_data) {
    // 섹터는 항상 512바이트 = 32개의 완전한 16바이트 블록
    for (int i = 0; i < 32; i++) {
        xts_encrypt_block(&sector_data[i*16], tweak);
        tweak_multiply_by_alpha(tweak);  // 다음 블록용 tweak
    }
    // Stealing이 필요한 상황이 발생하지 않음
}
```

## XTS에서 부분 블록이 없는 이유

### **1. 데이터 단위 (Data Unit) 개념**
```c
// XTS에서 데이터 단위는 전체가 하나의 단위
struct xts_data_unit {
    uint64_t sector_number;    // tweak로 사용
    uint8_t sector_data[512];  // 항상 완전한 크기
};

// 각 섹터는 독립적으로 암호화
// 섹터 내에서는 모든 블록이 연결되어 있음
```

### **2. Tweak 체인**
```c
void xts_encrypt_data_unit(uint8_t *data, size_t blocks, uint64_t sector_num) {
    uint8_t tweak[16];
    generate_initial_tweak(tweak, sector_num);
    
    for (int i = 0; i < blocks; i++) {
        // 각 블록은 완전한 16바이트
        xts_encrypt_block(&data[i*16], tweak);
        
        // 다음 블록을 위해 tweak 업데이트
        tweak_multiply_by_alpha(tweak);
    }
    // 모든 블록이 완전하므로 stealing 불필요
}
```

## 만약 XTS에 Stealing을 적용한다면?

### **문제점들**
```c
// 가상의 XTS-CTS 구현 (실제로는 존재하지 않음)
int xts_encrypt_with_hypothetical_cts(uint8_t *data, size_t len) {
    size_t complete_blocks = len / 16;
    size_t remaining = len % 16;
    
    // 완전한 블록들 처리
    for (int i = 0; i < complete_blocks; i++) {
        xts_encrypt_block(&data[i*16], tweak);
        tweak_multiply_by_alpha(tweak);
    }
    
    if (remaining > 0) {
        // 문제: XTS의 tweak 체인이 깨짐
        // 문제: 디스크 섹터 경계와 맞지 않음
        // 문제: 표준에서 정의되지 않음
        hypothetical_xts_stealing();  // 이런 건 없음!
    }
}
```

## 결론

**AES-XTS에서 비트/바이트 단위 Ciphertext Stealing이 없는 이유**:

1. **설계 목적**: 고정 크기 디스크 섹터 암호화용
2. **표준 요구사항**: 완전한 블록만 처리
3. **Tweak 체인**: 섹터 내 모든 블록이 연결되어 있어야 함
4. **실용성**: 부분 블록이 발생할 실제 상황이 없음

따라서 XTS에서는 **애초에 stealing이 필요한 상황이 발생하지 않도록 설계**되었습니다. 만약 임의 길이 데이터를 암호화해야 한다면, XTS 대신 CBC+CTS나 다른 모드를 사용해야 합니다.

# 그럼 데이터 유닛이 140 비트 등 이런 케이스는 없다?

**맞습니다! 실제로는 140비트 같은 데이터 유닛은 존재하지 않습니다.** 그 이유를 설명드리겠습니다.

## XTS 데이터 유닛의 실제 크기들

### **실제 디스크 섹터 크기**
```c
// 표준 디스크 섹터 크기들 (모두 16바이트의 배수)
#define SECTOR_512B   512    // 512 bytes = 32 * 16 bytes
#define SECTOR_4KB    4096   // 4096 bytes = 256 * 16 bytes  
#define SECTOR_8KB    8192   // 8192 bytes = 512 * 16 bytes

// 모든 표준 섹터 크기는 AES 블록 크기(16바이트)의 정수배
```

### **실제 사용되는 데이터 유닛들**
```c
// 하드 디스크
struct hdd_sector {
    uint8_t data[512];  // 512 bytes (32 blocks)
};

// SSD
struct ssd_page {
    uint8_t data[4096]; // 4KB (256 blocks)
};

// NVMe
struct nvme_sector {
    uint8_t data[512];  // 또는 4096 bytes
};

// 모두 완전한 16바이트 블록들로 구성됨
```

## 140비트 테스트 벡터의 진짜 목적

### **1. 구현 오류 검출**
```c
// 잘못된 구현 예시
int buggy_xts_implementation(uint8_t *data, size_t bits) {
    // 버그: 비트 단위 검증을 안 함
    size_t blocks = bits / 128;  // 140/128 = 1 (정수 나눗셈)
    
    for (int i = 0; i < blocks; i++) {
        xts_encrypt_block(&data[i*16]);  // 16바이트씩 처리
    }
    // 결과: 128비트만 처리하고 12비트 무시 → 버그!
}

// 올바른 구현
int correct_xts_implementation(uint8_t *data, size_t bits) {
    if (bits % 128 != 0) {
        return XTS_ERROR_INVALID_LENGTH;  // 에러 반환
    }
    // 정상 처리...
}
```

### **2. API 오남용 방지**
```c
// 개발자가 실수로 이런 호출을 할 수 있음
void developer_mistake() {
    uint8_t some_data[18] = {0};  // 18바이트 = 144비트
    
    // 실수: 140비트만 암호화하려고 시도
    xts_encrypt(key, tweak, some_data, 140);  // 에러 발생해야 함
}
```

### **3. 표준 준수 검증**
```c
// IEEE 1619 표준 검증
void test_standard_compliance() {
    assert(xts_encrypt(key, tweak, data, 127) == ERROR);  // < 128비트
    assert(xts_encrypt(key, tweak, data, 140) == ERROR);  // 블록 경계 아님
    assert(xts_encrypt(key, tweak, data, 255) == ERROR);  // 블록 경계 아님
    assert(xts_encrypt(key, tweak, data, 256) == SUCCESS); // 2블록, 정상
}
```

## 실제 환경에서 일어나는 일

### **디스크 드라이버 레벨**
```c
// 디스크 I/O는 항상 섹터 단위
int disk_read_sector(uint64_t sector_num, uint8_t *buffer) {
    // 하드웨어가 강제로 512바이트 단위로만 읽음
    return hardware_read(sector_num * 512, buffer, 512);
}

int disk_encrypt_sector(uint64_t sector_num, uint8_t *data) {
    // 입력이 항상 512바이트 = 32개의 완전한 블록
    return xts_encrypt(key, sector_num, data, 512);
}
```

### **파일 시스템 레벨**
```c
// 파일 시스템도 블록 단위로 관리
#define FS_BLOCK_SIZE 4096  // 4KB 블록

struct fs_block {
    uint8_t data[4096];  // 항상 256개의 완전한 AES 블록
};

void encrypt_fs_block(struct fs_block *block) {
    // 4096바이트 = 256 * 16바이트 (완전한 블록들)
    xts_encrypt(key, block_number, block->data, 4096);
}
```

## 만약 140비트 데이터 유닛이 존재한다면?

### **하드웨어적 불가능**
```c
// 디스크 하드웨어는 섹터 단위로만 동작
// 140비트 = 17.5바이트는