# KBC OpenSSL 3 provider
#
#   make            → kbcprov.so 와 테스트 프로그램 빌드
#   make test       → 테스트 실행
#   make list       → openssl CLI 로 등록된 알고리즘 확인
#   make install    → 시스템 ossl-modules 디렉터리에 설치 (sudo 필요)

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -fPIC
LDFLAGS ?=
LIBS     = -lcrypto

MODULE   = kbcprov.so
SRCS     = KBCprov.c kbc_ciphercommon.c kbc_lea.c ../src/lea/lea.c
OBJS     = $(SRCS:.c=.o)

MODULESDIR = $(shell openssl version -m | sed 's/.*"\(.*\)"/\1/')

.PHONY: all test list install clean

all: $(MODULE) test_kbcprov

$(MODULE): $(SRCS)
	$(CC) $(CFLAGS) -shared -o $@ $(SRCS) $(LDFLAGS) $(LIBS)

test_kbcprov: test_kbcprov.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

test: all
	./test_kbcprov

# provider-path 로 현재 디렉터리를 가리켜서 설치 없이 확인
list: $(MODULE)
	openssl list -provider-path . -provider kbcprov -providers
	openssl list -provider-path . -provider kbcprov -cipher-algorithms

install: $(MODULE)
	install -m 0755 $(MODULE) $(MODULESDIR)/

clean:
	rm -f $(MODULE) test_kbcprov $(OBJS)
