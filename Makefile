GCC_BIN=`xcrun --sdk iphoneos --find clang`
GCC=$(GCC_BASE) -arch arm64
SDK=`xcrun --sdk iphoneos --show-sdk-path`

CFLAGS = -lobjc
GCC_BASE = $(GCC_BIN) -Os $(CFLAGS) -isysroot $(SDK) -F$(SDK)/System/Library/Frameworks -F$(SDK)/System/Library/PrivateFrameworks

all: libobjc_trace

libobjc_trace: objc_trace.m
	$(GCC) -shared -o $@.dylib $^
	ldid -Sent.xml $@.dylib

clean:
	rm -f *.o objc_trace.dylib