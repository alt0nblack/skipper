#pragma once

#include <stdio.h>

#ifdef _DEBUG
#define DR_DEBUG(content, ...) { wprintf(content L"\r\n", __VA_ARGS__); }
#else
#define DR_DEBUG(content, ...) { unsigned char nop = 0; }
#endif
