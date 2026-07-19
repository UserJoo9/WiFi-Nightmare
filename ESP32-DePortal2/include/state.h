// include/state.h
#pragma once

// نوع لتحديد وضع المسح الأخير
enum ScanMode
{
    SCAN_MODE_NONE,
    SCAN_MODE_NORMAL,
    SCAN_MODE_ADVANCED
};

// متغير عام لتخزين وضع المسح الأخير
extern ScanMode last_scan_mode;