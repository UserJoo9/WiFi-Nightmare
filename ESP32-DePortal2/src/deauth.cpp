#include <Arduino.h>

// دالة تجاوز الفحص الأمني (ضرورية للحقن)
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3)
{
  return 0; // تجاوز
}