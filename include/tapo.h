#ifndef TAPO_H
#define TAPO_H
#include <stdbool.h>
#include <stdint.h>

typedef struct TapoDevice TapoDevice;

/* Creates a handle for one bulb. No network traffic happens until the first call below. */
TapoDevice *tapo_device_new(const char *host, const char *email, const char *password);
void tapo_device_free(TapoDevice *device);

/* Every call returns a malloc'd JSON string that must be released with tapo_string_free:
 *   {"ok":true,"state":{...}}  (state only for tapo_get_state)  |  {"ok":false,"error":"..."} */
char *tapo_get_state(TapoDevice *device);
char *tapo_set_power(TapoDevice *device, bool on);
char *tapo_set_brightness(TapoDevice *device, uint8_t percent);
char *tapo_set_color_temp(TapoDevice *device, uint16_t kelvin);
char *tapo_set_hsv(TapoDevice *device, uint16_t hue, uint8_t saturation);
void tapo_string_free(char *s);

#endif
