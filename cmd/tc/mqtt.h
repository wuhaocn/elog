#define IPPROTO_MQTT 188 // Define the protocol number for MQTT

#define MQTT_DEFAULT_PORT 1883 // Define the default port number for MQTT

// Define MQTT packet types
#define MQTT_CONNECT    0x10
#define MQTT_CONNACK    0x20
#define MQTT_PUBLISH    0x30
#define MQTT_PUBACK     0x40
#define MQTT_PUBREC     0x50
#define MQTT_PUBREL     0x60
#define MQTT_PUBCOMP    0x70
#define MQTT_SUBSCRIBE  0x80
#define MQTT_SUBACK     0x90
#define MQTT_UNSUBSCRIBE    0xA0
#define MQTT_UNSUBACK   0xB0
#define MQTT_PINGREQ    0xC0
#define MQTT_PINGRESP   0xD0
#define MQTT_DISCONNECT 0xE0

// Define MQTT command types
#define MQTT_CMD_CONNECT    1
#define MQTT_CMD_PUBLISH    2
#define MQTT_CMD_SUBSCRIBE  3
#define MQTT_CMD_UNKNOWN    0 // If the command type is unknown
