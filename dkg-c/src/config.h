#ifndef CONFIG_H
#define CONFIG_H

#define MAX_MEMBERS  100
#define MIN_MEMBERS  3
#define MEMBERS      5
#define THRESHOLD    2
#define ENTROPY_SIZE 32
#define CURVE_NAME   SECP256K1_NAME

#ifndef USER_INPUT
#define USER_INPUT 0
#endif

#ifndef VERBOSE
#define VERBOSE 1
#endif

#endif