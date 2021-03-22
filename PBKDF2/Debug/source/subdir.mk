################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../source/isha.c \
../source/main.c \
../source/mtb.c \
../source/pbkdf2.c \
../source/pbkdf2_test.c \
../source/semihost_hardfault.c \
../source/ticktime.c 

OBJS += \
./source/isha.o \
./source/main.o \
./source/mtb.o \
./source/pbkdf2.o \
./source/pbkdf2_test.o \
./source/semihost_hardfault.o \
./source/ticktime.o 

C_DEPS += \
./source/isha.d \
./source/main.d \
./source/mtb.d \
./source/pbkdf2.d \
./source/pbkdf2_test.d \
./source/semihost_hardfault.d \
./source/ticktime.d 


# Each subdirectory must supply rules for building sources it contributes
source/%.o: ../source/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -D__REDLIB__ -DCPU_MKL25Z128VLK4 -DCPU_MKL25Z128VLK4_cm0plus -DFSL_RTOS_BM -DSDK_OS_BAREMETAL -DSDK_DEBUGCONSOLE=0 -DCR_INTEGER_PRINTF -DPRINTF_FLOAT_ENABLE=0 -DSDK_DEBUGCONSOLE_UART -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -I"C:\CU_Files\MCUXpressoIDE_11.2.1_4149\workspace\PBKDF2\board" -I"C:\CU_Files\MCUXpressoIDE_11.2.1_4149\workspace\PBKDF2\source" -I"C:\CU_Files\MCUXpressoIDE_11.2.1_4149\workspace\PBKDF2" -I"C:\CU_Files\MCUXpressoIDE_11.2.1_4149\workspace\PBKDF2\drivers" -I"C:\CU_Files\MCUXpressoIDE_11.2.1_4149\workspace\PBKDF2\CMSIS" -I"C:\CU_Files\MCUXpressoIDE_11.2.1_4149\workspace\PBKDF2\utilities" -I"C:\CU_Files\MCUXpressoIDE_11.2.1_4149\workspace\PBKDF2\startup" -O0 -fno-common -g3 -Wall -Werror -c -fmessage-length=0 -fno-builtin -ffunction-sections -fdata-sections -fmerge-constants -fmacro-prefix-map="../$(@D)/"=. -mcpu=cortex-m0plus -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


