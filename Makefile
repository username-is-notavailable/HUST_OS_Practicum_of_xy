# we assume that the utilities from RISC-V cross-compiler (i.e., riscv64-unknown-elf-gcc and etc.)
# are in your system PATH. To check if your environment satisfies this requirement, simple use 
# `which` command as follows:
# $ which riscv64-unknown-elf-gcc
# if you have an output path, your environment satisfy our requirement.

# ---------------------	macros --------------------------
CROSS_PREFIX 	:= riscv64-unknown-elf-
CC 				:= $(CROSS_PREFIX)gcc
AR 				:= $(CROSS_PREFIX)ar
RANLIB        	:= $(CROSS_PREFIX)ranlib

SRC_DIR        	:= .
OBJ_DIR 		:= obj
SPROJS_INCLUDE 	:= -I.  

HOSTFS_ROOT := hostfs_root
ifneq (,)
  march := -march=
  is_32bit := $(findstring 32,$(march))
  mabi := -mabi=$(if $(is_32bit),ilp32,lp64)
endif

CFLAGS        := -Wall -Werror  -fno-builtin -nostdlib -D__NO_INLINE__ -mcmodel=medany -g -gdwarf-3 -Og -std=gnu99 -Wno-unused -Wno-attributes -fno-delete-null-pointer-checks -fno-PIE $(march) -fno-omit-frame-pointer
COMPILE       	:= $(CC) -MMD -MP $(CFLAGS) $(SPROJS_INCLUDE)

#---------------------	utils -----------------------
UTIL_CPPS 	:= util/*.c

UTIL_CPPS  := $(wildcard $(UTIL_CPPS))
UTIL_OBJS  :=  $(addprefix $(OBJ_DIR)/, $(patsubst %.c,%.o,$(UTIL_CPPS)))


UTIL_LIB   := $(OBJ_DIR)/util.a

#---------------------	kernel -----------------------
KERNEL_LDS  	:= kernel/kernel.lds
KERNEL_CPPS 	:= \
	kernel/*.c \
	kernel/machine/*.c \
	kernel/util/*.c

KERNEL_ASMS 	:= \
	kernel/*.S \
	kernel/machine/*.S \
	kernel/util/*.S

KERNEL_CPPS  	:= $(wildcard $(KERNEL_CPPS))
KERNEL_ASMS  	:= $(wildcard $(KERNEL_ASMS))
KERNEL_OBJS  	:=  $(addprefix $(OBJ_DIR)/, $(patsubst %.c,%.o,$(KERNEL_CPPS)))
KERNEL_OBJS  	+=  $(addprefix $(OBJ_DIR)/, $(patsubst %.S,%.o,$(KERNEL_ASMS)))

KERNEL_TARGET = $(OBJ_DIR)/riscv-pke





#---------------------	spike interface library -----------------------
SPIKE_INF_CPPS 	:= spike_interface/*.c

SPIKE_INF_CPPS  := $(wildcard $(SPIKE_INF_CPPS))
SPIKE_INF_OBJS 	:=  $(addprefix $(OBJ_DIR)/, $(patsubst %.c,%.o,$(SPIKE_INF_CPPS)))


SPIKE_INF_LIB   := $(OBJ_DIR)/spike_interface.a


#---------------------	user   -----------------------
# USER_CPPS 		:= user/app_shell.c

# USER_OBJS  		:= $(addprefix $(OBJ_DIR)/, $(patsubst %.c,%.o,$(USER_CPPS)))

# USER_TARGET 	:= $(HOSTFS_ROOT)/bin/app_shell

USER_LIB  		:= user/user_lib.c

USER_LIB_OBJ    := $(addprefix $(OBJ_DIR)/, $(patsubst %.c,%.o,$(USER_LIB)))

USER_APP_CPPS	:= $(wildcard  user/app/*.c) 

USER_BIN_CPPS	:= $(wildcard  user/bin/*.c)

USER_APP_OBJS     := $(addprefix $(OBJ_DIR)/, $(patsubst %.c,%.o,$(USER_APP_CPPS)))

USER_BIN_OBJS     := $(addprefix $(OBJ_DIR)/, $(patsubst %.c,%.o,$(USER_BIN_CPPS)))

USER_APP_CPPS     := $(basename $(notdir $(USER_APP_CPPS)))

USER_BIN_CPPS     := $(basename $(notdir $(USER_BIN_CPPS)))


USER_APP_TARGET     := $(HOSTFS_ROOT)/app/$(patsubst %.c,%,$(USER_APP_CPPS))

USER_BIN_TARGET     := $(HOSTFS_ROOT)/bin/$(patsubst %.c,%,$(USER_BIN_CPPS))

# USER_E_CPPS 		:= user/app_ls.c user/user_lib.c

# USER_E_OBJS  		:= $(addprefix $(OBJ_DIR)/, $(patsubst %.c,%.o,$(USER_E_CPPS)))

# USER_E_TARGET 	:= $(HOSTFS_ROOT)/bin/app_ls

# USER_M_CPPS 		:= user/app_mkdir.c user/user_lib.c

# USER_M_OBJS  		:= $(addprefix $(OBJ_DIR)/, $(patsubst %.c,%.o,$(USER_M_CPPS)))

# USER_M_TARGET 	:= $(HOSTFS_ROOT)/bin/app_mkdir

# USER_T_CPPS 		:= user/app_touch.c user/user_lib.c

# USER_T_OBJS  		:= $(addprefix $(OBJ_DIR)/, $(patsubst %.c,%.o,$(USER_T_CPPS)))

# USER_T_TARGET 	:= $(HOSTFS_ROOT)/bin/app_touch

# USER_C_CPPS 		:= user/app_cat.c user/user_lib.c

# USER_C_OBJS  		:= $(addprefix $(OBJ_DIR)/, $(patsubst %.c,%.o,$(USER_C_CPPS)))

# USER_C_TARGET 	:= $(HOSTFS_ROOT)/bin/app_cat

# USER_O_CPPS 		:= user/app_echo.c user/user_lib.c

# USER_O_OBJS  		:= $(addprefix $(OBJ_DIR)/, $(patsubst %.c,%.o,$(USER_O_CPPS)))

# USER_O_TARGET 	:= $(HOSTFS_ROOT)/bin/app_echo

# USER_S_CPPS 		:= user/app_test.c user/user_lib.c

# USER_S_OBJS  		:= $(addprefix $(OBJ_DIR)/, $(patsubst %.c,%.o,$(USER_S_CPPS)))

# USER_S_TARGET 	:= $(HOSTFS_ROOT)/bin/app_test

#------------------------targets------------------------
$(OBJ_DIR):
	@-mkdir -p $(OBJ_DIR)	
	@-mkdir -p $(dir $(UTIL_OBJS))
	@-mkdir -p $(dir $(SPIKE_INF_OBJS))
	@-mkdir -p $(dir $(KERNEL_OBJS))
	@-mkdir -p $(dir $(USER_APP_OBJS))
	@-mkdir -p $(dir $(USER_BIN_OBJS))
	
$(OBJ_DIR)/%.o : %.c
	@echo "compiling" $< 
	@$(COMPILE) -c $< -o $@


$(OBJ_DIR)/%.o : %.S
	@echo "compiling" $<
	@$(COMPILE) -c $< -o $@

# $(USER_LIB_OBJ):$(USER_LIB)
# 	@echo "compiling" $<
# 	@$(COMPILE) -c $< -o $@

$(UTIL_LIB): $(OBJ_DIR) $(UTIL_OBJS)
	@echo "linking " $@	...	
	@$(AR) -rcs $@ $(UTIL_OBJS) 
	@echo "Util lib has been build into" \"$@\"
	
$(SPIKE_INF_LIB): $(OBJ_DIR) $(UTIL_OBJS) $(SPIKE_INF_OBJS)
	@echo "linking " $@	...	
	@$(AR) -rcs $@ $(SPIKE_INF_OBJS) $(UTIL_OBJS)
	@echo "Spike lib has been build into" \"$@\"

$(KERNEL_TARGET): $(OBJ_DIR) $(UTIL_LIB) $(SPIKE_INF_LIB) $(KERNEL_OBJS) $(KERNEL_LDS)
	@echo "linking" $@ ...
	@$(COMPILE) $(KERNEL_OBJS) $(UTIL_LIB) $(SPIKE_INF_LIB) -o $@ -T $(KERNEL_LDS)
	@echo "PKE core has been built into" \"$@\"

# $(USER_TARGET): $(OBJ_DIR) $(UTIL_LIB) $(USER_OBJS) $(USER_LIB_OBJ)
# 	@echo "linking" $@	...	
# 	-@mkdir -p $(HOSTFS_ROOT)/bin
# 	@$(COMPILE) --entry=main $(USER_OBJS) $(USER_LIB_OBJ) $(UTIL_LIB)  -o $@
# 	@echo "User app has been built into" \"$@\"
# 	@cp $@ $(OBJ_DIR)

$(USER_APP_TARGET):$(USER_LIB_OBJ) $(UTIL_LIB) $(OBJ_DIR) $(USER_APP_OBJS)
	@for item in $(USER_APP_CPPS);do \
		mkdir -p $(HOSTFS_ROOT)/app; \
		$(COMPILE) --entry=main  obj/user/app/$$item.o  $(USER_LIB_OBJ) $(UTIL_LIB) -o $(HOSTFS_ROOT)/app/$$item;\
		cp $(HOSTFS_ROOT)/app/$$item $(OBJ_DIR);\
		done

$(USER_BIN_TARGET):$(USER_LIB_OBJ) $(UTIL_LIB) $(OBJ_DIR) $(USER_BIN_OBJS)
	@for item in $(USER_BIN_CPPS);do \
		mkdir -p $(HOSTFS_ROOT)/bin; \
		$(COMPILE) --entry=main  obj/user/bin/$$item.o  $(USER_LIB_OBJ) $(UTIL_LIB) -o $(HOSTFS_ROOT)/bin/$$item;\
		cp $(HOSTFS_ROOT)/bin/$$item $(OBJ_DIR);\
		done
	

#	$(foreach i,$(USER_A_CPPS),@$(COMPILE) --entry=main $(addprefix $(OBJ_DIR)/, $(patsubst %.c,%.o,$(i))) $(USER_LIB_OBJ) $(UTIL_LIB) -o $(i))

#$(USER_A_CPPS):$(OBJ_DIR) $(UTIL_LIB)\
	@echo "nolinking" $@ ...\
	-@mkdir -p $(HOSTFS_ROOT)/bin\
	@$(COMPILE) --entry=main $(addprefix $(OBJ_DIR)/, $(patsubst %.c,%.o,$@)) $(UTIL_LIB) -o $@\
	@echo "User app has been built into" \"$@\"\
	@cp $@ $(OBJ_DIR)\


#$(USER_E_TARGET): $(OBJ_DIR) $(UTIL_LIB) $(USER_E_OBJS)\
	@echo "linking" $@	...	\
	-@mkdir -p $(HOSTFS_ROOT)/bin\
	@$(COMPILE) --entry=main $(USER_E_OBJS) $(UTIL_LIB) -o $@\
	@echo "User app has been built into" \"$@\"\
\
$(USER_M_TARGET): $(OBJ_DIR) $(UTIL_LIB) $(USER_M_OBJS)\
	@echo "linking" $@	...	\
	-@mkdir -p $(HOSTFS_ROOT)/bin\
	@$(COMPILE) --entry=main $(USER_M_OBJS) $(UTIL_LIB) -o $@\
	@echo "User app has been built into" \"$@\"\
\
$(USER_T_TARGET): $(OBJ_DIR) $(UTIL_LIB) $(USER_T_OBJS)\
	@echo "linking" $@	...	\
	-@mkdir -p $(HOSTFS_ROOT)/bin\
	@$(COMPILE) --entry=main $(USER_T_OBJS) $(UTIL_LIB) -o $@\
	@echo "User app has been built into" \"$@\"\
\
$(USER_C_TARGET): $(OBJ_DIR) $(UTIL_LIB) $(USER_C_OBJS)\
	@echo "linking" $@	...	\
	-@mkdir -p $(HOSTFS_ROOT)/bin\
	@$(COMPILE) --entry=main $(USER_C_OBJS) $(UTIL_LIB) -o $@\
	@echo "User app has been built into" \"$@\"\
\
$(USER_O_TARGET): $(OBJ_DIR) $(UTIL_LIB) $(USER_O_OBJS)\
	@echo "linking" $@	...	\
	-@mkdir -p $(HOSTFS_ROOT)/bin\
	@$(COMPILE) --entry=main $(USER_O_OBJS) $(UTIL_LIB) -o $@\
	@echo "User app has been built into" \"$@\"\
\
$(USER_S_TARGET): $(OBJ_DIR) $(UTIL_LIB) $(USER_S_OBJS)\
	@echo "linking" $@	...	\
	-@mkdir -p $(HOSTFS_ROOT)/bin\
	@$(COMPILE) --entry=main $(USER_S_OBJS) $(UTIL_LIB) -o $@\
	@echo "User app has been built into" \"$@\"\

-include $(wildcard $(OBJ_DIR)/*/*.d)
-include $(wildcard $(OBJ_DIR)/*/*/*.d)

.DEFAULT_GOAL := $(all)

# test:$(KERNEL_TARGET) $(USER_LIB_OBJ)  $(USER_A_TARGET)
# .PHONY:test

all: $(KERNEL_TARGET) $(USER_APP_TARGET) $(USER_BIN_TARGET) $(USER_LIB_OBJ)
.PHONY:all

run: $(KERNEL_TARGET) $(USER_TARGET) $(USER_E_TARGET) $(USER_M_TARGET) $(USER_T_TARGET) $(USER_C_TARGET) $(USER_O_TARGET) $(USER_S_TARGET)
	@echo "********************HUST PKE********************"
	spike $(KERNEL_TARGET) /bin/app_shell

# need openocd!
gdb:$(KERNEL_TARGET) $(USER_TARGET)
	spike --rbb-port=9824 -H $(KERNEL_TARGET) $(USER_TARGET) &
	@sleep 1
	openocd -f ./.spike.cfg &
	@sleep 1
	riscv64-unknown-elf-gdb -command=./.gdbinit

# clean gdb. need openocd!
gdb_clean:
	@-kill -9 $$(lsof -i:9824 -t)
	@-kill -9 $$(lsof -i:3333 -t)
	@sleep 1

objdump:
	riscv64-unknown-elf-objdump -d $(KERNEL_TARGET) > $(OBJ_DIR)/kernel_dump
	riscv64-unknown-elf-objdump -d $(USER_TARGET) > $(OBJ_DIR)/user_dump

cscope:
	find ./ -name "*.c" > cscope.files
	find ./ -name "*.h" >> cscope.files
	find ./ -name "*.S" >> cscope.files
	find ./ -name "*.lds" >> cscope.files
	cscope -bqk

format:
	@python ./format.py ./

clean:
	rm -fr ${OBJ_DIR} ${HOSTFS_ROOT}/bin ${HOSTFS_ROOT}/app