#!/bin/bash

read -p "Static Linker [y/N]: " linker
if [ "${linker}" = "y" ]; then
    aarch64-linux-gnu-gcc main.c -Werror -I install/usr/include install/usr/lib/libseteec.a install/usr/lib/libteec.a -o import-pkcs11
else
    aarch64-linux-gnu-gcc main.c -Werror -I install/usr/include -L install/usr/lib -l seteec -l teec -l dl -o import-pkcs11
fi
