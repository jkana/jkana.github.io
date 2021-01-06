---
layout: post
title:  "SigReturn-Oriented-Programming-SROP"
date:   2020-11-21

categories: Writeup, CVE
---

Trong quá trình tìm hiểu, mình thấy rất ít tài liệu, writeup tiếng việt về SROP, vì thế bài viết này ra đời...

# SROP là gì ?

Về cơ bản, SROP là kĩ thuật sử dụng syscall để tạo ra các fake signal nhằm thực hiện 1 hành vi nào đó. Tham khảo chi tiết tại: ![https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf](https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf)

## Signal
Khi kernel gửi signal tới process, luồng thực thi của process sẽ tạm ngưng lại và sẽ chuyển sang thực thi signal nhận được. Sau khi signal thực hiện xong, CPU sẽ quay trở lại thực thi tiếp process đó. Mô tả như hình dưới đây 

![](./Images/srop-1.png)

1.Kernel gửi signal tới process.
2.Kernel lưu trạng thái hiện tại của process và return sang user mode sau khi hoàn thành việc lưu trạng thái.
3.Việc thực thi signal được thực hiện ở user mode.
4.Sau khi thực hiện xong signal, kernel sẽ thực hiện gọi sigreturn để trả lại trạng thái của process. Đối với x86, call number của sigreturn có giá trị 0x77. Đối với x64, call number của sigreturn có giá trị 0xf

Một hình minh họa khác. Trong hình minh họa này, process đang thực hiện ở 1 buffer bị ghi đè trên stack. Khi gọi tới 1 signal, kernel sẽ cấp 1 vùng buffer_X để lưu trữ thông tin và thực thi signal đó.

![](./Images/srop-2.png)

## Kịch bản tấn công SROP

### Điều kiện khai thác
- Attacker có khả năng kiểm soát EIP/RIP
- ESP/RSP phải nằm trên vùng data mà attacker có thể kiểm soát được. Ngoài ra NULL bytes không bị cấm trên stack.
- Attacker nắm được địa chỉ của vùng data có thể kiểm soát.
- Attacker nắm được địa chỉ của code thực hiện sigreturn hoặc syscall.

### Phương án khai thác
- Bằng việc fake signal, attacker có thể gọi tới signal **mprotect** để thay đổi quyền truy cập trên bộ nhớ.
- Ngoài ra, attacker có thể dùng signal **execve** để gọi shell


