---
title: Tìm hiểu về OAuth2  
published: 2025-05-07
description: "Bài viết tổng hợp tất cả những kiến thức mà mình tìm hiểu được về OAuth2"
image: ""
tags: ["oauth","research"]
category: Research
draft: true
---



## Giới thiệu về OAuth2 

                                                            

## Các vai trò trong OAuth2
- **Resource owner:** là những người dùng có khả năng cấp quyền truy cập, chủ sở hữu của tài nguyên mà ứng dụng muốn lấy.
- **Resource server:** nơi lưu trữ các tài nguyên và sẽ cung cấp các resource khi có request đến các tài nguyên này.
- **Client:** là những ứng dụng bên thứ 3 muốn truy cập vào phần tài nguyên được chia sẻ với tư cách của người sở hữu (resource owner) và tất nhiên trước khi truy cập ứng dụng cần được sự ủy quyền của _user_.
- **Authorization server:** làm nhiệm vụ xác thực, kiểm tra thông tin mà user gửi đến từ đó cấp quyền truy cập cho ứng dụng bằng việc sinh ra các đoạn mã **access token**. Đôi khi _authorization server_ cũng chính là _resource server_.


