# 加密模块

## KEY

### verify_message

    1. 从 message和sig 获取 publicKey 和是否压缩；
    2. 从 publicKey 获取地址
    3. 对消息两次hash（sha-256）
    4. 校验签名散列值（digest）

```
address: 地址

sig: 签名

message: 消息

```

### MyVerifyingKey

继承自`ecdsa.VerifyingKey` 实现了`from_signature`

#### from_signature

从签名中获取公钥（VerifyingKey）--> publicKey


### 秘钥加解密

`pw_encode(s, password)` 加密：采用AES256

`pw_decode(s, password)` 解密：采用AES256
