#include <Arduino.h>
#include <ESPCrypto.h>

#include <vector>
#include <string>

const char *RSA_PRIVATE_PEM = R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwudwslbzHhgGu
dFb3e6tz3E71iiqpYE5kpdAipKyMlbjIQgCiEFRfZnDNGZJSMEEkFYQDjGx/Q0wu
mZxgI52rIDW3ZQcp2LqMg16JesUUMv7WW/EEhOX7yQjth2uZVHio3sKanteLjG0s
NPbyMfG3oGp1m6m75kovsm/KF6/stftPmqhbJSD9vfeDF9NQDw1nsnxY1X8an4cl
clidYssFPoD+mImoKxX+y+GLTcsbY+RLRV1DK5PFKWSVZ3UHwdOp9OEZhNgXgCQ2
o8IE9d7Be2PbzCmgYQGPekRehZwf/q5bhnS00dT+/qwcwlA8sra2Po7H34XtjDOK
IOCjkMuhAgMBAAECggEAAgG3mnlVdu3dHVuB1KE+svvt7kN+34R8mg+jRjluIicz
EscOax4Erz6iX5nU5leuQwLMMx7IPpuyL5dGm3WGvUzff0ZyPIs9obR+LCZ3kBan
e8yjIc+BLbOR2oyemqjxuSJ/vYdkitech74kOF97z1TO0Ki6ASxeFvOPlGZiH4Me
pxvHMJ3LVW3UBLOJRnpM5/sIyVhyj3ANHKkEU2yIe6qvzKo5sRWI/NtID87wi36Y
LbWA7zCHqXxenyawhHWs1a9757UQKh8Gzd+qX6M5jeIWNgdVMeTPtW8gMN9+raRH
2nAYOBKMTgl5rFB+KYxA47VCEHPq5RmlOFf5GY3HSQKBgQDgumgxejxK3P2bFDee
znpBrqvTPRAbAa02Y+rcBb0tMt3QeFuuvvF9+kkJxVZk6HKID933Vo88tr6p4qDx
pRE2lK+wgk90mBcsGH5FOas9VlJspXeFMwcPsaznmX1gP8otYo+HH037sT9KqP1N
N/l+cv8TE9KqLq6uhzlgTYhZZQKBgQDJUXN+e6liSseLyBHsJRL466xS3GSVu0fI
22Z3c9x158Mz0JeqW0zywjJfdDTa9JJpXzuaNFlPMi7VsicB0JeDrKOlfOcdBvDv
jUWRNzgaTPQSEAQROmDnhOAgDXCCHw7k1Pnpr2VU42jnoXc3aJKKUnLC9I7jiXkE
IF2EDbfjjQKBgA1DczrYWA6jFGS+wLmivhx6TrHc/MJbSvnW09nAjPXJ9sWDFQYv
RtmEmCL3fq3d+kSFizg556JRttcYBR+9+lIaXHQyfLYI8/UqTOmRCcZI/fxjl7ZI
2LXYargQmxG/MhOTqZz0AApG39FsP+b60sLfzqY1mU1qC+1JFd3VNaLxAoGBAI9h
Z3Rp9pV+1OgFMl6ReRW4JB9PwIOzwsiXGj9xUU7YJfq9UYePRxqOnPnG9e4Lyksp
/HUzW3hAMYMZQxbTzVWGm3a9oozV6Lt0TlvCjD6PGDXVGlB615GM3WN2ru692Am6
ddOti+oNnSV7pkDcRaImXn3jV/FOc9YwhuoKKzHxAoGAMsH96Qa4X2fKpd7qCG+V
MXMST6MY2rWR+UqNHfd8FCJc8zMERm8yeibG6CxdZQkN4VBoq5kj4ZCiPkSmhWbQ
Gtz/xpPPMUrpRSy8QXQHEGbSBelyK3bgpDukTt90qgqj+2Emvna5tmZrPS3bxx1l
ZpIBKrSVJRXd+g0+Ykq17jc=
-----END PRIVATE KEY-----)";

const char *RSA_PUBLIC_PEM = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsLncLJW8x4YBrnRW93ur
c9xO9YoqqWBOZKXQIqSsjJW4yEIAohBUX2ZwzRmSUjBBJBWEA4xsf0NMLpmcYCOd
qyA1t2UHKdi6jINeiXrFFDL+1lvxBITl+8kI7YdrmVR4qN7Cmp7Xi4xtLDT28jHx
t6BqdZupu+ZKL7Jvyhev7LX7T5qoWyUg/b33gxfTUA8NZ7J8WNV/Gp+HJXJYnWLL
BT6A/piJqCsV/svhi03LG2PkS0VdQyuTxSlklWd1B8HTqfThGYTYF4AkNqPCBPXe
wXtj28wpoGEBj3pEXoWcH/6uW4Z0tNHU/v6sHMJQPLK2tj6Ox9+F7YwziiDgo5DL
oQIDAQAB
-----END PUBLIC KEY-----)";

const char *ECC_PRIVATE_PEM = R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP0pKFycEBq/Ni+ZHDktdahCYFm8UnFnBXLEvaGpRCAxoAoGCCqGSM49
AwEHoUQDQgAEIN0ZqE/X7JvEH6W+Z6VcVpZYiT/GIuWpNdrP2f4GvtZYKkeYrhXD
idn1+qYo+jGWUwmCdbo0yKmpDYwmy3/BnQ==
-----END EC PRIVATE KEY-----)";

const char *ECC_PUBLIC_PEM = R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIN0ZqE/X7JvEH6W+Z6VcVpZYiT/G
IuWpNdrP2f4GvtZYKkeYrhXDidn1+qYo+jGWUwmCdbo0yKmpDYwmy3/BnQ==
-----END PUBLIC KEY-----)";

String bytesToHex(const std::vector<uint8_t> &bytes) {
    static const char *HEX_DIGITS = "0123456789ABCDEF";
    String out;
    for (uint8_t b : bytes) {
        out += HEX_DIGITS[(b >> 4) & 0x0F];
        out += HEX_DIGITS[b & 0x0F];
    }
    return out;
}

String statusText(const CryptoStatusDetail &status) {
    if (status.ok()) {
        return "ok";
    }
    if (status.message.length() > 0) {
        return status.message;
    }
    return String(toString(status.code));
}

void logCaps() {
    CryptoCaps caps = ESPCrypto::caps();
    Serial.printf("HW accel → SHA:%s AES:%s GCM:%s\n",
                  caps.shaAccel ? "yes" : "no",
                  caps.aesAccel ? "yes" : "no",
                  caps.aesGcmAccel ? "yes" : "no");
}

void setup() {
    Serial.begin(115200);
    delay(200);

    // Tighten policy (PBKDF2 iterations >= 2048 by default here)
    CryptoPolicy pol = ESPCrypto::policy();
    pol.minPbkdf2Iterations = 2048;
    ESPCrypto::setPolicy(pol);

    logCaps();

    // Secure key material that zeroizes on scope exit
    SecureBuffer key(32);
    for (size_t i = 0; i < key.size(); ++i) {
        key.raw()[i] = static_cast<uint8_t>(0xA0 + i);
    }

    // HMAC-SHA256
    std::vector<uint8_t> msg = {'a', 'p', 'i'};
    auto hmac = ESPCrypto::hmac(ShaVariant::SHA256, CryptoSpan<const uint8_t>(key.raw()), CryptoSpan<const uint8_t>(msg));
    Serial.printf("HMAC-SHA256: %s (status=%s)\n", bytesToHex(hmac.value).c_str(), statusText(hmac.status).c_str());

    // HKDF derive two subkeys
    std::vector<uint8_t> salt = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> info = {'h', 'a', 'n', 'd', 's', 'h', 'a', 'k', 'e'};
    auto hkdf = ESPCrypto::hkdf(ShaVariant::SHA256, CryptoSpan<const uint8_t>(salt), CryptoSpan<const uint8_t>(key.raw()), CryptoSpan<const uint8_t>(info), 32);
    Serial.printf("HKDF key: %s (status=%s)\n", bytesToHex(hkdf.value).c_str(), statusText(hkdf.status).c_str());

    // PBKDF2 (policy-enforced iterations)
    std::vector<uint8_t> passwordSalt = {0x10, 0x20, 0x30, 0x40, 0x50};
    auto pbkdf2 = ESPCrypto::pbkdf2("wifi-password", CryptoSpan<const uint8_t>(passwordSalt), pol.minPbkdf2Iterations, 32);
    Serial.printf("PBKDF2: %s (status=%s)\n", bytesToHex(pbkdf2.value).c_str(), statusText(pbkdf2.status).c_str());

    // AES-CTR streaming demo
    std::vector<uint8_t> ctrNonce(16, 0x00);
    for (size_t i = 0; i < ctrNonce.size(); ++i) {
        ctrNonce[i] = static_cast<uint8_t>(i);
    }
    std::vector<uint8_t> streamInput = {'s', 't', 'r', 'e', 'a', 'm', '-', 'c', 't', 'r'};
    auto ctrOut = ESPCrypto::aesCtrCrypt(key.raw(), ctrNonce, streamInput);
    Serial.printf("AES-CTR cipher: %s (status=%s)\n", bytesToHex(ctrOut.value).c_str(), statusText(ctrOut.status).c_str());
    auto ctrPlain = ESPCrypto::aesCtrCrypt(key.raw(), ctrNonce, ctrOut.value);
    Serial.printf("AES-CTR plain: %s (status=%s)\n",
                  String(reinterpret_cast<const char *>(ctrPlain.value.data()), ctrPlain.value.size()).c_str(),
                  statusText(ctrPlain.status).c_str());

    // RSA sign/verify
    std::vector<uint8_t> firmware = {'f', 'w', '-', '1', '.', '0'};
    auto rsaSig = ESPCrypto::rsaSign(std::string(RSA_PRIVATE_PEM), CryptoSpan<const uint8_t>(firmware), ShaVariant::SHA256);
    Serial.printf("RSA sig bytes: %u (status=%s)\n", static_cast<unsigned>(rsaSig.value.size()), statusText(rsaSig.status).c_str());
    auto rsaVerify = ESPCrypto::rsaVerify(std::string(RSA_PUBLIC_PEM), CryptoSpan<const uint8_t>(firmware), CryptoSpan<const uint8_t>(rsaSig.value), ShaVariant::SHA256);
    Serial.printf("RSA verify: %s (status=%s)\n", rsaVerify.ok() ? "ok" : "fail", statusText(rsaVerify.status).c_str());

    // ECDSA sign/verify
    auto eccSig = ESPCrypto::eccSign(std::string(ECC_PRIVATE_PEM), CryptoSpan<const uint8_t>(firmware), ShaVariant::SHA256);
    Serial.printf("ECC sig bytes: %u (status=%s)\n", static_cast<unsigned>(eccSig.value.size()), statusText(eccSig.status).c_str());
    auto eccVerify = ESPCrypto::eccVerify(std::string(ECC_PUBLIC_PEM), CryptoSpan<const uint8_t>(firmware), CryptoSpan<const uint8_t>(eccSig.value), ShaVariant::SHA256);
    Serial.printf("ECC verify: %s (status=%s)\n", eccVerify.ok() ? "ok" : "fail", statusText(eccVerify.status).c_str());
}

void loop() {
    vTaskDelay(pdMS_TO_TICKS(1000));
}
