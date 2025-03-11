# 📡 `API.md` - Zero Trust Website API Documentation

## 📌 **Overview**

This document details the **Zero Trust Website API**, including **RESTful and WebSocket APIs**, authentication mechanisms, and security controls. All API endpoints enforce **Zero Trust principles**, requiring **authentication, authorization, and encrypted communication**.

🔹 **Key API Security Features:**
- ✅ **FIDO2 & WebAuthn authentication for all users**
- ✅ **JWT-based session management with strict expiration policies**
- ✅ **RBAC (Role-Based Access Control) and ABAC (Attribute-Based Access Control)**
- ✅ **Rate limiting and IP-based request throttling**
- ✅ **Secure WebSocket communication for real-time interactions**
- ✅ **Audit logging for all API requests**
- ✅ **End-to-end encryption with TLS 1.3 & mutual TLS (mTLS) for services**

---

## 🌐 **Base URL**
```plaintext
https://api.zero-trust.example.com
```
All API requests must be sent to the above base URL over **HTTPS (TLS 1.3 enforced)**.

---

## 🔑 **Authentication & Security**

### 🔹 **User Authentication (FIDO2 / WebAuthn)**
- **All endpoints require authentication.**
- **FIDO2/WebAuthn** is used for passwordless login.
- **Multi-Factor Authentication (MFA)** enforced for high-privilege actions.
- **JWT tokens** are issued upon successful authentication.

### 🔹 **API Security Policies**
- **Requests require Bearer Token Authentication (JWT).**
- **Strict role-based & attribute-based authorization (RBAC/ABAC).**
- **Rate limiting:**
  - 🚨 **10 requests per second per IP**
  - 🚨 **5 failed login attempts trigger temporary account lock**
- **CORS policy allows only whitelisted domains.**
- **All WebSockets enforce mutual TLS (mTLS) authentication.**

---

## 🏗️ **RESTful API Endpoints**

### 🔹 **User Authentication & Identity**
#### 🔐 **1. Register a new user**
```http
POST /api/auth/register
```
📥 **Request Body (JSON)**
```json
{
    "username": "alice",
    "email": "alice@example.com",
    "fido2_challenge": "base64_encoded_challenge"
}
```
📤 **Response (201 Created)**
```json
{
    "message": "User registered successfully. Complete FIDO2 authentication to login."
}
```

#### 🔐 **2. Login (FIDO2/WebAuthn)**
```http
POST /api/auth/login
```
📥 **Request Body (JSON)**
```json
{
    "username": "alice",
    "fido2_response": "base64_encoded_response"
}
```
📤 **Response (200 OK)**
```json
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5c...",
    "expires_in": 3600
}
```

#### 🔑 **3. Refresh Token**
```http
POST /api/auth/refresh
```
📥 **Request Body (JSON)**
```json
{
    "refresh_token": "old_refresh_token"
}
```
📤 **Response (200 OK)**
```json
{
    "token": "new_access_token",
    "expires_in": 3600
}
```

#### 🔓 **4. Logout**
```http
POST /api/auth/logout
```
📥 **Request Body (JSON)**
```json
{
    "token": "access_token"
}
```
📤 **Response (200 OK)**
```json
{
    "message": "Logged out successfully."
}
```

---

## 🔒 **User & Role Management**
#### 🛂 **5. Get User Details**
```http
GET /api/users/{username}
Authorization: Bearer <JWT>
```
📤 **Response (200 OK)**
```json
{
    "username": "alice",
    "role": "admin",
    "last_login": "2024-02-20T14:32:01Z"
}
```

#### 🛡️ **6. Assign Role to User (Admin Only)**
```http
POST /api/users/{username}/assign-role
Authorization: Bearer <Admin JWT>
```
📥 **Request Body (JSON)**
```json
{
    "role": "moderator"
}
```
📤 **Response (200 OK)**
```json
{
    "message": "Role assigned successfully."
}
```

---

## 📡 **WebSocket API**

### 🔹 **Real-Time Secure Communication**
WebSockets are used for **real-time event streaming, UI updates, and secure messaging**. All WebSocket connections enforce **mutual TLS (mTLS) authentication**.

### 📌 **WebSocket Connection**
```plaintext
wss://api.zero-trust.example.com/ws
```

📥 **Client sends authentication request**
```json
{
    "action": "authenticate",
    "token": "jwt_access_token"
}
```
📤 **Server responds with authentication status**
```json
{
    "status": "authenticated",
    "user": "alice"
}
```

---

### 🔥 **Live Intrusion Alerts**
📥 **Server sends real-time security alerts**
```json
{
    "alert": "Failed login attempt detected from IP 192.168.1.50",
    "timestamp": "2024-02-20T14:35:12Z"
}
```

---

### 📢 **Live Chat Messaging**
📥 **Client sends a message**
```json
{
    "action": "send_message",
    "to": "bob",
    "message": "Hello, Bob!"
}
```
📤 **Server broadcasts message**
```json
{
    "from": "alice",
    "to": "bob",
    "message": "Hello, Bob!",
    "timestamp": "2024-02-20T14:40:00Z"
}
```

---

## 🚀 **Rate Limits & Security Policies**
| **Endpoint**        | **Method** | **Rate Limit** | **Requires Auth?** |
|---------------------|-----------|---------------|--------------------|
| `/api/auth/login`   | `POST`    | 5/min per IP  | ❌ |
| `/api/auth/register` | `POST`   | 2/min per IP  | ❌ |
| `/api/auth/refresh` | `POST`    | 10/min per user | ✅ |
| `/api/users/{user}` | `GET`     | 30/min per token | ✅ |
| `/api/users/{user}/assign-role` | `POST` | 10/hour | ✅ (Admin Only) |

---

## 📜 **Logging & Auditing**
- **All API requests are logged with timestamp, IP, and user agent.**
- **Unauthorized access attempts trigger alerts.**
- **Tamper-proof cryptographic logs stored in append-only format.**

---

## 🛡️ **Error Handling**
| **Status Code** | **Meaning** |
|---------------|------------|
| `200 OK`      | Request successful |
| `201 Created` | Resource successfully created |
| `400 Bad Request` | Invalid input provided |
| `401 Unauthorized` | Authentication failed |
| `403 Forbidden` | Insufficient permissions |
| `429 Too Many Requests` | Rate limit exceeded |
| `500 Internal Server Error` | Unexpected server failure |

---

## 📚 **References & Further Reading**
📖 [Zero Trust Security Model (NIST)](https://www.nist.gov/publications/zero-trust-architecture)\
📖 [WebAuthn and FIDO2 Authentication](https://webauthn.io/)\
📖 [TLS 1.3 Security Enhancements](https://tools.ietf.org/html/rfc8446)

---

## 🎯 **Final Thoughts**
The **Zero Trust API** ensures **secure, scalable, and privacy-respecting web communication**. Every request is **authenticated, authorized, encrypted, and monitored**—eliminating implicit trust and mitigating security risks.

Would you like to add **additional security policies, new endpoints, or further WebSocket capabilities?** 🚀