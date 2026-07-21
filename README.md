# Secure Node.js Express Authentication Boilerplate

A production-ready authentication backend featuring **JWT (JSON Web Tokens)** and **Google OAuth2** integration. This project is built with a "security-first" mindset, implementing various middleware to protect against common web vulnerabilities.

## 🛡️ Security Features

- **HTTPS Required**: Configured to run over TLS/SSL.
- **Rate Limiting**: Protection against brute-force attacks on sensitive routes.
- **Data Sanitization**: Prevents NoSQL Injection and Parameter Pollution.
- **Security Headers**: Uses `helmet` and disables `x-powered-by` to hide server tech stacks.
- **Bcrypt Hashing**: Secure password storage with salt rounds.
- **Timing Attack Mitigation**: Uses a dummy hash comparison for non-existent users to prevent username enumeration.
- **Input Validation**: Strict schema enforcement using `Joi`.

## 🚀 Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: MongoDB (via Mongoose)
- **Authentication**: Passport.js (Google Strategy) & JWT
- **Validation**: Joi & mongo-sanitize

## 📋 Prerequisites

- Node.js installed
- MongoDB instance (Local or Atlas)
- Google Cloud Console credentials (for OAuth)
- SSL Certificates (`key.pem` and `cert.pem`)

## ⚙️ Environment Variables

Create a `.env` file in the root directory and add:

```env
MONGO_URL=your_mongodb_connection_string
ACCESS_TOKEN_SECRET=your_jwt_access_secret
REFRESH_TOKEN_SECRET=your_jwt_refresh_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```
Clone the repo:
```
git clone https://github.com/giorgi-bezhiashvili/Register-and-login.git](https://github.com/giorgi-bezhiashvili/Register-and-login.git
cd Register-and-login
```
Install dependencies:
```
npm install
```
SSL Setup (Development):
```
openssl req -nodes -new -x509 -keyout key.pem -out cert.pem
```
run:
```
npm run devStart

```
⚠️ Important Note

The current implementation stores refreshTokens in a local array. For a production environment, it is highly recommended to migrate these to a Redis store or a database collection to ensure tokens persist through server restarts.
