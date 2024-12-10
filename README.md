# Secure Backend with API Endpoints

This project demonstrates the implementation of a secure backend using Express.js, PostgreSQL, JWT, and various security middleware. The main focus is on providing safe API endpoints, user authentication, and protection against common security vulnerabilities like brute force attacks, SQL injection, and XSS.

## Features

- **REST API** with endpoints for user registration, login, data retrieval, and API key management.
- **JSON format** for communication between the client and server.
- **Bcrypt** for securely hashing passwords and API keys.
- **Environment variables** stored in a `.env` file for sensitive information (e.g., database credentials, secret keys).
- **ES6 Fetch** used for data fetching in the client side.
- **JWT stored in HttpOnly cookies** to protect against XSS and CSRF attacks.
- **Token encryption** using AES-256 to secure the JWT.
- **Middleware to authenticate tokens** and ensure protected routes are only accessible to authenticated users.
- **Token blacklist** to manage JWT invalidation (e.g., logout).
- **CORS middleware** with limited origins for cross-origin resource sharing.
- **Rate limiting** to mitigate brute force attacks with `express-rate-limit`.
- **Content Security Policy (CSP)** via `helmet` to prevent XSS attacks and content injection.
- **SQL Injection and XSS protection** using `express-validator`.
