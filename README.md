# LocalEventsHub

A secure and user-friendly platform for discovering, creating, and managing local events. Built with Node.js, Express, and MongoDB, the application prioritizes 
security and simplicity.

---

## Table of Contents
1. [Overview](#overview)
2. [Features](#features)
3. [Tech Stack](#tech-stack)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Security Features](#security-features)
7. [Future Enhancements](#future-enhancements)
8. [License](#license)

---

## Overview

LocalEventsHub is designed to connect people through local events while maintaining a secure and private user experience. It allows users to:
- Discover events in their area.
- Create and manage their own events.
- Interact with other users securely.

---

## Features

- **Event Management**: Create, edit, and delete events with details like title, description, date, location, and category.
- **User Authentication**: Secure login and registration with JWT-based authentication.
- **Role-Based Access Control (RBAC)**: Event creators can manage their events, while general users can only view and express interest.
- **Rate Limiting**: Prevent brute-force attacks and excessive requests.
- **Account Lockout**: Automatically locks accounts after multiple failed login attempts.
- **Token Versioning**: Ensures secure logout by invalidating old tokens.

---

## Tech Stack

- **Backend**: Node.js, Express
- **Database**: MongoDB, Mongoose
- **Security**: Helmet, bcrypt, JSON Web Tokens (JWT), express-validator
- **Testing**: Mocha, Chai, Supertest

---

## Installation

### Prerequisites
- Node.js and npm installed
- MongoDB server running locally or accessible remotely
- Git installed (optional)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/LocalEventsHub.git
   ```
2. Navigate to the project directory:
   ```bash
   cd LocalEventsHub
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Create a `.env` file and add the following environment variables:
   ```plaintext
   MONGODB_URL=mongodb://localhost:27017/local_events
   JWT_SECRET=your_jwt_secret
   PORT=3000
   ```
5. Start the server:
   ```bash
   npm start
   ```

---

## Usage

### API Endpoints

#### Authentication
- **POST** `/api/users/register`: Register a new user.
- **POST** `/api/users/login`: Log in with an email and password.
- **POST** `/api/users/logout`: Log out and invalidate tokens.

#### Events
- **GET** `/api/events`: Fetch all events.
- **POST** `/api/events`: Create a new event (requires authentication).
- **PUT** `/api/events/:id`: Update an event (only the creator).
- **DELETE** `/api/events/:id`: Delete an event (only the creator).

---

## Security Features

1. **Input Validation**: Prevents injection attacks using `express-validator`.
2. **Encryption**: Passwords are hashed with bcrypt.
3. **Rate Limiting**: Limits requests to prevent abuse (e.g., brute-force attacks).
4. **Account Lockout**: Temporarily locks accounts after multiple failed login attempts.
5. **Token Versioning**: Ensures secure logout by invalidating older tokens.
6. **CSP (Content Security Policy)**: Mitigates XSS attacks by restricting loaded resources.
7. **Logging**: Tracks security events like failed login attempts and account lockouts.

---

## Future Enhancements

- **Two-Factor Authentication (2FA)**: Add an extra layer of security for user accounts.
- **Event Notifications**: Notify users of updates to their events.
- **Geolocation Search**: Allow users to find events near their current location.
- **Admin Dashboard**: Manage events and users from a centralized dashboard.
