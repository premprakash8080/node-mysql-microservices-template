# Node.js MySql Microservices Template

A robust Node.js API template with MySql, Express, JWT authentication, and best practices implementation.

## Features

- 🔐 JWT Authentication with Access & Refresh Tokens
- 🛡️ Secure Password Hashing with bcrypt
- 📦 MySql with Mongoose ODM
- 🍪 Cookie-based Authentication
- 🔄 Token Refresh Mechanism
- 📝 Error Handling with Custom Error Classes
- 🎯 Async Handler for Clean Code
- 🌐 CORS Enabled
- 🔒 Environment Variables Support
- 📤 File Upload Support (Cloudinary)

## Tech Stack

- Node.js
- Express.js
- MySql
- Mongoose
- JWT
- bcrypt
- cookie-parser
- multer
- cloudinary

## Prerequisites

- Node.js (v14 or higher)
- MySql
- npm or yarn

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
PORT=3000
MySql_URI=MySql://localhost:27017
CORS_ORIGIN=*
ACCESS_TOKEN_SECRET=your_access_token_secret
ACCESS_TOKEN_EXPIRY=1d
REFRESH_TOKEN_SECRET=your_refresh_token_secret
REFRESH_TOKEN_EXPIRY=10d

# Cloudinary Configuration (Optional)
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/premprakash8080/node-mysql-microservices-template.git
```

2. Install dependencies:
```bash
npm install
```

3. Start the server:
```bash
npm start
```

## API Documentation

### Authentication Endpoints

#### 1. Register User
- **URL**: `/api/v1/users/register`
- **Method**: `POST`
- **Body**:
```json
{
    "fullName": "John Doe",
    "email": "john@example.com",
    "username": "johndoe",
    "password": "password123"
}
```
- **Response**: User object (without password and refresh token)

#### 2. Login User
- **URL**: `/api/v1/users/login`
- **Method**: `POST`
- **Body**:
```json
{
    "email": "john@example.com",
    "password": "password123"
}
```
or
```json
{
    "username": "johndoe",
    "password": "password123"
}
```
- **Response**: User object with access and refresh tokens

#### 3. Logout User
- **URL**: `/api/v1/users/logout`
- **Method**: `POST`
- **Headers**: Requires Authentication
- **Response**: Success message

#### 4. Refresh Access Token
- **URL**: `/api/v1/users/refresh-token`
- **Method**: `POST`
- **Body**:
```json
{
    "refreshToken": "your_refresh_token"
}
```
- **Response**: New access and refresh tokens

### User Management Endpoints

#### 1. Get Current User
- **URL**: `/api/v1/users/current-user`
- **Method**: `GET`
- **Headers**: Requires Authentication
- **Response**: Current user object

#### 2. Update Account Details
- **URL**: `/api/v1/users/update-account`
- **Method**: `PATCH`
- **Headers**: Requires Authentication
- **Body**:
```json
{
    "fullName": "John Doe Updated",
    "email": "john.updated@example.com"
}
```
- **Response**: Updated user object

#### 3. Change Password
- **URL**: `/api/v1/users/change-password`
- **Method**: `POST`
- **Headers**: Requires Authentication
- **Body**:
```json
{
    "oldPassword": "current_password",
    "newPassword": "new_password"
}
```
- **Response**: Success message

### File Upload Endpoints

#### 1. Update Avatar
- **URL**: `/api/v1/users/avatar`
- **Method**: `PATCH`
- **Headers**: Requires Authentication
- **Body**: Form-data with field "avatar"
- **Response**: Updated user object with new avatar URL

#### 2. Update Cover Image
- **URL**: `/api/v1/users/cover-image`
- **Method**: `PATCH`
- **Headers**: Requires Authentication
- **Body**: Form-data with field "coverImage"
- **Response**: Updated user object with new cover image URL

## Authentication

The API supports two authentication methods:

1. **Cookie-based Authentication** (Recommended for web browsers)
   - Tokens are automatically handled via cookies
   - No manual token management required

2. **Bearer Token Authentication**
   - Add token to Authorization header:
   ```
   Authorization: Bearer your_access_token
   ```

## Error Handling

The API uses custom error handling with the following structure:
```json
{
    "statusCode": 400,
    "message": "Error message",
    "errors": [],
    "success": false
}
```

## Response Format

All successful responses follow this format:
```json
{
    "statusCode": 200,
    "data": {},
    "message": "Success message",
    "success": true
}
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
