# Skop Live Chat

A secure, scalable live chat system with admin support, built with Node.js, Socket.IO, MySQL, and Redis.

## Features
✅ User-to-admin real-time chat  
✅ Admin authentication (JWT)  
✅ Session forwarding between admins  
✅ Rate limiting and logging  
✅ Dockerized for easy deployment  
✅ MySQL/Redis for data persistence  

## Tech Stack
- **Backend**: Node.js, Express, Socket.IO
- **Database**: MySQL (sessions/messages), Redis (scaling)
- **Security**: JWT, bcrypt, rate limiting
- **Deployment**: Docker, Nginx

## Setup Instructions

### 1. Prerequisites
- Node.js 18+
- MySQL 8+
- Redis 7+
- Docker (optional)

### 2. Clone the Repository
```bash
git clone https://github.com/Skop505/skop-live-chat.git
cd skop-live-chat

