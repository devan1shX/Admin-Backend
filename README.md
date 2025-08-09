# OTMT Admin Backend

## Overview

The Admin Backend is a write-enabled Node.js service that serves as the exclusive gateway for all Create, Read, Update, and Delete (CRUD) operations in the OTMT platform ecosystem. This backend is specifically designed to handle data modifications securely through the Admin/User Portal interface.

## 🏗️ Architecture

This backend is part of OTMT's **Two-Backend Architecture**:
- **Admin Backend** (This Repository): Write-enabled service with full CRUD permissions
- **General Backend**: Read-only service for public-facing applications

### Security Design
- **Network Isolation**: Deployed on intranet-only accessible domain
- **Authentication**: JWT-based session management
- **Database Permissions**: Only service with write access to MongoDB
- **Role-Based Access Control**: Three-tier permission system

## 🚀 Features

### Authentication & Authorization
- **Firebase Integration**: Secure login via institutional Google accounts
- **JWT Session Management**: Token-based authentication for API calls
- **Three-Tier Role System**:
  - **Super Admin**: Full control including user permission management
  - **Admin**: Full CRUD control over technologies and events
  - **Employee**: Can only add new technologies and events

### Technology Management
- **Personal Technology Control**: Users can view, edit, and manage only their own submitted technologies
- **OTMT Admin Oversight**: Admin role retains global oversight capabilities
- **Data Purging System**: Soft delete with 30-day recovery period via "Recycle Bin"

### Event Management
- **CRUD Operations**: Full event lifecycle management
- **Visibility Control**: Toggle event active status
- **Event Details**: Complete event information including location, time, and registration

### Data Security
- **Automated Purging**: Permanently deletes technologies after 30 days in recycle bin
- **User Isolation**: Each user can only access their own data
- **Secure API Endpoints**: All operations require valid authentication

## 🛠️ Technology Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: MongoDB (Write permissions)
- **Authentication**: Firebase Authentication + JWT
- **Process Management**: PM2 (Production)

## 📊 Database Collections

### Technologies Collection
Complete technology information management including:
- Basic info (name, description, overview)
- Technical details and specifications  
- Innovator information and contact details
- Patent status and tracking
- Images and related links
- Technology Readiness Level (TRL)
- Brochure associations

### Events Collection  
Event management capabilities including:
- Event scheduling (date, time, location)
- Event descriptions and registration links
- Visibility controls (isActive flag)

## 🔧 Local Development Setup

### Prerequisites
- Node.js and npm installed
- MongoDB connection string
- Firebase project configuration
- JWT secret key

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/devan1shX/Admin-Backend
   cd Admin-Backend
   ```

2. **Install dependencies**
   ```bash
   npm install --force
   ```
   *Note: --force flag bypasses potential peer dependency conflicts*

3. **Environment Configuration**
   - Update MongoDB connection string for local environment
   - Configure Firebase authentication credentials
   - Set JWT secret key
   - Update API endpoints from production URLs to local addresses

4. **Start development server**
   ```bash
   npm run start
   ```

### Production Deployment
- Served as optimized production build
- Managed by PM2 process manager
- SSL/TLS enabled with HTTPS enforcement
- Reverse proxy configuration via NGINX

## 🔒 Security Features

- **Intranet-Only Access**: Not accessible from public internet
- **JWT Authentication**: Secure session management
- **Role-Based Permissions**: Granular access control
- **Database Write Isolation**: Only service with modify permissions
- **HTTPS Enforcement**: SSL/TLS encryption for all communications

## 🔄 API Workflow

1. User authenticates via Firebase (Google Sign-In)
2. Firebase returns authentication token
3. Token used to create JWT session with Admin Backend
4. React frontend makes authenticated API calls
5. Backend validates JWT and user permissions
6. Operations performed based on user role and ownership

## 📝 Role Permissions

| Feature | Super Admin | Admin | Employee |
|---------|-------------|--------|----------|
| Manage User Permissions | ✅ | ❌ | ❌ |
| CRUD Technologies (All) | ✅ | ✅ | ❌ |
| CRUD Events (All) | ✅ | ✅ | ❌ |
| Add Technologies | ✅ | ✅ | ✅ |
| Add Events | ✅ | ✅ | ✅ |
| Manage Own Technologies | ✅ | ✅ | ✅ |

## 🗑️ Recycle Bin System

- **Soft Delete**: Technologies moved to separate collection when "deleted"
- **30-Day Recovery**: Users can restore deleted technologies within 30 days  
- **Automated Cleanup**: System permanently deletes after 30-day period
- **Data Safety**: Prevents accidental permanent data loss

## 🤝 Integration Points

- **Admin/User Portal Frontend**: Primary client interface
- **General Backend**: Data synchronization for public display
- **MongoDB Database**: Exclusive write access point
- **Firebase Authentication**: User identity management

## 📚 Related Repositories

- **Admin Frontend**: [Admin-Frontend](https://github.com/devan1shX/Admin-Frontend)
- **General Backend**: [TMTO-Backend](https://github.com/devan1shX/TMTO-Backend)  
- **Public Website**: [TMTO](https://github.com/devan1shX/TMTO)
- **Mobile App**: [OTMT-App](https://github.com/devan1shX/OTMT-App)
- **Chatbot**: [Tech-Transfer-Pal](https://github.com/Beingstupid4me/Tech-Transfer-Pal)
- **Brochure Generator**: [Brochure-Automation](https://github.com/devan1shX/Brochure-Automation)

## 📄 License

This project is developed for the Office of Technology Management and Transfer, IIIT Delhi.

## 👥 Team

**Developers:**
- **Amartya Singh** - amartya22062@iiitd.ac.in
- **Anish** - anish22075@iiitd.ac.in

**Supervisor:**
- **Mr. Alok Nikhil Jha** - Office of Technology Management and Transfer

---

<div align="center">
  <p>Made with ❤️ for IIIT Delhi's innovation ecosystem</p>
</div>

---

*This backend service is part of the comprehensive OTMT digital ecosystem designed to manage, showcase, and facilitate institutional innovations and intellectual property.*
