# 🏠 HostelHub - Complete Hostel Management System

A modern, full-stack hostel management system built with React, Node.js, Express, and MySQL. Features comprehensive admin and student portals with real-time chat, QR attendance, fee management, and much more.

## ✨ Features

### 🔐 Authentication & Authorization
- JWT-based authentication
- Role-based access control (Admin/Student)
- Password reset via email
- Secure session management

### 🧑‍💼 Admin Panel
- **Dashboard**: Real-time analytics and statistics
- **Student Management**: Add, edit, delete students with room assignment
- **Room Management**: Track occupancy and availability
- **Fee Management**: Create fees, track payments, generate receipts
- **Complaint Management**: Handle and resolve student complaints
- **Notice Management**: Create and broadcast announcements
- **Lost & Found**: Manage lost and found items
- **Real-time Chat**: Communicate with students
- **QR Attendance**: Generate QR codes for attendance
- **Reports**: Generate PDF/Excel reports
- **Profile Management**: Admin profile settings

### 🧑‍🎓 Student Panel
- **Dashboard**: Personal overview with stats
- **Profile**: Update personal information
- **Attendance**: QR code attendance marking
- **Fees**: View fee structure and payment status
- **Notices**: Read announcements and notices
- **Complaints**: Submit and track complaints
- **Lost & Found**: Report and claim items
- **Chat**: Real-time communication
- **Food Menu**: View weekly meal plans
- **Laundry Service**: Request laundry services
- **Visitor Management**: Register visitors
- **Maintenance**: Submit maintenance requests
- **Events**: View hostel events calendar
- **Feedback**: Rate hostel services

### 🎨 Premium Features
- **Responsive Design**: Mobile-first approach
- **Dark/Light Mode**: Theme switching
- **Real-time Updates**: Socket.io integration
- **QR Code Generation**: Attendance system
- **File Uploads**: Profile photos and documents
- **Email Notifications**: Automated alerts
- **PDF Generation**: Receipts and reports
- **Excel Export**: Data export functionality
- **AI Chatbot**: FAQ assistance
- **Analytics Dashboard**: Charts and insights

## 🛠️ Tech Stack

### Frontend
- **React 18** - Modern UI library
- **TailwindCSS** - Utility-first CSS framework
- **React Router** - Client-side routing
- **Axios** - HTTP client
- **Socket.io Client** - Real-time communication
- **React Hot Toast** - Notifications
- **React Icons** - Icon library
- **Framer Motion** - Animations
- **Recharts** - Data visualization

### Backend
- **Node.js** - Runtime environment
- **Express.js** - Web framework
- **MySQL** - Database
- **JWT** - Authentication
- **bcryptjs** - Password hashing
- **Multer** - File uploads
- **Socket.io** - Real-time communication
- **Nodemailer** - Email service
- **QRCode** - QR generation
- **PDFKit** - PDF generation
- **ExcelJS** - Excel generation

## 🚀 Quick Start

### Prerequisites
- Node.js (v16 or higher)
- MySQL (v8 or higher)
- npm or yarn

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/hostel-management-system.git
   cd hostel-management-system
   ```

2. **Install dependencies**
   ```bash
   npm run install-all
   ```

3. **Database Setup**
   ```bash
   # Create MySQL database
   mysql -u root -p
   CREATE DATABASE hostel_management;
   
   # Import schema
   mysql -u root -p hostel_management < server/database/schema.sql
   ```

4. **Environment Configuration**
   ```bash
   # Copy environment file
   cp server/env.example server/.env
   
   # Edit server/.env with your configuration
   DB_HOST=localhost
   DB_USER=root
   DB_PASSWORD=your_password
   DB_NAME=hostel_management
   JWT_SECRET=your_super_secret_jwt_key
   EMAIL_USER=your_email@gmail.com
   EMAIL_PASS=your_app_password
   ```

5. **Start the application**
   ```bash
   # Development mode (both frontend and backend)
   npm run dev
   
   # Or start individually
   npm run server  # Backend only
   npm run client  # Frontend only
   ```

6. **Access the application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:5000

## 🔑 Default Credentials

### Admin
- Email: admin@hostel.com
- Password: password

### Student
- Email: student@hostel.com
- Password: password

## 📁 Project Structure

```
hostel-management-system/
├── client/                 # React frontend
│   ├── src/
│   │   ├── components/    # Reusable components
│   │   ├── contexts/      # React contexts
│   │   ├── pages/         # Page components
│   │   └── App.js         # Main app component
│   └── package.json
├── server/                 # Node.js backend
│   ├── config/            # Database configuration
│   ├── middleware/        # Custom middleware
│   ├── routes/            # API routes
│   ├── database/          # Database schema
│   └── index.js           # Server entry point
├── package.json           # Root package.json
└── README.md
```

## 🔧 API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `GET /api/auth/me` - Get current user
- `PUT /api/auth/profile` - Update profile
- `POST /api/auth/forgot-password` - Forgot password
- `POST /api/auth/reset-password` - Reset password

### Users
- `GET /api/users` - Get all users (Admin)
- `GET /api/users/:id` - Get user by ID
- `POST /api/users` - Create user (Admin)
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user (Admin)

### Rooms
- `GET /api/rooms` - Get all rooms
- `GET /api/rooms/:id` - Get room by ID
- `POST /api/rooms` - Create room (Admin)
- `PUT /api/rooms/:id` - Update room (Admin)
- `DELETE /api/rooms/:id` - Delete room (Admin)

### Attendance
- `GET /api/attendance/qr/:userId` - Generate QR code
- `POST /api/attendance/mark` - Mark attendance
- `GET /api/attendance` - Get attendance records
- `GET /api/attendance/stats/:userId` - Get attendance stats

### Fees
- `GET /api/fees/user/:userId` - Get user fees
- `GET /api/fees` - Get all fees (Admin)
- `POST /api/fees` - Create fee (Admin)
- `PUT /api/fees/:id/pay` - Mark fee as paid (Admin)
- `GET /api/fees/:id/receipt` - Generate receipt

### Complaints
- `GET /api/complaints` - Get complaints
- `POST /api/complaints` - Create complaint
- `PUT /api/complaints/:id/status` - Update status (Admin)

### Notices
- `GET /api/notices` - Get notices
- `POST /api/notices` - Create notice (Admin)
- `PUT /api/notices/:id` - Update notice (Admin)

### Chat
- `GET /api/chat/messages` - Get messages
- `POST /api/chat/send` - Send message
- `GET /api/chat/rooms` - Get chat rooms

## 🎨 UI Components

### Admin Components
- `AdminLayout` - Main admin layout
- `AdminSidebar` - Navigation sidebar
- `AdminNavbar` - Top navigation
- `StatsCard` - Statistics cards
- `QuickActions` - Quick action buttons
- `RecentActivity` - Activity feed
- `ChartsSection` - Data visualization

### Student Components
- `StudentLayout` - Main student layout
- `StudentSidebar` - Navigation sidebar
- `StudentNavbar` - Top navigation
- `StatsCard` - Personal stats
- `QuickActions` - Student actions
- `RecentNotices` - Latest notices
- `AttendanceChart` - Attendance visualization

## 🔒 Security Features

- JWT token authentication
- Password hashing with bcrypt
- Role-based access control
- Input validation and sanitization
- Rate limiting
- CORS configuration
- Helmet security headers

## 📱 Responsive Design

- Mobile-first approach
- Tablet and desktop optimized
- Touch-friendly interfaces
- Adaptive layouts
- Dark/light theme support

## 🚀 Deployment

### Frontend (Vercel/Netlify)
```bash
cd client
npm run build
# Deploy the build folder
```

### Backend (Railway/Heroku)
```bash
cd server
# Set environment variables
# Deploy to your platform
```

### Database
- Use MySQL hosting service
- Configure connection string
- Run database migrations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support, email support@hostelhub.com or create an issue on GitHub.

## 🙏 Acknowledgments

- React team for the amazing framework
- TailwindCSS for the utility-first CSS
- All open-source contributors

---

**HostelHub** - Making hostel management simple and efficient! 🏠✨
