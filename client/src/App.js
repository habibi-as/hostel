import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';

// Pages
import LandingPage from './pages/LandingPage';
import Login from './pages/Login';
import Register from './pages/Register';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';

// Admin Pages
import AdminDashboard from './pages/admin/AdminDashboard';
import AdminStudents from './pages/admin/AdminStudents';
import AdminRooms from './pages/admin/AdminRooms';
import AdminFees from './pages/admin/AdminFees';
import AdminComplaints from './pages/admin/AdminComplaints';
import AdminNotices from './pages/admin/AdminNotices';
import AdminLostFound from './pages/admin/AdminLostFound';
import AdminChat from './pages/admin/AdminChat';
import AdminAttendance from './pages/admin/AdminAttendance';
import AdminReports from './pages/admin/AdminReports';
import AdminProfile from './pages/admin/AdminProfile';

// Student Pages
import StudentDashboard from './pages/student/StudentDashboard';
import StudentProfile from './pages/student/StudentProfile';
import StudentAttendance from './pages/student/StudentAttendance';
import StudentFees from './pages/student/StudentFees';
import StudentNotices from './pages/student/StudentNotices';
import StudentComplaints from './pages/student/StudentComplaints';
import StudentLostFound from './pages/student/StudentLostFound';
import StudentChat from './pages/student/StudentChat';
import StudentFoodMenu from './pages/student/StudentFoodMenu';
import StudentLaundry from './pages/student/StudentLaundry';
import StudentVisitors from './pages/student/StudentVisitors';
import StudentMaintenance from './pages/student/StudentMaintenance';
import StudentEvents from './pages/student/StudentEvents';
import StudentFeedback from './pages/student/StudentFeedback';

// Components
import ProtectedRoute from './components/ProtectedRoute';
import LoadingSpinner from './components/LoadingSpinner';

function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <Router>
          <div className="App">
            <Toaster
              position="top-right"
              toastOptions={{
                duration: 4000,
                style: {
                  background: '#363636',
                  color: '#fff',
                },
                success: {
                  duration: 3000,
                  iconTheme: {
                    primary: '#4ade80',
                    secondary: '#fff',
                  },
                },
                error: {
                  duration: 5000,
                  iconTheme: {
                    primary: '#ef4444',
                    secondary: '#fff',
                  },
                },
              }}
            />
            <Routes>
              {/* Public Routes */}
              <Route path="/" element={<LandingPage />} />
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/forgot-password" element={<ForgotPassword />} />
              <Route path="/reset-password" element={<ResetPassword />} />

              {/* Admin Routes */}
              <Route path="/admin" element={
                <ProtectedRoute allowedRoles={['admin']}>
                  <AdminDashboard />
                </ProtectedRoute>
              } />
              <Route path="/admin/students" element={
                <ProtectedRoute allowedRoles={['admin']}>
                  <AdminStudents />
                </ProtectedRoute>
              } />
              <Route path="/admin/rooms" element={
                <ProtectedRoute allowedRoles={['admin']}>
                  <AdminRooms />
                </ProtectedRoute>
              } />
              <Route path="/admin/fees" element={
                <ProtectedRoute allowedRoles={['admin']}>
                  <AdminFees />
                </ProtectedRoute>
              } />
              <Route path="/admin/complaints" element={
                <ProtectedRoute allowedRoles={['admin']}>
                  <AdminComplaints />
                </ProtectedRoute>
              } />
              <Route path="/admin/notices" element={
                <ProtectedRoute allowedRoles={['admin']}>
                  <AdminNotices />
                </ProtectedRoute>
              } />
              <Route path="/admin/lost-found" element={
                <ProtectedRoute allowedRoles={['admin']}>
                  <AdminLostFound />
                </ProtectedRoute>
              } />
              <Route path="/admin/chat" element={
                <ProtectedRoute allowedRoles={['admin']}>
                  <AdminChat />
                </ProtectedRoute>
              } />
              <Route path="/admin/attendance" element={
                <ProtectedRoute allowedRoles={['admin']}>
                  <AdminAttendance />
                </ProtectedRoute>
              } />
              <Route path="/admin/reports" element={
                <ProtectedRoute allowedRoles={['admin']}>
                  <AdminReports />
                </ProtectedRoute>
              } />
              <Route path="/admin/profile" element={
                <ProtectedRoute allowedRoles={['admin']}>
                  <AdminProfile />
                </ProtectedRoute>
              } />

              {/* Student Routes */}
              <Route path="/student" element={
                <ProtectedRoute allowedRoles={['student']}>
                  <StudentDashboard />
                </ProtectedRoute>
              } />
              <Route path="/student/profile" element={
                <ProtectedRoute allowedRoles={['student']}>
                  <StudentProfile />
                </ProtectedRoute>
              } />
              <Route path="/student/attendance" element={
                <ProtectedRoute allowedRoles={['student']}>
                  <StudentAttendance />
                </ProtectedRoute>
              } />
              <Route path="/student/fees" element={
                <ProtectedRoute allowedRoles={['student']}>
                  <StudentFees />
                </ProtectedRoute>
              } />
              <Route path="/student/notices" element={
                <ProtectedRoute allowedRoles={['student']}>
                  <StudentNotices />
                </ProtectedRoute>
              } />
              <Route path="/student/complaints" element={
                <ProtectedRoute allowedRoles={['student']}>
                  <StudentComplaints />
                </ProtectedRoute>
              } />
              <Route path="/student/lost-found" element={
                <ProtectedRoute allowedRoles={['student']}>
                  <StudentLostFound />
                </ProtectedRoute>
              } />
              <Route path="/student/chat" element={
                <ProtectedRoute allowedRoles={['student']}>
                  <StudentChat />
                </ProtectedRoute>
              } />
              <Route path="/student/food-menu" element={
                <ProtectedRoute allowedRoles={['student']}>
                  <StudentFoodMenu />
                </ProtectedRoute>
              } />
              <Route path="/student/laundry" element={
                <ProtectedRoute allowedRoles={['student']}>
                  <StudentLaundry />
                </ProtectedRoute>
              } />
              <Route path="/student/visitors" element={
                <ProtectedRoute allowedRoles={['student']}>
                  <StudentVisitors />
                </ProtectedRoute>
              } />
              <Route path="/student/maintenance" element={
                <ProtectedRoute allowedRoles={['student']}>
                  <StudentMaintenance />
                </ProtectedRoute>
              } />
              <Route path="/student/events" element={
                <ProtectedRoute allowedRoles={['student']}>
                  <StudentEvents />
                </ProtectedRoute>
              } />
              <Route path="/student/feedback" element={
                <ProtectedRoute allowedRoles={['student']}>
                  <StudentFeedback />
                </ProtectedRoute>
              } />

              {/* Catch all route */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </div>
        </Router>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;
