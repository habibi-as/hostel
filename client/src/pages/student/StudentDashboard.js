import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useTheme } from '../../contexts/ThemeContext';
import StudentLayout from '../../components/student/StudentLayout';
import StatsCard from '../../components/student/StatsCard';
import RecentNotices from '../../components/student/RecentNotices';
import QuickActions from '../../components/student/QuickActions';
import AttendanceChart from '../../components/student/AttendanceChart';
import LoadingSpinner from '../../components/LoadingSpinner';
import axios from 'axios';
import { 
  FaUser, 
  FaBed, 
  FaDollarSign, 
  FaChartLine,
  FaQrcode,
  FaComments,
  FaUtensils,
  FaBell
} from 'react-icons/fa';

const StudentDashboard = () => {
  const { user } = useAuth();
  const { darkMode } = useTheme();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      // Mock data for now - replace with actual API calls
      const mockStats = {
        attendancePercentage: 85,
        pendingFees: 1,
        unreadNotices: 3,
        roomNumber: user?.room_no || 'N/A'
      };
      setStats(mockStats);
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      setError('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <StudentLayout>
        <div className="flex items-center justify-center h-64">
          <LoadingSpinner size="lg" />
        </div>
      </StudentLayout>
    );
  }

  if (error) {
    return (
      <StudentLayout>
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <p className="text-red-600 mb-4">{error}</p>
            <button
              onClick={fetchDashboardData}
              className="btn btn-primary"
            >
              Retry
            </button>
          </div>
        </div>
      </StudentLayout>
    );
  }

  const statsCards = [
    {
      title: 'Attendance',
      value: `${stats?.attendancePercentage || 0}%`,
      icon: <FaChartLine className="w-6 h-6" />,
      color: 'primary',
      description: 'This month'
    },
    {
      title: 'Room',
      value: stats?.roomNumber || 'N/A',
      icon: <FaBed className="w-6 h-6" />,
      color: 'gold',
      description: 'Your room number'
    },
    {
      title: 'Pending Fees',
      value: stats?.pendingFees || 0,
      icon: <FaDollarSign className="w-6 h-6" />,
      color: 'red',
      description: 'Unpaid fees'
    },
    {
      title: 'Notices',
      value: stats?.unreadNotices || 0,
      icon: <FaBell className="w-6 h-6" />,
      color: 'blue',
      description: 'Unread notices'
    }
  ];

  return (
    <StudentLayout>
      <div className="space-y-6">
        {/* Welcome Section */}
        <div className="bg-gradient-to-r from-primary-600 to-gold-600 rounded-lg p-6 text-white">
          <h1 className="text-3xl font-bold mb-2">
            Welcome, {user?.name}!
          </h1>
          <p className="text-primary-100">
            Here's your hostel dashboard overview.
          </p>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {statsCards.map((card, index) => (
            <StatsCard
              key={index}
              title={card.title}
              value={card.value}
              icon={card.icon}
              color={card.color}
              description={card.description}
            />
          ))}
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Attendance Chart */}
          <div className="lg:col-span-2">
            <AttendanceChart />
          </div>

          {/* Quick Actions */}
          <div className="space-y-6">
            <QuickActions />
            <RecentNotices />
          </div>
        </div>

        {/* Additional Info */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="card">
            <div className="card-header">
              <h3 className="card-title flex items-center">
                <FaUtensils className="mr-2 text-primary-600" />
                Today's Menu
              </h3>
            </div>
            <div className="card-content">
              <div className="space-y-3">
                <div>
                  <h4 className="font-semibold text-gray-900 dark:text-white">Breakfast</h4>
                  <p className="text-sm text-gray-600 dark:text-gray-400">7:00 AM - 9:00 AM</p>
                  <p className="text-sm text-gray-500">Idli, Sambar, Coffee</p>
                </div>
                <div>
                  <h4 className="font-semibold text-gray-900 dark:text-white">Lunch</h4>
                  <p className="text-sm text-gray-600 dark:text-gray-400">12:00 PM - 2:00 PM</p>
                  <p className="text-sm text-gray-500">Rice, Dal, Vegetables, Curd</p>
                </div>
                <div>
                  <h4 className="font-semibold text-gray-900 dark:text-white">Dinner</h4>
                  <p className="text-sm text-gray-600 dark:text-gray-400">7:00 PM - 9:00 PM</p>
                  <p className="text-sm text-gray-500">Roti, Curry, Rice, Salad</p>
                </div>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <h3 className="card-title flex items-center">
                <FaComments className="mr-2 text-primary-600" />
                Quick Chat
              </h3>
            </div>
            <div className="card-content">
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                Connect with your hostel mates
              </p>
              <button className="btn btn-primary w-full">
                Open Chat
              </button>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <h3 className="card-title flex items-center">
                <FaQrcode className="mr-2 text-primary-600" />
                QR Attendance
              </h3>
            </div>
            <div className="card-content">
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                Mark your attendance using QR code
              </p>
              <button className="btn btn-outline w-full">
                Generate QR
              </button>
            </div>
          </div>
        </div>
      </div>
    </StudentLayout>
  );
};

export default StudentDashboard;
