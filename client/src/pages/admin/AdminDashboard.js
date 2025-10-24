import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useTheme } from '../../contexts/ThemeContext';
import AdminLayout from '../../components/admin/AdminLayout';
import StatsCard from '../../components/admin/StatsCard';
import RecentActivity from '../../components/admin/RecentActivity';
import QuickActions from '../../components/admin/QuickActions';
import ChartsSection from '../../components/admin/ChartsSection';
import LoadingSpinner from '../../components/LoadingSpinner';
import axios from 'axios';
import { 
  FaUsers, 
  FaBed, 
  FaExclamationTriangle, 
  FaDollarSign,
  FaChartLine,
  FaUserPlus,
  FaPlus,
  FaBell,
  FaComments
} from 'react-icons/fa';

const AdminDashboard = () => {
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
      const response = await axios.get('/api/users/stats/dashboard');
      setStats(response.data.data);
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      setError('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <AdminLayout>
        <div className="flex items-center justify-center h-64">
          <LoadingSpinner size="lg" />
        </div>
      </AdminLayout>
    );
  }

  if (error) {
    return (
      <AdminLayout>
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
      </AdminLayout>
    );
  }

  const statsCards = [
    {
      title: 'Total Students',
      value: stats?.totalStudents || 0,
      icon: <FaUsers className="w-8 h-8" />,
      color: 'primary',
      change: '+12%',
      changeType: 'positive'
    },
    {
      title: 'Rooms Occupied',
      value: `${stats?.occupiedRooms || 0}/${stats?.totalRooms || 0}`,
      icon: <FaBed className="w-8 h-8" />,
      color: 'gold',
      change: '+5%',
      changeType: 'positive'
    },
    {
      title: 'Pending Complaints',
      value: stats?.pendingComplaints || 0,
      icon: <FaExclamationTriangle className="w-8 h-8" />,
      color: 'red',
      change: '-8%',
      changeType: 'negative'
    },
    {
      title: 'Fees Collected',
      value: `₹${stats?.feesCollected || 0}`,
      icon: <FaDollarSign className="w-8 h-8" />,
      color: 'green',
      change: '+15%',
      changeType: 'positive'
    }
  ];

  return (
    <AdminLayout>
      <div className="space-y-6">
        {/* Welcome Section */}
        <div className="bg-gradient-to-r from-primary-600 to-gold-600 rounded-lg p-6 text-white">
          <h1 className="text-3xl font-bold mb-2">
            Welcome back, {user?.name}!
          </h1>
          <p className="text-primary-100">
            Here's what's happening at your hostel today.
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
              change={card.change}
              changeType={card.changeType}
            />
          ))}
        </div>

        {/* Charts and Quick Actions */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Charts Section */}
          <div className="lg:col-span-2">
            <ChartsSection />
          </div>

          {/* Quick Actions */}
          <div className="space-y-6">
            <QuickActions />
            <RecentActivity />
          </div>
        </div>

        {/* Additional Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="card">
            <div className="card-header">
              <h3 className="card-title flex items-center">
                <FaChartLine className="mr-2 text-primary-600" />
                Monthly Overview
              </h3>
            </div>
            <div className="card-content">
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-gray-600 dark:text-gray-400">New Students</span>
                  <span className="font-semibold text-green-600">+24</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-600 dark:text-gray-400">Room Occupancy</span>
                  <span className="font-semibold text-blue-600">85%</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-600 dark:text-gray-400">Satisfaction Rate</span>
                  <span className="font-semibold text-gold-600">92%</span>
                </div>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <h3 className="card-title flex items-center">
                <FaBell className="mr-2 text-primary-600" />
                Recent Notifications
              </h3>
            </div>
            <div className="card-content">
              <div className="space-y-3">
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-green-500 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm text-gray-900 dark:text-white">New student registration</p>
                    <p className="text-xs text-gray-500">2 minutes ago</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-yellow-500 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm text-gray-900 dark:text-white">Maintenance request pending</p>
                    <p className="text-xs text-gray-500">15 minutes ago</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-blue-500 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm text-gray-900 dark:text-white">Fee payment received</p>
                    <p className="text-xs text-gray-500">1 hour ago</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <h3 className="card-title flex items-center">
                <FaComments className="mr-2 text-primary-600" />
                Quick Stats
              </h3>
            </div>
            <div className="card-content">
              <div className="space-y-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-primary-600">98%</div>
                  <div className="text-sm text-gray-600 dark:text-gray-400">System Uptime</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-600">4.8/5</div>
                  <div className="text-sm text-gray-600 dark:text-gray-400">Average Rating</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-gold-600">24/7</div>
                  <div className="text-sm text-gray-600 dark:text-gray-400">Support Available</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </AdminLayout>
  );
};

export default AdminDashboard;
