import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useTheme } from '../../contexts/ThemeContext';
import { 
  FaHome,
  FaUser,
  FaQrcode,
  FaDollarSign,
  FaBullhorn,
  FaExclamationTriangle,
  FaSearch,
  FaComments,
  FaUtensils,
  FaTshirt,
  FaUserFriends,
  FaWrench,
  FaCalendarAlt,
  FaStar,
  FaSun,
  FaMoon,
  FaTimes
} from 'react-icons/fa';

const StudentSidebar = ({ onClose }) => {
  const location = useLocation();
  const { darkMode, toggleDarkMode } = useTheme();

  const navigation = [
    {
      name: 'Dashboard',
      href: '/student',
      icon: FaHome,
      current: location.pathname === '/student'
    },
    {
      name: 'Profile',
      href: '/student/profile',
      icon: FaUser,
      current: location.pathname === '/student/profile'
    },
    {
      name: 'Attendance',
      href: '/student/attendance',
      icon: FaQrcode,
      current: location.pathname === '/student/attendance'
    },
    {
      name: 'Fees',
      href: '/student/fees',
      icon: FaDollarSign,
      current: location.pathname === '/student/fees'
    },
    {
      name: 'Notices',
      href: '/student/notices',
      icon: FaBullhorn,
      current: location.pathname === '/student/notices'
    },
    {
      name: 'Complaints',
      href: '/student/complaints',
      icon: FaExclamationTriangle,
      current: location.pathname === '/student/complaints'
    },
    {
      name: 'Lost & Found',
      href: '/student/lost-found',
      icon: FaSearch,
      current: location.pathname === '/student/lost-found'
    },
    {
      name: 'Chat',
      href: '/student/chat',
      icon: FaComments,
      current: location.pathname === '/student/chat'
    },
    {
      name: 'Food Menu',
      href: '/student/food-menu',
      icon: FaUtensils,
      current: location.pathname === '/student/food-menu'
    },
    {
      name: 'Laundry',
      href: '/student/laundry',
      icon: FaTshirt,
      current: location.pathname === '/student/laundry'
    },
    {
      name: 'Visitors',
      href: '/student/visitors',
      icon: FaUserFriends,
      current: location.pathname === '/student/visitors'
    },
    {
      name: 'Maintenance',
      href: '/student/maintenance',
      icon: FaWrench,
      current: location.pathname === '/student/maintenance'
    },
    {
      name: 'Events',
      href: '/student/events',
      icon: FaCalendarAlt,
      current: location.pathname === '/student/events'
    },
    {
      name: 'Feedback',
      href: '/student/feedback',
      icon: FaStar,
      current: location.pathname === '/student/feedback'
    }
  ];

  return (
    <div className={`h-full flex flex-col ${darkMode ? 'bg-gray-800' : 'bg-white'} border-r border-gray-200 dark:border-gray-700`}>
      {/* Logo and close button */}
      <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center">
          <div className="w-8 h-8 bg-gradient-to-r from-primary-600 to-gold-600 rounded-lg flex items-center justify-center">
            <span className="text-white font-bold text-sm">H</span>
          </div>
          <span className="ml-2 text-xl font-bold text-gray-900 dark:text-white">
            HostelHub
          </span>
        </div>
        <button
          onClick={onClose}
          className="lg:hidden p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700"
        >
          <FaTimes className="w-5 h-5" />
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-4 py-4 space-y-2">
        {navigation.map((item) => {
          const Icon = item.icon;
          return (
            <Link
              key={item.name}
              to={item.href}
              onClick={onClose}
              className={`flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                item.current
                  ? 'bg-primary-100 text-primary-700 dark:bg-primary-900 dark:text-primary-200'
                  : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-700 dark:hover:text-white'
              }`}
            >
              <Icon className="mr-3 w-5 h-5" />
              {item.name}
            </Link>
          );
        })}
      </nav>

      {/* Theme toggle and footer */}
      <div className="p-4 border-t border-gray-200 dark:border-gray-700">
        <button
          onClick={toggleDarkMode}
          className="flex items-center w-full px-3 py-2 text-sm font-medium text-gray-700 rounded-md hover:bg-gray-100 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-700 dark:hover:text-white transition-colors"
        >
          {darkMode ? (
            <>
              <FaSun className="mr-3 w-5 h-5" />
              Light Mode
            </>
          ) : (
            <>
              <FaMoon className="mr-3 w-5 h-5" />
              Dark Mode
            </>
          )}
        </button>
        <div className="mt-4 text-xs text-gray-500 dark:text-gray-400 text-center">
          <p>Student Portal</p>
          <p>Version 1.0.0</p>
        </div>
      </div>
    </div>
  );
};

export default StudentSidebar;
