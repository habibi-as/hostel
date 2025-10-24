import React, { useState } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { 
  FaBars, 
  FaBell, 
  FaUser, 
  FaCog, 
  FaSignOutAlt,
  FaChevronDown
} from 'react-icons/fa';

const StudentNavbar = ({ onMenuClick, user, onLogout }) => {
  const [showUserMenu, setShowUserMenu] = useState(false);

  return (
    <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
      <div className="flex items-center justify-between px-4 py-3">
        {/* Left side */}
        <div className="flex items-center">
          <button
            onClick={onMenuClick}
            className="lg:hidden p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700"
          >
            <FaBars className="w-5 h-5" />
          </button>
          <h1 className="ml-2 text-xl font-semibold text-gray-900 dark:text-white lg:ml-0">
            Student Portal
          </h1>
        </div>

        {/* Right side */}
        <div className="flex items-center space-x-4">
          {/* Notifications */}
          <button className="relative p-2 text-gray-400 hover:text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md">
            <FaBell className="w-5 h-5" />
            <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
          </button>

          {/* User menu */}
          <div className="relative">
            <button
              onClick={() => setShowUserMenu(!showUserMenu)}
              className="flex items-center space-x-3 p-2 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700"
            >
              <div className="w-8 h-8 bg-primary-600 rounded-full flex items-center justify-center">
                <span className="text-white text-sm font-medium">
                  {user?.name?.charAt(0) || 'S'}
                </span>
              </div>
              <div className="hidden md:block text-left">
                <p className="text-sm font-medium text-gray-900 dark:text-white">
                  {user?.name || 'Student'}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  {user?.batch || 'Batch'} • Room {user?.room_no || 'N/A'}
                </p>
              </div>
              <FaChevronDown className="w-3 h-3 text-gray-400" />
            </button>

            {/* Dropdown menu */}
            {showUserMenu && (
              <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-gray-800 rounded-md shadow-lg py-1 z-50 border border-gray-200 dark:border-gray-700">
                <div className="px-4 py-2 border-b border-gray-200 dark:border-gray-700">
                  <p className="text-sm font-medium text-gray-900 dark:text-white">
                    {user?.name || 'Student'}
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    {user?.email || 'student@hostel.com'}
                  </p>
                </div>
                <a
                  href="#"
                  className="flex items-center px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                >
                  <FaUser className="mr-3 w-4 h-4" />
                  Profile
                </a>
                <a
                  href="#"
                  className="flex items-center px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                >
                  <FaCog className="mr-3 w-4 h-4" />
                  Settings
                </a>
                <button
                  onClick={onLogout}
                  className="flex items-center w-full px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                >
                  <FaSignOutAlt className="mr-3 w-4 h-4" />
                  Sign out
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};

export default StudentNavbar;
