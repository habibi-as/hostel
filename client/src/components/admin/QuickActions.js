import React from 'react';
import { Link } from 'react-router-dom';
import { 
  FaUserPlus, 
  FaBed, 
  FaDollarSign, 
  FaBullhorn,
  FaExclamationTriangle,
  FaQrcode
} from 'react-icons/fa';

const QuickActions = () => {
  const actions = [
    {
      title: 'Add Student',
      description: 'Register a new student',
      icon: <FaUserPlus className="w-6 h-6" />,
      href: '/admin/students',
      color: 'bg-blue-500 hover:bg-blue-600'
    },
    {
      title: 'Manage Rooms',
      description: 'View and assign rooms',
      icon: <FaBed className="w-6 h-6" />,
      href: '/admin/rooms',
      color: 'bg-green-500 hover:bg-green-600'
    },
    {
      title: 'Fee Collection',
      description: 'Process fee payments',
      icon: <FaDollarSign className="w-6 h-6" />,
      href: '/admin/fees',
      color: 'bg-yellow-500 hover:bg-yellow-600'
    },
    {
      title: 'Send Notice',
      description: 'Create announcements',
      icon: <FaBullhorn className="w-6 h-6" />,
      href: '/admin/notices',
      color: 'bg-purple-500 hover:bg-purple-600'
    },
    {
      title: 'View Complaints',
      description: 'Handle student complaints',
      icon: <FaExclamationTriangle className="w-6 h-6" />,
      href: '/admin/complaints',
      color: 'bg-red-500 hover:bg-red-600'
    },
    {
      title: 'QR Attendance',
      description: 'Generate QR codes',
      icon: <FaQrcode className="w-6 h-6" />,
      href: '/admin/attendance',
      color: 'bg-indigo-500 hover:bg-indigo-600'
    }
  ];

  return (
    <div className="card">
      <div className="card-header">
        <h3 className="card-title">Quick Actions</h3>
        <p className="card-description">
          Common administrative tasks
        </p>
      </div>
      <div className="card-content">
        <div className="grid grid-cols-2 gap-3">
          {actions.map((action, index) => (
            <Link
              key={index}
              to={action.href}
              className={`${action.color} text-white p-4 rounded-lg hover:shadow-md transition-all duration-200 transform hover:scale-105`}
            >
              <div className="flex flex-col items-center text-center">
                <div className="mb-2">
                  {action.icon}
                </div>
                <h4 className="font-semibold text-sm">
                  {action.title}
                </h4>
                <p className="text-xs opacity-90 mt-1">
                  {action.description}
                </p>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
};

export default QuickActions;
