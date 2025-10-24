import React from 'react';
import { Link } from 'react-router-dom';
import { 
  FaQrcode, 
  FaDollarSign, 
  FaExclamationTriangle,
  FaComments,
  FaUtensils,
  FaTshirt
} from 'react-icons/fa';

const QuickActions = () => {
  const actions = [
    {
      title: 'Mark Attendance',
      description: 'Use QR code to mark attendance',
      icon: <FaQrcode className="w-5 h-5" />,
      href: '/student/attendance',
      color: 'bg-blue-500 hover:bg-blue-600'
    },
    {
      title: 'Pay Fees',
      description: 'View and pay hostel fees',
      icon: <FaDollarSign className="w-5 h-5" />,
      href: '/student/fees',
      color: 'bg-green-500 hover:bg-green-600'
    },
    {
      title: 'Submit Complaint',
      description: 'Report issues or complaints',
      icon: <FaExclamationTriangle className="w-5 h-5" />,
      href: '/student/complaints',
      color: 'bg-red-500 hover:bg-red-600'
    },
    {
      title: 'Chat',
      description: 'Connect with hostel mates',
      icon: <FaComments className="w-5 h-5" />,
      href: '/student/chat',
      color: 'bg-purple-500 hover:bg-purple-600'
    },
    {
      title: 'Food Menu',
      description: 'View today\'s menu',
      icon: <FaUtensils className="w-5 h-5" />,
      href: '/student/food-menu',
      color: 'bg-yellow-500 hover:bg-yellow-600'
    },
    {
      title: 'Laundry',
      description: 'Request laundry service',
      icon: <FaTshirt className="w-5 h-5" />,
      href: '/student/laundry',
      color: 'bg-indigo-500 hover:bg-indigo-600'
    }
  ];

  return (
    <div className="card">
      <div className="card-header">
        <h3 className="card-title">Quick Actions</h3>
        <p className="card-description">
          Common student tasks
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
