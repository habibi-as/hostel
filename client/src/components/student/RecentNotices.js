import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { FaBullhorn, FaClock } from 'react-icons/fa';

const RecentNotices = () => {
  const [notices, setNotices] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchRecentNotices();
  }, []);

  const fetchRecentNotices = async () => {
    try {
      // Mock data for now - replace with actual API call
      const mockNotices = [
        {
          id: 1,
          title: 'Hostel Rules Update',
          content: 'Please follow the updated hostel rules...',
          priority: 'important',
          createdAt: '2 hours ago'
        },
        {
          id: 2,
          title: 'Maintenance Notice',
          content: 'Water supply will be interrupted...',
          priority: 'normal',
          createdAt: '1 day ago'
        },
        {
          id: 3,
          title: 'Fee Payment Reminder',
          content: 'Last date for fee payment is...',
          priority: 'urgent',
          createdAt: '2 days ago'
        }
      ];
      
      setNotices(mockNotices);
    } catch (error) {
      console.error('Error fetching notices:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Recent Notices</h3>
        </div>
        <div className="card-content">
          <div className="animate-pulse space-y-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="flex items-start space-x-3">
                <div className="w-8 h-8 bg-gray-200 rounded-full"></div>
                <div className="flex-1">
                  <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
                  <div className="h-3 bg-gray-200 rounded w-1/2"></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header">
        <div className="flex items-center justify-between">
          <h3 className="card-title">Recent Notices</h3>
          <Link
            to="/student/notices"
            className="text-sm text-primary-600 hover:text-primary-500"
          >
            View All
          </Link>
        </div>
        <p className="card-description">
          Latest announcements
        </p>
      </div>
      <div className="card-content">
        <div className="space-y-4">
          {notices.map((notice) => (
            <div key={notice.id} className="flex items-start space-x-3">
              <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${
                notice.priority === 'urgent' ? 'bg-red-100 text-red-600' :
                notice.priority === 'important' ? 'bg-yellow-100 text-yellow-600' :
                'bg-blue-100 text-blue-600'
              }`}>
                <FaBullhorn className="w-4 h-4" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                  {notice.title}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400 flex items-center mt-1">
                  <FaClock className="w-3 h-3 mr-1" />
                  {notice.createdAt}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default RecentNotices;
