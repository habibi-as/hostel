import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { FaUser, FaExclamationTriangle, FaDollarSign, FaBullhorn } from 'react-icons/fa';

const RecentActivity = () => {
  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchRecentActivity();
  }, []);

  const fetchRecentActivity = async () => {
    try {
      // This would be replaced with actual API calls
      const mockActivities = [
        {
          id: 1,
          type: 'student',
          message: 'New student registered',
          user: 'Rajesh Kumar',
          time: '2 minutes ago',
          icon: FaUser,
          color: 'text-blue-500'
        },
        {
          id: 2,
          type: 'complaint',
          message: 'Complaint submitted',
          user: 'Priya Sharma',
          time: '15 minutes ago',
          icon: FaExclamationTriangle,
          color: 'text-red-500'
        },
        {
          id: 3,
          type: 'payment',
          message: 'Fee payment received',
          user: 'Amit Singh',
          time: '1 hour ago',
          icon: FaDollarSign,
          color: 'text-green-500'
        },
        {
          id: 4,
          type: 'notice',
          message: 'Notice published',
          user: 'Admin',
          time: '2 hours ago',
          icon: FaBullhorn,
          color: 'text-purple-500'
        }
      ];
      
      setActivities(mockActivities);
    } catch (error) {
      console.error('Error fetching recent activity:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Recent Activity</h3>
        </div>
        <div className="card-content">
          <div className="animate-pulse space-y-4">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="flex items-center space-x-3">
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
        <h3 className="card-title">Recent Activity</h3>
        <p className="card-description">
          Latest system activities
        </p>
      </div>
      <div className="card-content">
        <div className="space-y-4">
          {activities.map((activity) => {
            const Icon = activity.icon;
            return (
              <div key={activity.id} className="flex items-start space-x-3">
                <div className={`flex-shrink-0 w-8 h-8 rounded-full bg-gray-100 dark:bg-gray-700 flex items-center justify-center`}>
                  <Icon className={`w-4 h-4 ${activity.color}`} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 dark:text-white">
                    {activity.message}
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    by {activity.user} • {activity.time}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default RecentActivity;
