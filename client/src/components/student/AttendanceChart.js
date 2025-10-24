import React, { useState, useEffect } from 'react';
import { FaChartLine, FaCalendarAlt } from 'react-icons/fa';

const AttendanceChart = () => {
  const [attendanceData, setAttendanceData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAttendanceData();
  }, []);

  const fetchAttendanceData = async () => {
    try {
      // Mock data for now - replace with actual API call
      const mockData = {
        currentMonth: 85,
        lastMonth: 78,
        weeklyData: [
          { day: 'Mon', present: true },
          { day: 'Tue', present: true },
          { day: 'Wed', present: false },
          { day: 'Thu', present: true },
          { day: 'Fri', present: true },
          { day: 'Sat', present: false },
          { day: 'Sun', present: true }
        ]
      };
      
      setAttendanceData(mockData);
    } catch (error) {
      console.error('Error fetching attendance data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Attendance Overview</h3>
        </div>
        <div className="card-content">
          <div className="animate-pulse">
            <div className="h-32 bg-gray-200 rounded"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header">
        <h3 className="card-title flex items-center">
          <FaChartLine className="mr-2 text-primary-600" />
          Attendance Overview
        </h3>
        <p className="card-description">
          Your attendance performance
        </p>
      </div>
      <div className="card-content">
        <div className="space-y-6">
          {/* Monthly Stats */}
          <div className="grid grid-cols-2 gap-4">
            <div className="text-center">
              <div className="text-3xl font-bold text-primary-600">
                {attendanceData?.currentMonth}%
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">
                This Month
              </div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-gray-600">
                {attendanceData?.lastMonth}%
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">
                Last Month
              </div>
            </div>
          </div>

          {/* Weekly Chart */}
          <div>
            <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
              This Week
            </h4>
            <div className="grid grid-cols-7 gap-2">
              {attendanceData?.weeklyData.map((day, index) => (
                <div key={index} className="text-center">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-medium mb-1 ${
                    day.present 
                      ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' 
                      : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                  }`}>
                    {day.day.charAt(0)}
                  </div>
                  <div className="text-xs text-gray-600 dark:text-gray-400">
                    {day.day}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Progress Bar */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-gray-900 dark:text-white">
                Monthly Progress
              </span>
              <span className="text-sm text-gray-600 dark:text-gray-400">
                {attendanceData?.currentMonth}%
              </span>
            </div>
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <div 
                className="bg-gradient-to-r from-primary-500 to-primary-600 h-2 rounded-full transition-all duration-300"
                style={{ width: `${attendanceData?.currentMonth}%` }}
              ></div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="flex space-x-3">
            <button className="flex-1 btn btn-primary btn-sm">
              <FaCalendarAlt className="mr-2" />
              View Details
            </button>
            <button className="flex-1 btn btn-outline btn-sm">
              Generate QR
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AttendanceChart;
