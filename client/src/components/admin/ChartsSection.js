import React, { useState, useEffect } from 'react';
import { FaChartLine, FaChartBar, FaChartPie } from 'react-icons/fa';

const ChartsSection = () => {
  const [chartType, setChartType] = useState('line');
  const [chartData, setChartData] = useState(null);

  useEffect(() => {
    // Mock data - in real app, this would come from API
    const mockData = {
      line: {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
        datasets: [
          {
            label: 'Students',
            data: [65, 78, 85, 92, 88, 95],
            borderColor: 'rgb(59, 130, 246)',
            backgroundColor: 'rgba(59, 130, 246, 0.1)',
            tension: 0.4
          },
          {
            label: 'Revenue',
            data: [45, 52, 68, 75, 82, 88],
            borderColor: 'rgb(245, 158, 11)',
            backgroundColor: 'rgba(245, 158, 11, 0.1)',
            tension: 0.4
          }
        ]
      },
      bar: {
        labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        datasets: [
          {
            label: 'Attendance',
            data: [85, 92, 78, 96, 88, 75, 82],
            backgroundColor: 'rgba(34, 197, 94, 0.8)',
            borderColor: 'rgb(34, 197, 94)',
            borderWidth: 1
          }
        ]
      },
      pie: {
        labels: ['Paid', 'Pending', 'Overdue'],
        datasets: [
          {
            data: [65, 25, 10],
            backgroundColor: [
              'rgba(34, 197, 94, 0.8)',
              'rgba(245, 158, 11, 0.8)',
              'rgba(239, 68, 68, 0.8)'
            ],
            borderColor: [
              'rgb(34, 197, 94)',
              'rgb(245, 158, 11)',
              'rgb(239, 68, 68)'
            ],
            borderWidth: 1
          }
        ]
      }
    };

    setChartData(mockData[chartType]);
  }, [chartType]);

  const chartTypes = [
    { key: 'line', label: 'Line Chart', icon: FaChartLine },
    { key: 'bar', label: 'Bar Chart', icon: FaChartBar },
    { key: 'pie', label: 'Pie Chart', icon: FaChartPie }
  ];

  return (
    <div className="card">
      <div className="card-header">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="card-title">Analytics Dashboard</h3>
            <p className="card-description">
              Visual representation of hostel data
            </p>
          </div>
          <div className="flex space-x-2">
            {chartTypes.map((type) => {
              const Icon = type.icon;
              return (
                <button
                  key={type.key}
                  onClick={() => setChartType(type.key)}
                  className={`p-2 rounded-md transition-colors ${
                    chartType === type.key
                      ? 'bg-primary-100 text-primary-700 dark:bg-primary-900 dark:text-primary-200'
                      : 'text-gray-400 hover:text-gray-600 hover:bg-gray-100 dark:hover:bg-gray-700'
                  }`}
                  title={type.label}
                >
                  <Icon className="w-4 h-4" />
                </button>
              );
            })}
          </div>
        </div>
      </div>
      <div className="card-content">
        <div className="h-64 flex items-center justify-center">
          {chartType === 'line' && (
            <div className="w-full">
              <div className="text-center mb-4">
                <h4 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Student Growth & Revenue
                </h4>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Monthly trends over 6 months
                </p>
              </div>
              <div className="space-y-2">
                {chartData?.datasets.map((dataset, index) => (
                  <div key={index} className="flex items-center justify-between">
                    <div className="flex items-center">
                      <div 
                        className="w-3 h-3 rounded-full mr-2"
                        style={{ backgroundColor: dataset.borderColor }}
                      ></div>
                      <span className="text-sm text-gray-600 dark:text-gray-400">
                        {dataset.label}
                      </span>
                    </div>
                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                      {dataset.data[dataset.data.length - 1]}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {chartType === 'bar' && (
            <div className="w-full">
              <div className="text-center mb-4">
                <h4 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Weekly Attendance
                </h4>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Average attendance by day
                </p>
              </div>
              <div className="space-y-2">
                {chartData?.labels.map((label, index) => (
                  <div key={index} className="flex items-center justify-between">
                    <span className="text-sm text-gray-600 dark:text-gray-400 w-8">
                      {label}
                    </span>
                    <div className="flex-1 mx-3">
                      <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                        <div 
                          className="bg-green-500 h-2 rounded-full"
                          style={{ width: `${chartData.datasets[0].data[index]}%` }}
                        ></div>
                      </div>
                    </div>
                    <span className="text-sm font-medium text-gray-900 dark:text-white w-8 text-right">
                      {chartData.datasets[0].data[index]}%
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {chartType === 'pie' && (
            <div className="w-full">
              <div className="text-center mb-4">
                <h4 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Fee Payment Status
                </h4>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Distribution of payment status
                </p>
              </div>
              <div className="space-y-3">
                {chartData?.labels.map((label, index) => (
                  <div key={index} className="flex items-center justify-between">
                    <div className="flex items-center">
                      <div 
                        className="w-4 h-4 rounded mr-3"
                        style={{ backgroundColor: chartData.datasets[0].backgroundColor[index] }}
                      ></div>
                      <span className="text-sm text-gray-600 dark:text-gray-400">
                        {label}
                      </span>
                    </div>
                    <span className="text-sm font-medium text-gray-900 dark:text-white">
                      {chartData.datasets[0].data[index]}%
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ChartsSection;
